#!/usr/bin/env python3
"""
wsman_tls_scanner.py -- Active TLS capability probe for WS-Man / WMI ports

Behavior:
- For each host/port:
  - Attempts a TCP connect.
  - If TLS appears to be in use, performs:
      * A generic TLS handshake to capture negotiated version + cipher.
      * A "legacy" probe to see if TLS < 1.3 is still allowed.
      * A 3DES-only handshake attempt to detect SWEET32-class ciphers.
- Writes JSONL records suitable for correlation with wsman-guardian outputs.
- Intended for defensive config assessment, not exploitation.

Requirements:
- Python 3.8+
- Standard library only (ssl, socket, ipaddress, concurrent.futures)

Example usage:
  # Single host, defaults ports
  python3 wsman_tls_scanner.py 10.0.0.5

  # CIDR + explicit ports, JSONL out
  python3 wsman_tls_scanner.py 10.0.0.0/24 --ports 5985 5986 8531 \
      --out wsman_tls_scan.jsonl --workers 128

Notes:
- Ports like 5985/135/445 may not speak TLS at all; in that case, result is
  recorded as "not_tls".
- 3DES detection depends on your OpenSSL build; if 3DES is globally disabled,
  the 3DES probe will fail even if the server supports it.
"""

import argparse
import concurrent.futures
import ipaddress
import json
import logging
import socket
import ssl
import sys
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import re

RANGE_RE = re.compile(r"^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$")

# -------------------------
# Configurable defaults
# -------------------------

# WMI / WS-Man / WinRM-ish ports (union of your earlier list + wsman-guardian)
DEFAULT_PORTS = [
    135,      # RPC Endpoint Mapper (WMI/DCOM-related)
    139,      # NetBIOS
    445,      # SMB (CIM over DCOM-type stacks)
    5985,     # WinRM HTTP
    5986,     # WinRM HTTPS (primary TLS target)
    47001,    # WinRM / WMI-related on some builds
    8530,     # WSUS HTTP
    8531,     # WSUS HTTPS (TLS)
    8443,
    9443
]

DEFAULT_TIMEOUT = 3.0
DEFAULT_WORKERS = 64
DEFAULT_OUTFILE = "wsman_tls_scan.jsonl"

# 3DES cipher list (OpenSSL names)
THREEDES_CIPHERS = (
    "DES-CBC3-SHA:"
    "EDH-RSA-DES-CBC3-SHA:"
    "ECDHE-RSA-DES-CBC3-SHA:"
    "ECDHE-ECDSA-DES-CBC3-SHA"
)

logger = logging.getLogger("wsman_tls_scanner")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(_handler)


# -------------------------
# Helper functions
# -------------------------
def expand_targets(targets: List[str]) -> List[str]:
    """
    Expand a list of hostname/IP/CIDR/range strings into a flat list of IPs/hostnames.

    Supported forms:
      - 10.0.0.5            (single IP or hostname)
      - 10.0.0.0/24         (CIDR, expanded via ipaddress)
      - 10.0.0.0-255        (last octet range: 10.0.0.0..10.0.0.255)
      - 10.0.0.10-50        (last octet subrange)
    """
    expanded: List[str] = []

    for t in targets:
        t = t.strip()
        if not t:
            continue

        # Match last-octet range like 10.0.0.0-255
        m = RANGE_RE.match(t)
        if m:
            base = m.group(1)      # "10.0.0"
            start = int(m.group(2))
            end = int(m.group(3))
            if start > end:
                start, end = end, start
            logger.debug("Expanding range %s as %s.%d-%d", t, base, start, end)
            for last in range(start, end + 1):
                expanded.append(f"{base}.{last}")
            continue

        # Try CIDR
        try:
            net = ipaddress.ip_network(t, strict=False)
            hosts = list(net.hosts())
            logger.debug("Expanded CIDR %s to %d hosts", t, len(hosts))
            for ip in hosts:
                expanded.append(str(ip))
            continue
        except ValueError:
            # Not CIDR, fall through
            pass

        # Treat as hostname or single IP
        logger.debug("Added single target %s", t)
        expanded.append(t)
        
    return expanded


def tcp_connect(host: str, port: int, timeout: float) -> Optional[socket.socket]:
    """Return a connected socket or None if connection fails."""
    try:
        logger.debug("Attempting TCP connect to %s:%d", host, port)
        sock = socket.create_connection((host, port), timeout=timeout)
        logger.debug("TCP connect OK %s:%d", host, port)
        return sock
    except Exception as e:
        logger.debug("TCP connect failed %s:%d: %s", host, port, e)
        return None


def tls_handshake_basic(
    host: str,
    sock: socket.socket,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Attempt a "normal" TLS handshake (any version/cipher) and capture:
    - success flag
    - negotiated TLS version (e.g. 'TLSv1.2', 'TLSv1.3')
    - negotiated cipher name
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        logger.debug("Starting generic TLS handshake with %s", host)
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            version = ssock.version()          # 'TLSv1.2', 'TLSv1.3', etc.
            cipher = ssock.cipher()[0]         # (name, protocol, bits)
            logger.debug("TLS handshake OK %s: version=%s cipher=%s",
                         host, version, cipher)
            return True, version, cipher
    except Exception as e:
        logger.debug("TLS basic handshake failed %s: %s", host, e)
        return False, None, None


def tls_supports_legacy(host: str, port: int, timeout: float) -> bool:
    """
    Check if the server will negotiate TLS < 1.3 by forcing max_version = TLSv1_2.
    If handshake succeeds, we assume legacy TLS is supported.
    """
    logger.debug("Probing for TLS < 1.3 support on %s:%d", host, port)

    # Some Python/OpenSSL builds may not have TLSVersion attributes (older versions)
    tls_version_enum = getattr(ssl, "TLSVersion", None)
    if tls_version_enum is None:
        logger.debug("TLSVersion enum not available; cannot probe legacy TLS precisely")
        # Fallback: if we can't explicitly constrain versions,
        # we can't reliably test; return False/Unknown.
        return False

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                logger.debug("Legacy TLS (<1.3) accepted on %s:%d", host, port)
                return True
    except Exception as e:
        logger.debug("Legacy TLS probe failed %s:%d: %s", host, port, e)
        return False


def tls_probe_3des(
    host: str,
    port: int,
    timeout: float,
) -> Tuple[bool, Optional[str]]:
    """
    Attempt to negotiate a 3DES cipher on TLS 1.0/1.1/1.2.
    Returns:
      - success flag
      - negotiated cipher name (if any)
    """
    logger.debug("Probing for 3DES/SWEET32-class cipher support on %s:%d", host, port)

    # Best-effort: iterate protocols we might have at runtime.
    versions = [
        ("TLSv1.0", getattr(ssl, "PROTOCOL_TLSv1", None)),
        ("TLSv1.1", getattr(ssl, "PROTOCOL_TLSv1_1", None)),
        ("TLSv1.2", getattr(ssl, "PROTOCOL_TLSv1_2", None)),
    ]

    for name, proto in versions:
        if proto is None:
            continue

        ctx = ssl.SSLContext(proto)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            ctx.set_ciphers(THREEDES_CIPHERS)
        except ssl.SSLError as e:
            # 3DES may be globally disabled in OpenSSL
            logger.debug("3DES ciphers unavailable in local OpenSSL: %s", e)
            return False, None

        try:
            logger.debug("Trying 3DES with %s (%s)", name, host)
            with socket.create_connection((host, port), timeout=timeout) as sock:
                print(sock)
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()[0]
                    logger.debug("3DES negotiated on %s:%d via %s -> %s",
                                 host, port, name, cipher)
                    return True, cipher
        except Exception as e:
            logger.debug("3DES probe failed %s:%d (%s): %s", host, port, name, e)

    logger.debug("3DES not negotiable on %s:%d", host, port)
    return False, None


def evaluate_sweet32_risk(record: Dict[str, Any]) -> str:
    """
    Classify SWEET32 risk based on scan record.

    SWEET32-RISK if:
      - TLS is present AND
      - 3DES is negotiable (supports_3des=True) AND
      - TLS < 1.3 is allowed (tls_supports_legacy=True OR tls_version != 'TLSv1.3')
    """
    if not record.get("tcp_connect"):
        return "NO-CONNECT"
    if not record.get("is_tls"):
        return "NO-TLS"

    if record.get("supports_3des"):
        # If they have 3DES AND legacy TLS, it's classic Sweet32 territory.
        if record.get("tls_supports_legacy") or record.get("tls_version") != "TLSv1.3":
            return "SWEET32-RISK"
        # Weird case: 3DES somehow but no explicit legacy flag
        return "WEAK-3DES"

    return "OK"


def scan_host_port(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """
    Single host/port scan routine. Returns a dict ready for JSONL.
    """
    record: Dict[str, Any] = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "host": host,
        "port": port,
        "tcp_connect": False,
        "is_tls": False,
        "tls_version": None,
        "tls_cipher": None,
        "tls_supports_legacy": None,   # True/False/None
        "supports_3des": None,
        "three_des_cipher": None,
        "error": None,
    }

    sock = tcp_connect(host, port, timeout)
    if not sock:
        record["error"] = "connect_failed"
        return record

    record["tcp_connect"] = True

    # Try a generic TLS handshake
    ok, version, cipher = tls_handshake_basic(host, sock)
    if not ok:
        # Not a TLS listener (or TLS handshake failed)
        record["error"] = "not_tls_or_handshake_failed"
        return record

    record["is_tls"] = True
    record["tls_version"] = version
    record["tls_cipher"] = cipher

    # Probe for legacy TLS (< 1.3) support
    try:
        supports_legacy = tls_supports_legacy(host, port, timeout)
        record["tls_supports_legacy"] = supports_legacy
    except Exception as e:
        logger.debug("Legacy TLS probe exception %s:%d: %s", host, port, e)
        record["tls_supports_legacy"] = None

    # Probe for 3DES support (SWEET32)
    try:
        supports_3des = tls_probe_3des(host, port, timeout) #, three_des_cipher 
        record["supports_3des"] = supports_3des
        record["three_des_cipher"] = three_des_cipher
    except Exception as e:
        logger.debug("3DES TLS probe exception %s:%d: %s", host, port, e)
        record["supports_3des"] = None
        record["three_des_cipher"] = None

    return record


# -------------------------
# Main / Arg parsing
# -------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="wsman_tls_scanner.py",
        description="Active TLS / 3DES capability scanner for WMI/WS-Man ports"
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="Hostname/IP or CIDR (e.g., 10.0.0.5, 10.0.0.0/24)",
    )
    parser.add_argument(
        "--ports", "-p",
        nargs="+",
        type=int,
        default=DEFAULT_PORTS,
        help=f"Ports to scan (default: {DEFAULT_PORTS})",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"TCP/TLS timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Max worker threads (default: {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "--out", "-o",
        default=DEFAULT_OUTFILE,
        help=f"Output JSONL file (default: {DEFAULT_OUTFILE})",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose logging (debug + SWEET32 explanation)",
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    targets = expand_targets(args.targets)
    ports = sorted(set(args.ports))

    logger.info("Starting wsman TLS scanner")
    logger.info("Targets expanded to %d hosts; ports=%s", len(targets), ports)
    logger.info("Output: %s", args.out)

    total_tasks = len(targets) * len(ports)
    logger.info("Planned probes: %d", total_tasks)

    # Open output file for append
    out_f = open(args.out, "a", encoding="utf-8")

    def _task(host: str, port: int) -> Dict[str, Any]:
        rec = scan_host_port(host, port, args.timeout)
        line = json.dumps(rec, sort_keys=True)
        out_f.write(line + "\n")
        out_f.flush()

        status = evaluate_sweet32_risk(rec)

        # Human summary line
        if rec["tcp_connect"] and rec["is_tls"]:
            # Bump to WARNING if SWEET32-ish
            lvl = logging.INFO
            if status in ("SWEET32-RISK", "WEAK-3DES"):
                lvl = logging.WARNING

            logger.log(
                lvl,
                "[%s] %s:%d TLS=%s cipher=%s legacy=%s 3DES=%s (%s)",
                status,
                rec["host"],
                rec["port"],
                rec["tls_version"],
                rec["tls_cipher"],
                rec["tls_supports_legacy"],
                rec["supports_3des"],
                rec["three_des_cipher"],
            )

            # Extra explanation in verbose mode for SWEET32
            if args.verbose and status == "SWEET32-RISK":
                logger.warning(
                    "  -> SWEET32 conditions met on %s:%d: 3DES (64-bit block cipher) "
                    "is negotiable on legacy TLS. Long-lived WinRM/WSUS sessions here "
                    "can be susceptible to birthday-style traffic-decryption attacks.",
                    rec["host"],
                    rec["port"],
                )

        elif not rec["tcp_connect"]:
            logger.info("[%s] %s:%d connect failed", status, rec["host"], rec["port"])
        else:
            logger.info(
                "[%s] %s:%d no TLS / handshake failed (%s)",
                status,
                rec["host"],
                rec["port"],
                rec["error"],
            )
        return rec

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = []
            for host in targets:
                for port in ports:
                    futures.append(ex.submit(_task, host, port))

            # Consume futures to surface exceptions
            for fut in concurrent.futures.as_completed(futures):
                try:
                    _ = fut.result()
                except Exception as e:
                    logger.error("Worker error: %s", e)
    except:
        print("err")

    finally:
        out_f.close()
        logger.info("Scan complete; results written to %s", args.out)


if __name__ == "__main__":
    main()
