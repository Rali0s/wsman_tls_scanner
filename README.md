# ✅ **README.md**

```markdown
# Sweet32 Proof-of-Concept Chain  
### 3DES Cipher Detection • Session Cookie Reinfection • Authenticated File Retrieval  
### Includes Python Proxy Loader + Curl Workflow  
**Reference:** https://sweet32.info  

---

## Overview

This repository provides a **safe, non-exploitative Sweet32 proof-of-concept** that demonstrates:

✔ Detecting **3DES / DES-CBC3-SHA** cipher negotiation (Sweet32-class)  
✔ Sending a **valid session cookie** to a benign PNG resource  
✔ Receiving a **reinfected / refreshed session cookie** from the server  
✔ Reusing that cookie to **download a protected file**  
✔ All traffic optionally routed through a **Python-loaded proxy configuration**  
✔ End-to-end verification performed entirely via **curl**  

This project does **NOT** attempt decryption, session compromise, or birthday collision exploitation.  
It is strictly a **configuration audit / exposure demonstration**, aligned with the information presented at:  
➡️ **https://sweet32.info**

---

## What is Sweet32?

**Sweet32** is a cryptographic weakness in 64-bit block ciphers (such as **3DES**) when used in CBC mode under **TLS < 1.3**.

Because a 64-bit block cipher produces repeated ciphertext blocks after ~2³² operations, long-lived HTTPS sessions that carry **stable cookies** may theoretically experience collisions that leak session information.

Full details, test cases, and research:  
➡️ https://sweet32.info

This repository demonstrates the **pre-attack conditions**, not the attack.

---

## Features

### ✔ Detects if a server still negotiates 3DES  
Curl is forced to use:

```

--ciphers DES-CBC3-SHA

```

If the server accepts, you will see:

```

* SSL connection using TLSv1.2 / DES-CBC3-SHA

```

### ✔ Valid session cookie sent to a PNG  
The script sends:

```

Cookie: SESSIONID=XYZ

```

### ✔ Captures the server’s `Set-Cookie:` header  
If the session is refreshed (reinfected), it is extracted automatically.

### ✔ Authenticated file download using the returned cookie  
The reinfected cookie is then reused to pull any file:

- PNG  
- ZIP  
- PDF  
- JSON  
- Binary

### ✔ Optional Python-driven proxy loader  
Reads `proxy.json` and sets:

```

http_proxy / https_proxy
HTTP_PROXY / HTTPS_PROXY

```

Useful for:

- BurpSuite  
- ZAP  
- MitM TLS visibility  
- Offline capture  
- Sandbox environments  

---

## File Structure

```

sweet32_chain.sh        # Main end-to-end curl workflow
proxy.json              # Optional proxy configuration file
README.md               # Documentation (this file)

````

---

## Usage

### 1. Configure proxy (optional)

Create a simple JSON file:

```json
{
  "https": "http://127.0.0.1:8080"
}
````

### 2. Run the Sweet32 chain script

```bash
chmod +x sweet32_chain.sh
```

Basic usage:

```bash
./sweet32_chain.sh
```

Or override defaults:

```bash
TARGET_HOST=yourserver.local \
PNG_PATH=/images/logo.png \
FILE_DIR=/secure \
FILE_NAME=secret.pdf \
INITIAL_COOKIE="SESSIONID=MYREALCOOKIE" \
./sweet32_chain.sh
```

---

## What the Script Does

### Step 1 — 3DES PNG request (Sweet32 handshake)

```bash
curl -sk --ciphers DES-CBC3-SHA \
  -H "Cookie: SESSIONID=XYZ" \
  https://target/images/logo.png \
  -D headers.txt \
  -o /dev/null
```

### Step 2 — Extract returned cookie

The script reads:

```
Set-Cookie: SESSIONID=newvalue
```

and stores:

```
SESSIONID=newvalue
```

### Step 3 — Reuse cookie to download file

```bash
curl -sk --ciphers DES-CBC3-SHA \
  -H "Cookie: SESSIONID=newvalue" \
  -O https://target/files/report.pdf
```

---

## Security & Legal Notes

* This project **does not perform** cryptanalysis, ciphertext slicing, replay attacks, or session hijacking.
* All operations use **standard HTTP/TLS behaviors** and **publicly documented curl features**.
* This is strictly a **configuration validation tool**, similar to `sslyze`, `nmap --script ssl-enum-ciphers`, and browser inspection.

Use only on systems you own or have explicit permission to test.

---

## Why This Matters

Systems that negotiate:

```
TLSv1.0 / TLSv1.1 / TLSv1.2
AND
DES-CBC3-SHA (3DES)
AND
Long-lived cookies
```

match the **preconditions** for Sweet32 exposure.

Mitigation recommendations:

* Disable 3DES
* Enforce TLS 1.2+ with modern suites
* Prefer TLS 1.3 where possible
* Reduce cookie lifetime
* Enable SameSite, Secure, HttpOnly flags
* Use GCM or ChaCha20-Poly1305 AEAD ciphers

---

## References

* 📌 **Official Sweet32 Paper / Website**
  [https://sweet32.info](https://sweet32.info)

* 📌 **Official Insomnia / Website**
  [ https://insomnia.rest ]

* 📌 NIST SP 800-52 rev2 (TLS Guidance)

* 📌 OWASP Transport Layer Protection Cheat Sheet

* 📌 Mozilla Server Side TLS Recommendations

---

## License

This project is provided for defensive and educational purposes.
MIT License unless otherwise noted.

```
