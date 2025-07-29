# HTTP‑GET Form Brute‑Force Exploit Write‑Up

## 1. Overview

- **Target URL:**  

http://<VM_IP>/index.php?page=signin

- **Login form parameters (GET):**  
- `page=signin`
- `username=<user>`
- `password=<pwd>`
- `Login=Login`
- **Goal:**  
Recover the admin password via brute‑force and retrieve the 64‑hex‑char flag.

---

## 2. Vulnerability

1. **Credentials in URL**  
 - GET parameters expose `username` and `password` in logs, browser history, and referer headers.

2. **No brute‑force protection**  
 - Unlimited login attempts without rate limits, lockouts, or CAPTCHAs.

3. **Weak/common password**  
 - Admin used a guessable password (`shadow`), making dictionary attacks trivial.

---

## 3. Exploit Steps

1. **Prepare a wordlist**  

10-million-password-list-top-10000.txt


2. **Run the brute‑force script**  
```bash
python3 bruteforce_login.py \
  localhost:8080 \
  -u admin \
  -w 10-million-password-list-top-10000.txt

    Script logic

        Iterates over each password in the wordlist.

        Sends a GET request to:

    http://localhost:8080/index.php
      ?page=signin
      &username=admin
      &password=<candidate>
      &Login=Login

    Checks for the failure marker (images/WrongAnswer.gif) in the response HTML.

    Stops on the first password that does not contain the failure marker.

Outcome

    Discovered credentials:

admin:shadow

Retrieved flag:

        B3A6E43DDF8B4BBB4125E5E7D23040433827759D4DE1C04EA63907479A80A6B2

4. Mitigations

    Use POST instead of GET

    <form method="POST" action="index.php?page=signin">
      <!-- ... -->
    </form>

    Enforce strong passwords

        Minimum length (≥12 characters)

        Mixed case, digits, symbols

        Reject known weak/common passwords

    Rate limiting & lockout

        Per‑account: lock account or require CAPTCHA after N failures.

        Per‑IP: throttle or block abusive IPs.

    Progressive delays or CAPTCHA

        Introduce increasing response delays (e.g. 500 ms → 1 s → 2 s)

        Present a CAPTCHA after repeated failures.

    Multi‑factor authentication (MFA)

        Require TOTP, SMS, or hardware token for high‑privilege users.

    Secure password storage

        Use salted, slow KDFs (bcrypt, Argon2, PBKDF2) instead of fast or unsalted hashes.

    Enforce HTTPS

        Always encrypt credentials and session cookies in transit.

    Monitoring & alerting

        Log and alert on spikes in login failures or lockouts.

5. References

    Hydra documentation: https://github.com/vanhauser-thc/thc-hydra

    OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

    OWASP Brute Force Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Brute_Force_Protection_Cheat_Sheet.html

::contentReference[oaicite:0]{index=0}