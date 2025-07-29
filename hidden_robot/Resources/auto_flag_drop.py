#!/usr/bin/env python3
import argparse
import re
import sys
import urllib.parse
from collections import deque

import requests
from bs4 import BeautifulSoup

# Regular expression to match a typical hex‑style CTF flag
FLAG_PATTERN = re.compile(r'\b[0-9a-f]{40,}\b', re.IGNORECASE)

def crawl_and_find_flags(start_url):
    """
    Crawl the given start_url (which should end with '/.hidden/'),
    follow subdirectories, fetch README* files, and print any flags found.
    """
    session = requests.Session()
    session.verify = False  # ignore TLS cert issues if any

    visited = set()
    queue = deque([start_url])

    found = set()

    while queue:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = session.get(url, timeout=10)
        except requests.RequestException as e:
            print(f"[!] Error fetching {url}: {e}", file=sys.stderr)
            continue

        # If this is a directory listing (HTML), parse links
        content_type = resp.headers.get("Content-Type", "")
        if "text/html" in content_type:
            soup = BeautifulSoup(resp.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link["href"]
                # Skip parent links
                if href in ("../",):
                    continue

                next_url = urllib.parse.urljoin(url, href)
                # If it ends with '/', treat as directory
                if href.endswith("/"):
                    queue.append(next_url)
                else:
                    # Check for README* files
                    name = href.rsplit("/", 1)[-1]
                    if name.lower().startswith("readme"):
                        queue.append(next_url)
        else:
            # Non-HTML: likely a file. Check for README and scan for flag
            path = urllib.parse.urlparse(url).path
            filename = path.rsplit("/", 1)[-1]
            if filename.lower().startswith("readme"):
                text = resp.text
                for match in FLAG_PATTERN.findall(text):
                    if match not in found:
                        found.add(match)
                        print(f"[*] Found flag in {url}: {match}")

    if not found:
        print("[!] No flags found. Double-check the target URL and directory structure.", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description="Auto‑crawl /.hidden/ and extract CTF flag.")
    parser.add_argument(
        "--target",
        default="http://localhost:8080",
        help="Base URL of the target (e.g. http://localhost:8080)",
    )
    args = parser.parse_args()

    # Ensure trailing slash and .hidden path
    base = args.target.rstrip("/")
    hidden_url = urllib.parse.urljoin(base + "/", ".hidden/")
    print(f"[*] Starting crawl at {hidden_url} …")
    crawl_and_find_flags(hidden_url)

if __name__ == "__main__":
    main()

