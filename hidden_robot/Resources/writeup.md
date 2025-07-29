1. Discover the target path

During recon you notice a .hidden/ directory exists on the web server, but browsing to it directly with a browser is blocked by the site’s robots.txt. robots.txt is only an instruction to well‑behaved crawlers, not a real access control mechanism—so you’re free to ignore it.
2. Mirror the directory with wget

wget --recursive --no-parent --no-check-certificate --execute robots=off http://$TARGET_IP/.hidden/

    --recursive – walk every sub‑directory automatically.

    --no-parent – stay under .hidden/; don’t wander upward into the rest of the site.

    --no-check-certificate – skip TLS validation in case the lab uses a self‑signed cert.

    --execute robots=off – tell wget to ignore robots.txt.

Result: you pull a complete local copy of everything the server stored under .hidden/, preserving the directory tree.
3. Hunt for human‑readable hints (README files)

Create a quick helper script (call it finder.sh):

#!/usr/bin/env bash
START_DIR="${1:-.}"          # default to current dir if no arg
find "$START_DIR" -type f -iname "README*" | while read -r file; do
    cat "$file"
done

Why this works:

    On CTF boxes, authors often scatter clues in files named README, readme.txt, etc.

    find walks the mirrored tree and passes every file whose name starts with README (case‑insensitive) to cat, printing their contents sequentially.

Run it in the directory you just mirrored:

cd $TARGET_IP/.hidden
bash finder.sh

4. Extract the flag text

Pipe the script’s output into grep to catch anything that looks like a flag:

bash finder.sh | grep -i flag

Typical CTF flags are long hex strings or FLAG{…} patterns, so a simple grep is plenty. Here it returns:

Hey, here is your flag : d5eec3ec36cf80dce44a896f961c1831a05526ec215693c8f2c39543497d4466

Copy the value after the colon—that’s the submission token.
