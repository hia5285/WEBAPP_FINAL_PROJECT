# CSecFiles

CSecFiles is an internal document-sharing web application that lets company
employees upload, organise, search and discuss documents inside their team
or department. It is the final project for the Web Security course and
ships in **two parallel builds** so students can compare an insecure
implementation against a hardened one, side by side, on a local XAMPP
install.

| Build         | URL prefix                                | Purpose                              |
|---------------|-------------------------------------------|--------------------------------------|
| Vulnerable    | `http://localhost/csecfiles/vulnerable/`  | Demonstrates 5 classic web vulns.    |
| Hardened      | `http://localhost/csecfiles/hardened/`    | Same UI; the same code paths fixed.  |

Both builds share a single MariaDB database called `csecfiles`.

---

## Technologies

- **Frontend:** HTML, CSS, vanilla JavaScript
- **Backend:** PHP 8.x
- **Database:** MariaDB / MySQL (via XAMPP phpMyAdmin)
- **Web server:** Apache (via XAMPP)
- **DB driver:** `mysqli` in the vulnerable build, `PDO` (with prepared
  statements) in the hardened build

No Composer dependencies, no external JS frameworks --- everything runs out
of the box on a default XAMPP install.

---

## Folder structure

```
csecfiles/
├── README.md
├── pentest_guide.md
├── database/
│   └── csecfiles.sql
├── vulnerable/
│   ├── index.php  login.php  register.php  dashboard.php
│   ├── upload.php  view_document.php  download.php
│   ├── search.php  comments.php  include_page.php  logout.php
│   ├── config/db.php
│   ├── includes/{header,sidebar,footer}.php
│   ├── pages/{about,help,policy}.php
│   ├── uploads/   (seeded txt files + .gitkeep)
│   └── assets/{css/style.css, js/app.js}
└── hardened/
    ├── (same page list as vulnerable/)
    ├── config/{db.php, security.php}
    ├── includes/{header,sidebar,footer}.php
    ├── pages/{about,help,policy}.php
    ├── uploads/
    └── assets/{css/style.css, js/app.js}
```

The two builds intentionally have an identical surface area and look. The
only differences live inside the PHP backend logic of the five files that
host the targeted vulnerabilities.

---

## XAMPP setup

1. Install [XAMPP](https://www.apachefriends.org/) (PHP 8.0 or newer).
2. Open the **XAMPP Control Panel** and start **Apache** and **MySQL**.
3. Copy this entire folder into `C:\xampp\htdocs\` and rename it to
   `csecfiles` so the final path is `C:\xampp\htdocs\csecfiles\`.

Confirm by opening:

- http://localhost/csecfiles/vulnerable/
- http://localhost/csecfiles/hardened/

---

## Database setup

1. Open http://localhost/phpmyadmin/ in your browser.
2. Click **Import** in the top menu.
3. Choose `database/csecfiles.sql` and click **Go**.
4. You should now see a `csecfiles` database in the left sidebar with four
   tables: `users`, `documents`, `comments`, `activity_logs`.

If your local MariaDB has a non-empty root password, edit the credentials
near the top of:

- `vulnerable/config/db.php`
- `hardened/config/db.php`

You can re-import the SQL file at any time to reset the seeded data.

---

## How to run the vulnerable version

1. Make sure Apache and MySQL are running in XAMPP.
2. Visit http://localhost/csecfiles/vulnerable/
3. Sign in with one of the test accounts below.
4. Follow [pentest_guide.md](pentest_guide.md) to reproduce each
   vulnerability.

## How to run the hardened version

1. Same XAMPP setup as above.
2. Visit http://localhost/csecfiles/hardened/
3. Sign in with the same test accounts and try the same payloads from the
   pentest guide. Each one should now be blocked or rendered harmless.

---

## Test accounts

| Username  | Password      | Role     | Department  |
|-----------|---------------|----------|-------------|
| `admin`   | `admin123`    | admin    | IT          |
| `john`    | `password123` | employee | Engineering |
| `sara`    | `password123` | employee | Marketing   |
| `manager` | `manager123`  | manager  | Engineering |

Passwords are seeded as plaintext for the lab. The hardened login silently
re-hashes them to bcrypt on first successful login, and any account
created through `hardened/register.php` is stored as a bcrypt hash from
the start.

---

## What CSecFiles demonstrates

The vulnerable build deliberately contains five classic web
vulnerabilities. The hardened build fixes the same code paths.

| Vulnerability             | Vulnerable file                                | Hardened file                                                 |
|---------------------------|------------------------------------------------|---------------------------------------------------------------|
| Stored Persistent XSS     | `vulnerable/comments.php` + `view_document.php`| `hardened/comments.php` + `view_document.php` (uses `e()`)    |
| SQL Injection             | `vulnerable/search.php` (and `login.php`)      | `hardened/search.php` + `login.php` (PDO prepared statements) |
| Local File Inclusion (LFI)| `vulnerable/include_page.php`                  | `hardened/include_page.php` + `safe_include_page()`           |
| Brute-force on login      | `vulnerable/login.php`                         | `hardened/login.php` + lockout helpers in `security.php`      |
| IDOR                      | `vulnerable/view_document.php` + `download.php`| `hardened/view_document.php` + `download.php` (`can_access_document()`) |

Every vulnerable file carries a `// INTENTIONAL VULNERABILITY:` comment
explaining what is wrong and pointing at the matched fix; every hardened
file carries the corresponding `// MITIGATION:` comment.

---

## Educational disclaimer

This project is **a teaching artefact for a local classroom lab**. The
vulnerable build is intentionally insecure and must never be exposed
outside `localhost`. Do not deploy it on a public network, do not point
any public DNS at it, and do not reuse the `vulnerable/` code in a real
application.

All penetration-testing activities described in `pentest_guide.md` are
intended to be performed only against your own copy of the vulnerable
build running on `127.0.0.1`. Performing the same techniques against any
system you do not own is unethical and, in most jurisdictions, illegal.

---

## Notes for instructors and students

- The two builds share one database, so you can switch between them in
  separate browser tabs and immediately see the difference in behaviour.
- A side-by-side `diff` of any vulnerable file and its hardened counterpart
  pinpoints the lesson: the change is always small, named, and commented.
- To reset everything to the seeded state, re-import
  `database/csecfiles.sql` from phpMyAdmin and (optionally) delete any
  files you uploaded from `vulnerable/uploads/` and `hardened/uploads/`.
- Default XAMPP ships with `display_errors = On`. The vulnerable build
  relies on this to leak SQL errors during the SQLi demo. The hardened
  build catches its own exceptions and never leaks the underlying message.
