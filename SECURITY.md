# Security notes

## What this protects against
* Casual access to other departments' letters (role-based screens + audit log).
* Password guessing at the login screen (lock-out + audit entries).
* Leaked source code or Git history (no secrets, no organisation data in the repository).
* Theft of the database file alone (only salted PBKDF2 hashes are stored).

## What it does NOT protect against (read before deploying)
1. **A compiled `.exe` is not secret.** PyInstaller output can be unpacked. Security rests on
   strong passwords, not on hiding code.
2. **`setup_config.json` can be attacked offline.** It holds PBKDF2 hashes of the two setup
   passwords. Use long, unique passwords (the generator enforces 12+ characters) and treat
   the file like a credential.
3. **File-system permissions are the real boundary.** Anyone with write access to the shared
   data folder can read the database, delete files, or replace the program. Restrict the share
   with NTFS ACLs to the accounts that need it.
4. **Lock-out uses the PC clock** and is stored in the shared database; it slows guessing but
   a user with direct DB access can reset it.
5. **No encryption at rest** for letters and attachments. Use BitLocker / an encrypted volume
   for the server if the content is sensitive.
6. **Legacy hash support.** Accounts created by very old versions (plain salted SHA-256) can
   still log in and are re-hashed with PBKDF2 on first successful login.

## Before publishing a fork
- [ ] `git log -p | grep -i -E "password|secret"` returns nothing (start from a fresh repository, never push the original history).
- [ ] `setup_config.json`, `logo.png`, `*.db`, `Data-archive-prog/` are not tracked.
- [ ] Screenshots were taken with fake data and no real logo / names.
- [ ] You are allowed to publish this code (employer IP / policy).

## Reporting
Open a private security advisory on the repository or contact the maintainer directly.
