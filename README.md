# DVM — Offline Document & Correspondence Workflow (public showcase)

DVM is a desktop system I designed for managing official correspondence inside a large
organisation, on an **offline internal network**. It is in use by a training administration
at a public-utility company. This repository is the **public showcase**: the architecture,
screenshots, and the security layer — published as a standalone, tested module.

> The complete application is a private repository. I'm happy to walk through the code in an
> interview or grant read access on request.

## What the system does

* **Approval workflow:** department → general manager (sign, stamp, or reject with a reason) →
  records office (official outgoing number, final export).
* **Documents:** automatic e-signature and stamp injection into **Word and PDF** files,
  positioned by an anchor phrase, with correct **Arabic shaping and RTL layout**.
* **Archive & reports:** daily incoming archive per department, dated outgoing archive,
  Excel reports for any date range, automatic backup on exit.
* **Access control & audit:** four roles, per-account subscription expiry, and a central
  audit log of every action.
* **Multi-user on an offline share:** SQLite persistence, lock-file coordination, auto-refresh.

<!-- Add your screenshots to docs/screenshots/ with these names, then delete this comment:
![Login](docs/screenshots/01-login.png)
![Dashboard](docs/screenshots/02-dashboard.png)
![Approval](docs/screenshots/03-approval.png)
![Report](docs/screenshots/04-report.png)
-->

## Architecture

```
 ┌────────────────────────────┐
 │  CustomTkinter UI (RTL)    │   screens per role: admin / super-admin / records / owner
 ├────────────────────────────┤
 │  Workflow & document logic │   routing, signature/stamp injection (python-docx, PyMuPDF)
 ├────────────────────────────┤
 │  dvm_security  (this repo) │   password policy · PBKDF2 · throttling · safe file names
 ├────────────────────────────┤
 │  SQLite (shared folder)    │   users · letters · archive · audit log · login attempts
 └────────────────────────────┘
```

## The security module (`dvm_security.py`)

Standard library only, no GUI dependency, fully unit-tested (`pytest tests -q`).

| Function | Purpose |
|---|---|
| `pbkdf2_verify`, `check_setup_password` | Constant-time PBKDF2-HMAC-SHA256 verification; fail-closed when no config exists |
| `validate_new_password`, `generate_temp_password` | Password policy; random temporary passwords with no look-alike characters |
| `throttle_*`, `login_delay_seconds` | Exponential lock-out (30 s → 15 min cap) stored per account |
| `clean_path_component` | Blocks `..`, reserved Windows names, shell metacharacters and over-long names |

`tools/generate_setup_config.py` creates the `setup_config.json` that holds the setup-password
hashes, so **no secret ever lives in the source code**. See [SECURITY.md](SECURITY.md) for the
threat model and the known limitations.

## How it was built

I identified the problem, specified the workflow and the security model, and tested the system
with its real users. The code was written with **AI-assisted development**: I reviewed and
tested the output and fixed the problems found in real use, including several security issues I
found during a later audit (e.g. default-password reset on a database read error, disabled
accounts that could still sign in).

## Run the tests

```bash
pip install -r requirements-dev.txt
pytest tests -q
```

## License

The security module and the setup tool are released under the MIT License.
The full application is proprietary and not part of this repository.
