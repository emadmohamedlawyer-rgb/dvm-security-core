# -*- coding: utf-8 -*-
"""
Generates setup_config.json for DVM.

Run this ONCE on your own machine before building / distributing the installer:

    python tools/generate_setup_config.py

It asks for two passwords (master setup + client setup), stores ONLY their
PBKDF2-HMAC-SHA256 hashes (random salt, 600k iterations) and optional
organisation-specific text (signature / stamp anchor phrases).

setup_config.json is listed in .gitignore - never commit it.
"""
import argparse
import getpass
import hashlib
import json
import os
import secrets
import sys

ITERATIONS = 600_000


def make_hash(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), ITERATIONS)
    return f"pbkdf2${ITERATIONS}${salt}${digest.hex()}"


def ask_password(label: str) -> str:
    while True:
        pw = getpass.getpass(f"{label} (min 12 chars, letters + digits): ")
        if len(pw) < 12 or not any(c.isalpha() for c in pw) or not any(c.isdigit() for c in pw):
            print("  Too weak. Use at least 12 characters with letters and digits.")
            continue
        if pw != getpass.getpass("  Confirm: "):
            print("  Passwords do not match.")
            continue
        return pw


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate DVM setup_config.json")
    parser.add_argument("--out", default="setup_config.json", help="output path")
    parser.add_argument("--signature-anchor", default="", help="phrase under which the signature is placed")
    parser.add_argument("--stamp-anchor", default="", help="phrase under which the stamp is placed")
    args = parser.parse_args()

    if os.path.exists(args.out):
        if input(f"{args.out} already exists. Overwrite? [y/N] ").strip().lower() != "y":
            return 1

    master = ask_password("Master setup password")
    client = ask_password("Client setup password")
    if master == client:
        print("Master and client passwords must be different.")
        return 1

    config = {"admin_setup_hash": make_hash(master), "client_setup_hash": make_hash(client)}
    if args.signature_anchor:
        config["signature_anchor_text"] = args.signature_anchor
    if args.stamp_anchor:
        config["stamp_anchor_text"] = args.stamp_anchor

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(args.out, 0o600)
    except OSError:
        pass
    print(f"Written: {os.path.abspath(args.out)}")
    print("Place it next to the program (or in %APPDATA%\\DVM). Do NOT commit it to Git.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
