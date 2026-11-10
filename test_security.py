# -*- coding: utf-8 -*-
"""Unit tests for the security helpers (no GUI is created)."""
import hashlib
import importlib.util
import os
import sqlite3
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="module")
def dvm():
    """The security module has no GUI / OS dependencies - import it directly."""
    sys.path.insert(0, ROOT)
    import dvm_security
    return dvm_security


# ---------------------------------------------------------------- passwords
@pytest.mark.parametrize("pw", ["short1", "onlyletters", "12345678901", "password1", "Password1"])
def test_weak_passwords_rejected(dvm, pw):
    assert dvm.validate_new_password(pw) is not None


def test_strong_password_accepted(dvm):
    assert dvm.validate_new_password("Tr1cky-Horse-42", "dept1") is None


def test_password_cannot_contain_username(dvm):
    assert dvm.validate_new_password("manager2026x", "manager") is not None


def test_new_password_must_differ_from_old(dvm):
    assert dvm.validate_new_password("Sam3-Passw0rd", "u", old_pw="Sam3-Passw0rd") is not None


def test_temp_password_shape(dvm):
    seen = {dvm.generate_temp_password() for _ in range(200)}
    assert len(seen) == 200  # no collisions
    for pw in seen:
        assert len(pw) == 12
        assert any(c.isalpha() for c in pw) and any(c.isdigit() for c in pw)
        assert not set(pw) & set("0O1lI")  # no look-alike characters


# --------------------------------------------------------------- setup hash
def _make_hash(pw, iterations=1000):
    salt = "ab" * 16
    d = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), iterations).hex()
    return f"pbkdf2${iterations}${salt}${d}"


def test_pbkdf2_verify_roundtrip(dvm):
    stored = _make_hash("correct horse 9")
    assert dvm.pbkdf2_verify(stored, "correct horse 9")
    assert not dvm.pbkdf2_verify(stored, "correct horse 8")


@pytest.mark.parametrize("bad", ["", "garbage", "pbkdf2$x$y$z", "sha1$1$a$b", "pbkdf2$1000$salt"])
def test_pbkdf2_verify_rejects_malformed(dvm, bad):
    assert not dvm.pbkdf2_verify(bad, "anything")


def test_setup_is_fail_closed_without_config(dvm):
    assert dvm.check_setup_password("", "", "") is None
    assert dvm.check_setup_password("anything", "", _make_hash("x")) is None
    assert dvm.check_setup_password("anything", _make_hash("x"), "") is None


def test_setup_modes(dvm):
    admin, client = _make_hash("master-pass-1"), _make_hash("client-pass-2")
    assert dvm.check_setup_password("master-pass-1", admin, client) == "master"
    assert dvm.check_setup_password("client-pass-2", admin, client) == "client"
    assert dvm.check_setup_password("nope", admin, client) is None


def test_no_secret_defaults_in_source():
    for name in ("DVM-MainSource.py", "dvm_security.py"):
        path = os.path.join(ROOT, name)
        if not os.path.exists(path):  # the public showcase repo has no main file
            continue
        text = open(path, encoding="utf-8").read()
        for needle in ('"pass":', 'hashlib.sha256("', "_REMEMBER_KEY", "base64.b64decode"):
            assert needle not in text, (name, needle)


# ---------------------------------------------------------- path components
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("..", "item"),
        ("../../etc/passwd", "etcpasswd"),
        ("a&b|c^d", "abcd"),
        ("CON", "_CON"),
        ("nul.txt", "_nul.txt"),
        ("  .hidden.  ", "hidden"),
        ("", "item"),
    ],
)
def test_clean_path_component(dvm, raw, expected):
    assert dvm.clean_path_component(raw) == expected


def test_clean_path_component_length_limit(dvm):
    assert len(dvm.clean_path_component("x" * 500)) <= 120


# ---------------------------------------------------------------- throttling
def test_login_delay_schedule(dvm):
    assert [dvm.login_delay_seconds(n) for n in range(1, 5)] == [0, 0, 0, 0]
    assert dvm.login_delay_seconds(5) == 30
    assert dvm.login_delay_seconds(6) == 60
    assert dvm.login_delay_seconds(50) == 900  # hard cap


def test_throttle_lifecycle(dvm):
    conn = sqlite3.connect(":memory:")
    now = 1_000_000.0
    for i in range(4):
        assert dvm.throttle_register_failure(conn, "u", now)[1] == 0
    assert dvm.throttle_remaining(conn, "u", now) == 0
    failed, delay = dvm.throttle_register_failure(conn, "u", now)
    assert (failed, delay) == (5, 30)
    assert dvm.throttle_remaining(conn, "u", now) == 30
    assert dvm.throttle_remaining(conn, "u", now + 31) == 0     # lock expires
    assert dvm.throttle_remaining(conn, "other", now) == 0      # per-account
    assert dvm.throttle_register_failure(conn, "u", now + 40)[1] == 60  # escalates
    dvm.throttle_reset(conn, "u")
    assert dvm.throttle_remaining(conn, "u", now + 40) == 0
