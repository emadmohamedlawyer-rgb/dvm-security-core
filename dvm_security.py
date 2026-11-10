# -*- coding: utf-8 -*-
"""
dvm_security - the security helpers of DVM, with no GUI dependencies.

* PBKDF2 verification (constant-time) for the setup passwords
* password policy and random temporary passwords
* safe file / folder names (no "..", reserved Windows names, shell metacharacters)
* exponential login throttling on top of any DB-API connection (SQLite)

Everything here is pure Python (standard library only) so it can be unit-tested
and reviewed on its own.
"""
import hashlib
import hmac
import secrets
import time


def pbkdf2_verify(stored, entered):
    """يتحقق من نص بصيغة pbkdf2$<iterations>$<salt>$<hex> بمقارنة ثابتة الزمن."""
    try:
        scheme, iterations, salt, expected = stored.split("$", 3)
        if scheme != "pbkdf2":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", entered.encode("utf-8"), salt.encode("utf-8"), int(iterations)
        ).hex()
        return hmac.compare_digest(digest, expected)
    except Exception:
        return False


def check_setup_password(entered, admin_hash, client_hash):
    """يرجّع "master" أو "client" أو None. لو أي hash فاضي (الإعداد غير موجود)
    يرجّع None دايماً (fail-closed)."""
    if not admin_hash or not client_hash:
        return None
    is_master = pbkdf2_verify(admin_hash, entered)
    is_client = pbkdf2_verify(client_hash, entered)
    if is_master:
        return "master"
    if is_client:
        return "client"
    return None


# ---------------------------------------------------------------------------
# سياسة كلمات المرور + تنضيف أسماء الملفات/المجلدات + تقييد محاولات الدخول
# (دوال على مستوى الملف عشان تتختبر لوحدها من غير واجهة).
# ---------------------------------------------------------------------------
_COMMON_PASSWORDS = {
    "password", "password1", "12345678", "123456789", "1234567890", "qwerty123",
    "11111111", "00000000", "admin123", "admin1234", "welcome1", "letmein1",
    "iloveyou1", "abc12345", "passw0rd", "p@ssw0rd", "dvm12345", "dvm-2026",
}


def validate_new_password(new_pw, user_name="", old_pw=None):
    """يرجّع رسالة الخطأ (بالعربي) لو كلمة المرور مرفوضة، أو None لو مقبولة."""
    if len(new_pw) < 8:
        return "كلمة المرور يجب ألا تقل عن 8 خانات."
    if not any(c.isalpha() for c in new_pw) or not any(c.isdigit() for c in new_pw):
        return "كلمة المرور يجب أن تحتوي على حروف وأرقام معاً."
    lowered = new_pw.lower()
    if lowered in _COMMON_PASSWORDS:
        return "كلمة المرور هذه شائعة جداً، اختر كلمة مرور أقوى."
    if user_name and (lowered == user_name.lower() or user_name.lower() in lowered):
        return "كلمة المرور يجب ألا تحتوي على اسم الحساب."
    if old_pw is not None and new_pw == old_pw:
        return "كلمة المرور الجديدة يجب أن تختلف عن الحالية."
    return None


_TEMP_PW_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"


def generate_temp_password(length=12):
    """كلمة مرور مؤقتة عشوائية (بدون حروف متشابهة)، مضمون فيها حروف وأرقام."""
    while True:
        pw = "".join(secrets.choice(_TEMP_PW_ALPHABET) for _ in range(length))
        if any(c.isalpha() for c in pw) and any(c.isdigit() for c in pw):
            return pw


_WIN_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *{f"COM{i}" for i in range(1, 10)}, *{f"LPT{i}" for i in range(1, 10)},
}


def clean_path_component(text, default="item", extra_allowed="._- ", max_len=120):
    """يحوّل أي نص لاسم ملف/فولدر آمن: بيمنع .. والنقط في الأطراف وأسماء ويندوز
    المحجوزة (CON, NUL...) ويقص الطول عشان مايكسرش حد المسار 260 حرف."""
    cleaned = "".join(x for x in str(text) if x.isalnum() or x in extra_allowed)
    cleaned = cleaned.strip(" .")
    if cleaned.split(".")[0].upper() in _WIN_RESERVED_NAMES:
        cleaned = "_" + cleaned
    cleaned = cleaned[:max_len].rstrip(" .")
    return cleaned or default


MAX_FAILED_BEFORE_DELAY = 5


def login_delay_seconds(failed):
    """مدة الإيقاف المؤقت بعد عدد محاولات فاشلة متتالية (بحد أقصى 15 دقيقة)."""
    if failed < MAX_FAILED_BEFORE_DELAY:
        return 0
    return min(900, 30 * 2 ** (failed - MAX_FAILED_BEFORE_DELAY))


def throttle_ensure(conn):
    conn.execute(
        "CREATE TABLE IF NOT EXISTS login_attempts ("
        "name TEXT PRIMARY KEY, failed INTEGER DEFAULT 0, locked_until REAL DEFAULT 0)"
    )


def throttle_remaining(conn, name, now=None):
    """الثواني المتبقية على فك إيقاف الحساب (0 لو مش موقوف)."""
    now = time.time() if now is None else now
    throttle_ensure(conn)
    row = conn.execute("SELECT locked_until FROM login_attempts WHERE name = ?", (name,)).fetchone()
    if not row:
        return 0
    return max(0, int(row[0] - now + 0.999)) if row[0] > now else 0


def throttle_register_failure(conn, name, now=None):
    """يسجّل محاولة فاشلة ويرجّع (عدد الفاشلة، ثواني الإيقاف)."""
    now = time.time() if now is None else now
    throttle_ensure(conn)
    row = conn.execute("SELECT failed FROM login_attempts WHERE name = ?", (name,)).fetchone()
    failed = (row[0] if row else 0) + 1
    delay = login_delay_seconds(failed)
    conn.execute(
        "INSERT INTO login_attempts (name, failed, locked_until) VALUES (?, ?, ?) "
        "ON CONFLICT(name) DO UPDATE SET failed=excluded.failed, locked_until=excluded.locked_until",
        (name, failed, now + delay if delay else 0),
    )
    conn.commit()
    return failed, delay


def throttle_reset(conn, name):
    throttle_ensure(conn)
    conn.execute("DELETE FROM login_attempts WHERE name = ?", (name,))
    conn.commit()
