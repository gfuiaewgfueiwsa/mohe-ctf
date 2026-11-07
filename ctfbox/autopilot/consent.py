# -*- coding: utf-8 -*-
"""旧版 Web 利用声明记录（兼容层，v3.7.0 起不再作为闸门）。

v3.7.0 起软件只在启动时保留唯一一道《软件责任说明》闸门
（见 ctfbox/responsibility.py）；逐功能/逐目标的声明与白名单已取消。
本模块仅保留历史记录读写接口与旧调用兼容，require() 恒放行。
"""
import hashlib
import json
import os
import threading
import time

from ..common import WORKSPACE

FEATURE_WEB_EXPLOIT = "web-exploit"
DECLARATION_VERSION = "2"
CONSENT_DIR = os.path.join(WORKSPACE, "config")
CONSENT_PATH = os.path.join(CONSENT_DIR, "consent.json")

DECLARATION_TEXT = """Web 利用授权声明（历史记录，v3.6.0 及更早版本使用）

v3.7.0 起该声明不再是独立闸门：进入软件时的《软件责任说明》已覆盖授权与行为
责任，逐功能声明与逐目标白名单全部取消。
"""

STATEMENT_SHA256 = hashlib.sha256(
    (DECLARATION_TEXT + "\nversion=" + DECLARATION_VERSION).encode("utf-8")).hexdigest()

# 进程内临时声明：保留旧接口，不参与任何拦截。
_SESSION = set()
_SESSION_LOCK = threading.Lock()


class ConsentError(RuntimeError):
    """历史异常类型，保留供旧调用捕获；v3.7.0 起不再抛出。"""


def _load() -> dict:
    try:
        with open(CONSENT_PATH, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def _save(data: dict):
    os.makedirs(CONSENT_DIR, exist_ok=True)
    tmp = CONSENT_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fp:
        json.dump(data, fp, ensure_ascii=False, indent=2)
    os.replace(tmp, CONSENT_PATH)


def grant(feature: str = FEATURE_WEB_EXPLOIT, source: str = "cli", note: str = "") -> dict:
    """写入历史声明记录（保留兼容，不再影响执行）。"""
    data = _load()
    record = {
        "granted": True,
        "feature": feature,
        "declaration_version": DECLARATION_VERSION,
        "statement_sha256": STATEMENT_SHA256,
        "accepted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
        "note": note,
    }
    data[feature] = record
    _save(data)
    return record


def grant_session(feature: str = FEATURE_WEB_EXPLOIT, target: str = "") -> dict:
    """仅本次进程有效的历史声明记录，不写配置。"""
    with _SESSION_LOCK:
        _SESSION.add(feature)
    return {"granted": True, "feature": feature, "source": "cli-session",
            "target": target, "declaration_version": DECLARATION_VERSION,
            "accepted_at": time.strftime("%Y-%m-%d %H:%M:%S")}


def revoke(feature: str = FEATURE_WEB_EXPLOIT) -> bool:
    with _SESSION_LOCK:
        _SESSION.discard(feature)
    data = _load()
    if feature in data:
        data[feature] = {"granted": False,
                         "revoked_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        _save(data)
        return True
    return False


def is_granted(feature: str = FEATURE_WEB_EXPLOIT) -> bool:
    with _SESSION_LOCK:
        if feature in _SESSION:
            return True
    rec = (_load().get(feature) or {})
    return bool(rec.get("granted")) and \
        rec.get("declaration_version") == DECLARATION_VERSION and \
        rec.get("statement_sha256") == STATEMENT_SHA256


def status(feature: str = FEATURE_WEB_EXPLOIT) -> dict:
    rec = (_load().get(feature) or {})
    with _SESSION_LOCK:
        session = feature in _SESSION
    return {
        "feature": feature,
        "granted": is_granted(feature),
        "session_granted": session,
        "record": rec,
        "declaration_version": DECLARATION_VERSION,
        "declaration_text": DECLARATION_TEXT,
        "path": CONSENT_PATH,
    }


def require(feature: str = FEATURE_WEB_EXPLOIT):
    """兼容旧调用：授权判断已上移到启动责任说明，这里恒放行。"""
    return True
