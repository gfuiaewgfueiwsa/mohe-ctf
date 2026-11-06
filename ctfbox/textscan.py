# -*- coding: utf-8 -*-
"""文本内嵌编码串的二次解码扫描（base64 / hex / URL 编码）。

真实题目里 flag 经常只藏在正文的某个编码片段里（"请解码：ZmxhZ..."、
"hex: 666c6167..."），主流程会把它当成哈希或普通文本。这里单独再扫一遍，
只做短链解码，命中 flag 才记 flag，避免刷一堆噪声。
"""
import re
import urllib.parse

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,}(?![0-9A-Fa-f])")


def _printable_ratio(text):
    if not text:
        return 0.0
    good = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return good / float(len(text))


def _decode_b64(token):
    import base64
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
    except Exception:
        return ""
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return ""


def _decode_hex(token):
    if len(token) % 2:
        token = token[:-1]
    try:
        raw = bytes.fromhex(token)
    except Exception:
        return ""
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return ""


def _scan_flags(text):
    try:
        from .common import scan_flags_text
        found = scan_flags_text(text)
        if found:
            return found
    except Exception:
        pass
    return [m.group(0) for m in re.finditer(r"(?i)\b[A-Za-z0-9_]{2,20}\{[ -~]{4,80}\}", text)]


def encoded_token_scan(text, rep, limit=10):
    """扫正文里的 base64/hex 片段，解码后查 flag。命中才写 flag 结论。"""
    if not isinstance(text, str) or len(text) > 2 * 1024 * 1024:
        return []
    candidates = []
    for mo in _B64_RE.finditer(text):
        candidates.append(("base64", mo.group(0)))
    for mo in _HEX_RE.finditer(text):
        candidates.append(("hex", mo.group(0)))
    seen = set()
    hits = []
    tried = 0
    for kind, token in candidates:
        if tried >= limit:
            break
        if (kind, token) in seen:
            continue
        seen.add((kind, token))
        tried += 1
        decoded = _decode_b64(token) if kind == "base64" else _decode_hex(token)
        if not decoded or _printable_ratio(decoded) < 0.85:
            continue
        flags = _scan_flags(decoded)
        if not flags:
            # 再往下一层：URL 编码 / 二次 base64
            try:
                unq = urllib.parse.unquote(decoded)
                if unq != decoded:
                    flags = _scan_flags(unq)
                    if flags:
                        decoded = unq
            except Exception:
                pass
        if not flags:
            continue
        hits.append({"kind": kind, "token": token[:64], "decoded": decoded[:160],
                     "flags": flags})
        rep.add("flag", "编码片段解码命中 flag（%s）" % kind,
                "原文片段：" + token[:64] + "\n解码结果：" + decoded[:160] +
                "\n命中：" + "; ".join(flags))
    return hits
