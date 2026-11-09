# -*- coding: utf-8 -*-
"""单表替换密码求解器（v4.0.5）。

思路：按“词形模式”检索随包分发的英语高频词表，用 beam search 维护全局
字母一一映射。适合 CTF 中 afctf{...}/flag{...} 这类短句替换密码，离线可用。
"""
import math
import os
import re
from collections import defaultdict

_WORDS = None
_BY_PAT = None
_RANK = None
_PREFIX = ("flag", "ctf", "afctf", "n1book", "dasctf", "buuctf", "sctf",
           "nssctf", "ctfshow", "key", "secret", "answer", "hgame", "polarflag")


def _pattern(w):
    mp = {}
    out = []
    for ch in w.lower():
        if ch not in mp:
            mp[ch] = len(mp)
        out.append(mp[ch])
    return tuple(out)


def _load():
    global _WORDS, _BY_PAT, _RANK
    if _BY_PAT is not None:
        return
    words = []
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "english_ranks.txt")
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            words = [ln.strip().lower() for ln in f if ln.strip().isalpha()]
    except Exception:
        words = []
    _WORDS = words
    _RANK = {w: i + 1 for i, w in enumerate(words)}
    by_pat = defaultdict(list)
    for i, w in enumerate(words):
        if 2 <= len(w) <= 12:
            by_pat[_pattern(w)].append((w, i + 1))
    for w in _PREFIX:
        if w not in _RANK:
            by_pat[_pattern(w)].insert(0, (w, 1))
    _BY_PAT = by_pat


def apply_map(text, mp):
    out = []
    for ch in text:
        if ch.isalpha():
            p = mp.get(ch.lower())
            out.append((p.upper() if ch.isupper() else p) if p else ch)
        else:
            out.append(ch)
    return "".join(out)


def crack(text, topn=8, beam=800, cap=1200):
    """返回 [(明文, 分数), ...] 按分数降序；仅处理 <=600 字符的文本。"""
    _load()
    text = str(text or "")
    if not text or len(text) > 600:
        return []
    toks = [m.group(0) for m in re.finditer(r"[A-Za-z]+", text) if len(m.group(0)) >= 2]
    if len(toks) < 2:
        return []
    tasks = []
    for tok in toks:
        lst = _BY_PAT.get(_pattern(tok), [])[:cap]
        tasks.append((tok, lst))
    tasks.sort(key=lambda x: len(x[1]))
    states = [({}, 0.0)]
    for tok, lst in tasks:
        cand = []
        for mp, sc in states:
            cand.append((mp, sc - 2.0))  # 允许词表外单词（如比赛前缀）
            for w, rank in lst:
                nm = dict(mp)
                ok = True
                for c, p in zip(tok.lower(), w):
                    if c in nm and nm[c] != p:
                        ok = False
                        break
                    nm[c] = p
                if not ok:
                    continue
                vals = list(nm.values())
                if len(vals) != len(set(vals)):
                    continue
                cand.append((nm, sc + 0.5 + 0.35 * len(w) - 0.08 * math.log(rank + 1)))
        cand.sort(key=lambda x: -x[1])
        states = cand[:beam]
    out, seen = [], set()
    for mp, sc in states:
        plain = apply_map(text, mp).strip()
        if plain and plain not in seen:
            seen.add(plain)
            out.append((plain, sc))
        if len(out) >= topn:
            break
    return out
