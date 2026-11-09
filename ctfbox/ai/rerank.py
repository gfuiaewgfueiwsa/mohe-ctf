# -*- coding: utf-8 -*-
"""古典密码候选重排（本地小模型，v4.0.5）。

确定性求解器先给出多个可能明文，模型只做“哪一条最像有意义英文/正确 flag”
的选择题；不生成新内容，不接触网络。低资源机器可关闭。
"""
import os
import re
import threading

_LOCK = threading.Lock()
_BACKEND = None

_SYS = ("你是CTF古典密码助手。用户会给出单表替换密码的多个候选明文，"
        "其中只有一条是语义通顺的英文短句。只输出该候选的编号，不要输出其他内容。")


def _available_cfg():
    from .config import ai_config, rerank_enabled
    if not rerank_enabled():
        return None
    cfg = ai_config()
    if not cfg.get("model") or not cfg.get("runtime"):
        return None
    if not os.path.exists(cfg["model"]):
        return None
    return cfg


def _prompt(texts):
    lines = "\n".join("%d. %s" % (i, t) for i, t in enumerate(texts))
    return ("<|im_start|>system\n%s<|im_end|>\n"
            "<|im_start|>user\n候选明文：\n%s\n\n请只输出最有意义的一条的编号（0-%d）。"
            "<|im_end|>\n<|im_start|>assistant\n" % (_SYS, lines, len(texts) - 1))


def pick(texts, log=None):
    """返回选中下标；不可用/失败返回 None。"""
    global _BACKEND
    texts = [str(t)[:200] for t in (texts or []) if str(t).strip()]
    if len(texts) < 2:
        return None
    cfg = _available_cfg()
    if not cfg:
        return None
    with _LOCK:
        try:
            from .backend import LlamaServer
            if _BACKEND is None:
                _BACKEND = LlamaServer(cfg["runtime"], cfg["model"], ngl=cfg["ngl"],
                                       ctx=min(int(cfg.get("ctx", 4096)), 2048),
                                       port=int(cfg.get("port", 18080)) + 1,
                                       timeout=min(int(cfg.get("timeout", 120)), 60),
                                       log=log or (lambda m: None),
                                       reserve_mb=cfg.get("vram_reserve_mb", 4096),
                                       fallback_exe=cfg.get("runtime_cpu", ""))
                if not _BACKEND.start():
                    _BACKEND = None
                    return None
            out = _BACKEND.complete(_prompt(texts), max_tokens=8, temperature=0.0)
            m = re.search(r"\d+", out or "")
            if not m:
                return None
            idx = int(m.group(0))
            return idx if 0 <= idx < len(texts) else None
        except Exception as exc:
            if log:
                log("[ai] 候选重排失败：%s" % exc)
            return None


def shutdown():
    global _BACKEND
    if _BACKEND:
        try:
            _BACKEND.stop()
        except Exception:
            pass
        _BACKEND = None
