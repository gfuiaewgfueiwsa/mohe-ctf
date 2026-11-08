# -*- coding: utf-8 -*-
"""AI conductor 配置解析（环境变量 > ai_config.json > 自动探测）。"""
import glob
import json
import os
import shutil

from ..common import APP_DIR

_DEFAULTS = {
    "enabled": False,
    "model": "",
    "runtime": "",
    "runtime_cpu": "",
    "ngl": "auto",
    "vram_reserve_mb": 4096,
    "ctx": 4096,
    "max_decisions": 3,
    "port": 18080,
    "timeout": 120,
}


def _load_file():
    path = os.path.join(APP_DIR, "ai_config.json")
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fp:
            data = json.load(fp)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _env_override(cfg):
    env = os.environ
    if "MOHE_AI_CONDUCTOR" in env:
        cfg["enabled"] = env["MOHE_AI_CONDUCTOR"].lower() in ("1", "true", "on", "yes")
    if env.get("MOHE_AI_MODEL"):
        cfg["model"] = env["MOHE_AI_MODEL"]
    if env.get("MOHE_AI_LLAMA"):
        cfg["runtime"] = env["MOHE_AI_LLAMA"]
    if env.get("MOHE_AI_LLAMA_CPU"):
        cfg["runtime_cpu"] = env["MOHE_AI_LLAMA_CPU"]
    if env.get("MOHE_AI_NGL"):
        cfg["ngl"] = env["MOHE_AI_NGL"]
    for key, cast in (("vram_reserve_mb", int), ("ctx", int), ("max_decisions", int),
                      ("port", int), ("timeout", int)):
        val = env.get("MOHE_AI_" + key.upper())
        if val:
            try:
                cfg[key] = cast(val)
            except ValueError:
                pass


def _has_nvidia():
    if shutil.which("nvidia-smi"):
        return True
    return os.path.exists(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                       "System32", "nvidia-smi.exe"))


def _discover(cfg):
    if not cfg.get("model"):
        found = sorted(glob.glob(os.path.join(APP_DIR, "models", "*.gguf")))
        cfg["model"] = found[0] if found else ""
    base = os.path.join(APP_DIR, "runtime", "llama")
    cuda = os.path.join(base, "cuda", "llama-server.exe")
    cpu = os.path.join(base, "cpu", "llama-server.exe")
    if not cfg.get("runtime_cpu") and os.path.exists(cpu):
        cfg["runtime_cpu"] = cpu
    if not cfg.get("runtime"):
        if os.path.exists(cuda) and _has_nvidia():
            cfg["runtime"] = cuda
        elif os.path.exists(cpu):
            cfg["runtime"] = cpu
        else:
            found = glob.glob(os.path.join(base, "**", "llama-server.exe"), recursive=True)
            cfg["runtime"] = found[0] if found else ""
    return cfg


def ai_config():
    cfg = dict(_DEFAULTS)
    file_cfg = _load_file()
    for key in cfg:
        if key in file_cfg:
            cfg[key] = file_cfg[key]
    _env_override(cfg)
    return _discover(cfg)


def ai_enabled():
    if os.environ.get("MOHE_AI_DISABLE", "").lower() in ("1", "true", "on", "yes"):
        return False
    cfg = ai_config()
    return bool(cfg.get("enabled") and cfg.get("model") and cfg.get("runtime")
                and os.path.exists(cfg["model"]) and os.path.exists(cfg["runtime"]))
