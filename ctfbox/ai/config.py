# -*- coding: utf-8 -*-
"""AI conductor 配置解析（环境变量 > ai_config.json > 自动探测）。

v4.1 面向低配机器：按显存/物理内存自动选模型与推理参数。
  - 模型只在候选重排/路由里当「粘合剂」，不主导解题；
  - 无 NVIDIA 或内存偏小时直接选最小 GGUF 并走 CPU，避免 GPU 启动超时；
  - 源码运行时（PYTHONPATH 指向源码树）自动回退到同级分发目录找模型与 runtime。
"""
import glob
import json
import os
import shutil
import subprocess

from ..common import APP_DIR

_DEFAULTS = {
    "enabled": False,
    "conductor": False,      # 动作编排：实测 0 增益且拖慢，默认关；MOHE_AI_CONDUCTOR=1 可显式开启
    # 候选重排：确定性求解器已给出有序候选，模型只做选择题。实测仅改变排序、
    # 未新增候选；而每次调用要启动/占用 llama-server（首调 +7s，之后 +1~5s），
    # 批量自动化里纯属成本。默认关，MOHE_AI_RERANK=1 或 "rerank": true 可显式开启。
    "rerank": False,
    "model": "",
    "runtime": "",
    "runtime_cpu": "",
    "ngl": "auto",
    "vram_reserve_mb": 4096,
    "ctx": 2048,
    "max_decisions": 2,
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
        cfg["conductor"] = cfg["enabled"]
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


def _total_ram_mb():
    """物理内存（MB）；取不到返回 0，按「保守=低配」处理。"""
    try:
        import ctypes

        class _MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

        st = _MEMORYSTATUSEX()
        st.dwLength = ctypes.sizeof(st)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st))
        return int(st.ullTotalPhys // (1024 * 1024))
    except Exception:
        return 0


_VRAM_CACHE = [None]          # nvidia-smi 最多探一次；每次 ai_config() 都跑会拖慢解题


def _vram_mb():
    if _VRAM_CACHE[0] is not None:
        return _VRAM_CACHE[0]
    val = 0
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
            timeout=6, creationflags=0x08000000 if os.name == "nt" else 0)
        val = int(out.decode("utf-8", "replace").strip().splitlines()[0].strip())
    except Exception:
        val = 0
    _VRAM_CACHE[0] = val
    return val


def _low_resource():
    """是否按低配收敛：显式 MOHE_AI_PROFILE=low/high 可覆盖自动判断。"""
    profile = os.environ.get("MOHE_AI_PROFILE", "auto").lower()
    if profile == "low":
        return True
    if profile == "high":
        return False
    if not _has_nvidia():
        return True                      # 无独显：直接 CPU + 小模型，跳过 GPU 启动等待
    ram = _total_ram_mb()
    vram = _vram_mb()
    if ram and ram < 12000:              # <12GB 内存：Ghidra/ffmpeg/浏览器还要留余量
        return True
    if vram and vram < 6000:             # <6GB 显存：3B Q4 常驻 + KV 太紧
        return True
    return False


def _app_dirs():
    """模型/runtime 的搜索路径：APP_DIR 优先，其次同级分发目录。"""
    dirs = []
    env_dist = os.environ.get("MOHE_AI_DIST", "")
    if env_dist and os.path.isdir(env_dist):
        dirs.append(env_dist)
    dirs.append(APP_DIR)
    parent = os.path.dirname(APP_DIR)
    for name in ("魔盒-CTF", "mohe-ctf", "dist", "CTFToolbox"):
        p = os.path.join(parent, name)
        if os.path.isdir(p) and p not in dirs:
            dirs.append(p)
    return dirs


def _find_runtime(rel):
    for d in _app_dirs():
        p = os.path.join(d, *rel)
        if os.path.isfile(p):
            return p
    return ""


def _discover(cfg):
    low = _low_resource()
    if not cfg.get("model"):
        found = []
        for d in _app_dirs():
            found += glob.glob(os.path.join(d, "models", "*.gguf"))
        found = sorted(set(found), key=lambda p: os.path.getsize(p))
        # 低配取最小（1.5B/0.5B），配置充足取最大（3B）：同一份分发包适配不同机器
        cfg["model"] = (found[0] if low else found[-1]) if found else ""
    cuda = _find_runtime(("runtime", "llama", "cuda", "llama-server.exe"))
    cpu = _find_runtime(("runtime", "llama", "cpu", "llama-server.exe"))
    if not cfg.get("runtime_cpu") and cpu:
        cfg["runtime_cpu"] = cpu
    if not cfg.get("runtime"):
        if cuda and _has_nvidia() and not low:
            cfg["runtime"] = cuda
        elif cpu:
            cfg["runtime"] = cpu
        elif cuda:
            cfg["runtime"] = cuda
        else:
            found = []
            for d in _app_dirs():
                found += glob.glob(os.path.join(d, "runtime", "llama", "**",
                                                "llama-server.exe"), recursive=True)
            cfg["runtime"] = found[0] if found else ""
    if low:
        # CPU 推理一次 10~40s：只留一次决策、上下文砍半，NGPU 直接 0 免 120s 启动等待
        cfg["ngl"] = 0
        cfg["ctx"] = min(int(cfg.get("ctx", 2048)), 1024)
        cfg["max_decisions"] = 1
        cfg["timeout"] = min(int(cfg.get("timeout", 120)), 60)
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


def conductor_enabled():
    """动作编排是否启用；候选重排只看 rerank_enabled()。

    实测（2026-11-09，8 题 A/B + 换 1.5B 复测）：编排新增候选 0、每次 +4~8s，
    重排 3B 4/4、1.5B 3/4。故编排默认关闭，保留显式开关做实验。
    """
    if os.environ.get("MOHE_AI_DISABLE", "").lower() in ("1", "true", "on", "yes"):
        return False
    if os.environ.get("MOHE_AI_CONDUCTOR", "").lower() in ("1", "true", "on", "yes"):
        return True
    return bool(ai_config().get("conductor"))


def rerank_enabled():
    """候选重排是否启用（默认关）。

    v4.1.0：旧实现只判断总开关 `enabled`，导致 ai_config.json 打开 AI 后，
    每一次古典密码分析都会拉起 llama-server（首调实测 +7s、之后每题 +1~5s），
    而 A/B 结果表明重排只改变顺序、不新增候选。批量跑题时这是纯损耗，
    因此拆成独立开关：MOHE_AI_RERANK=1 或 "rerank": true 才启用。
    """
    if os.environ.get("MOHE_AI_DISABLE", "").lower() in ("1", "true", "on", "yes"):
        return False
    flag = os.environ.get("MOHE_AI_RERANK", "")
    if flag:
        return flag.lower() in ("1", "true", "on", "yes")
    return bool(ai_config().get("rerank"))
