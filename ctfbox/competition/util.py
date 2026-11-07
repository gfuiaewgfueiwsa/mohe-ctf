# -*- coding: utf-8 -*-
"""赛事专项公共设施：工作区、工具探测、子进程、结果结构。"""
import json
import os
import re
import shutil
import subprocess
import sys
import time

from ..common import (APP_DIR, IS_FROZEN, WORKSPACE, external_python,
                      human_size, safe_name, scan_flags)

COMP_ROOT = os.path.join(WORKSPACE, "competition")


def case_dir(kind: str, target: str = "") -> str:
    """为一次分析创建独立目录：workspace/competition/<时间>_<类型>_<名称>/。"""
    stem = time.strftime("%Y%m%d_%H%M%S")
    label = safe_name(os.path.basename(str(target).rstrip("\\/")) or "case")[:40]
    path = os.path.join(COMP_ROOT, "%s_%s_%s" % (stem, kind, label))
    os.makedirs(path, exist_ok=True)
    os.makedirs(os.path.join(path, "artifacts"), exist_ok=True)
    return path


def save_text(outdir: str, name: str, text: str) -> str:
    path = os.path.join(outdir, "artifacts", safe_name(name))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fp:
        fp.write(text)
    return path


def save_json(outdir: str, name: str, data) -> str:
    return save_text(outdir, name, json.dumps(data, ensure_ascii=False,
                                               indent=2, default=str))


def save_bytes(outdir: str, name: str, data: bytes) -> str:
    """按相对路径保存二进制产物，逐段清洗，避免目录穿越。"""
    parts = [safe_name(p) for p in str(name).replace("\\", "/").split("/") if p]
    path = os.path.join(outdir, "artifacts", *(parts or ["unnamed.bin"]))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fp:
        fp.write(data)
    return path


def make_result(kind: str, outdir: str, ok: bool = True, summary: str = "",
                findings=None, artifacts=None, notes=None, data=None) -> dict:
    return {
        "version": "3.7.0",
        "kind": kind,
        "ok": bool(ok),
        "summary": summary,
        "outdir": outdir,
        "findings": findings or [],
        "artifacts": artifacts or [],
        "notes": notes or [],
        "data": data or {},
        "finished": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def finish(result: dict, report_text: str) -> dict:
    """落盘 report.md / result.json（result.json 最后写，含全部产物路径）。"""
    outdir = result["outdir"]
    result["artifacts"].append(save_text(outdir, "report.md", report_text))
    result["artifacts"].append(save_json(outdir, "result.json", result))
    return result


def finding(level: str, title: str, detail: str = "", data=None) -> dict:
    return {"level": level, "title": title, "detail": str(detail or ""),
            "data": data or {}}


def add(result: dict, level: str, title: str, detail: str = "", data=None):
    result["findings"].append(finding(level, title, detail, data))


def add_artifact(result: dict, path: str):
    if path and path not in result["artifacts"]:
        result["artifacts"].append(path)


def flag_hit(result: dict, flag: str, source: str) -> bool:
    flags = result.setdefault("data", {}).setdefault("flags", [])
    if flag in flags:
        return False
    flags.append(flag)
    result["findings"].append(finding("flag", "发现 flag（%s）" % source, flag,
                                      {"flag": flag}))
    return True


def flag_scan(data, source: str, result: dict) -> list:
    if isinstance(data, str):
        raw = data.encode("utf-8", "ignore")
    else:
        raw = bytes(data or b"")
    found = scan_flags(raw, strong_only=True)
    for flag in found:
        flag_hit(result, flag, source)
    return found


def run_cmd(args, timeout: float = 120, cwd: str = "", input_data=None,
            env=None, check=False):
    """静默运行外部命令，返回 dict(rc, stdout, stderr, elapsed, timeout)。"""
    started = time.time()
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    try:
        proc = subprocess.run(
            args, cwd=cwd or None, input=input_data, timeout=timeout,
            capture_output=True, env=full_env, check=False,
            creationflags=(0x08000000 if sys.platform.startswith("win") else 0))
        out = _decode(proc.stdout)
        err = _decode(proc.stderr)
        return {"rc": proc.returncode, "stdout": out, "stderr": err,
                "elapsed": round(time.time() - started, 2), "timeout": False}
    except subprocess.TimeoutExpired as exc:
        return {"rc": -1, "stdout": _decode(exc.stdout or b""),
                "stderr": _decode(exc.stderr or b"") + "\n[timeout]",
                "elapsed": round(time.time() - started, 2), "timeout": True}
    except Exception as exc:
        return {"rc": -1, "stdout": "", "stderr": str(exc),
                "elapsed": round(time.time() - started, 2), "timeout": False}


def _decode(raw) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    for enc in ("utf-8", "gb18030", "utf-16-le", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", "replace")


def which(name: str, extra=None) -> str:
    """先找随包工具目录，再找 PATH。"""
    for cand in (extra or []):
        if cand and os.path.isfile(cand):
            return cand
    return shutil.which(name) or ""


def portable_dir(name: str) -> str:
    return os.path.join(APP_DIR, "tools", "portable", name)


def runtime_python() -> str:
    cand = os.path.join(APP_DIR, "tools", "runtime", "python", "python.exe")
    if os.path.isfile(cand):
        return cand
    return external_python() or ""


def python_scripts_dir(py: str) -> str:
    if not py:
        return ""
    return os.path.join(os.path.dirname(py), "Scripts")


def find_volatility() -> dict:
    """定位 Volatility 3：vol.exe / vol.py / Python 模块三种形态。"""
    candidates = []
    env = os.environ.get("VOLATILITY", "")
    if env:
        candidates.append(env)
    py = runtime_python()
    scripts = python_scripts_dir(py)
    if scripts:
        candidates += [os.path.join(scripts, "vol.exe"),
                       os.path.join(scripts, "vol.py"),
                       os.path.join(scripts, "vol")]
    candidates += [
        os.path.join(portable_dir("volatility3"), "vol.exe"),
        os.path.join(portable_dir("volatility3"), "vol.py"),
        shutil.which("vol") or "",
        shutil.which("vol.py") or "",
    ]
    # 开发机常见位置：与 python.exe 同级的 Scripts
    if sys.executable:
        d = os.path.dirname(sys.executable)
        candidates += [os.path.join(d, "Scripts", "vol.exe"),
                       os.path.join(d, "Scripts", "vol.py")]
    for cand in candidates:
        if cand and os.path.isfile(cand):
            kind = "python-module" if cand.lower().endswith(".py") else "exe"
            return {"available": True, "path": cand, "kind": kind,
                    "python": py, "version": _vol_version(cand, py)}
    # 只有模块可用时，用 python -c 引导
    for candidate in (py, sys.executable):
        if not candidate:
            continue
        r = run_cmd([candidate, "-c", "import volatility3"], timeout=15)
        if r["rc"] == 0:
            return {"available": True, "path": "", "kind": "module-bootstrap",
                    "python": candidate, "version": _vol_version("", candidate)}
    return {
        "available": False, "path": "", "kind": "", "python": py, "version": "",
        "install": "pip install volatility3（约 2 MB；Windows 符号表按镜像另行下载，"
                   "通常 20-80 MB，首次分析需联网或预置 symbols 目录）",
    }


def vol_command(info: dict, args) -> list:
    """把 Volatility 调用统一成可执行命令（模块形态用 python -c 引导）。"""
    if info.get("path"):
        if info["path"].lower().endswith(".py"):
            return [info.get("python") or sys.executable, info["path"]] + list(args)
        return [info["path"]] + list(args)
    bootstrap = ("import sys; sys.argv=['vol']+sys.argv[1:]; "
                 "from volatility3.cli import main; main()")
    return [info.get("python") or sys.executable, "-c", bootstrap] + list(args)


def _vol_version(path: str, py: str) -> str:
    try:
        cmd = [path, "--help"] if path and not path.lower().endswith(".py") else \
            ([py, path, "--help"] if path else [py, "-c", "import volatility3; print(getattr(volatility3,'__version__',''))"])
        r = run_cmd(cmd, timeout=20)
        first = (r["stdout"] or r["stderr"]).splitlines()[0] if (r["stdout"] or r["stderr"]) else ""
        return first.strip()
    except Exception:
        return ""


def find_jadx() -> str:
    p = portable_dir("jadx")
    for rel in ("bin/jadx.bat", "bin/jadx.exe", "jadx.bat", "jadx.exe"):
        cand = os.path.join(p, rel)
        if os.path.isfile(cand):
            return cand
    return shutil.which("jadx") or ""


def find_apktool() -> str:
    p = portable_dir("apktool")
    for rel in ("apktool.bat", "apktool.jar", "apktool"):
        cand = os.path.join(p, rel)
        if os.path.isfile(cand):
            return cand
    return shutil.which("apktool") or ""


def jadx_env() -> dict:
    """jadx.bat 需要 java；指向随包 JRE。"""
    root = os.path.join(APP_DIR, "tools", "runtime")
    for name in ("jre", "jdk-21.0.12.1+1-jre"):
        cand = os.path.join(root, name)
        if os.path.isfile(os.path.join(cand, "bin", "java.exe")):
            return {"JAVA_HOME": cand,
                    "PATH": os.path.join(cand, "bin") + os.pathsep + os.environ.get("PATH", "")}
    return {}


def find_7z() -> str:
    p = portable_dir("7z")
    for rel in ("7z.exe", "7za.exe"):
        cand = os.path.join(p, rel)
        if os.path.isfile(cand):
            return cand
    return shutil.which("7z") or ""


def size_text(path: str) -> str:
    try:
        return human_size(os.path.getsize(path))
    except Exception:
        return "?"


def read_text(path: str, limit: int = 4 * 1024 * 1024) -> str:
    with open(path, "rb") as fp:
        raw = fp.read(limit)
    return _decode(raw)


def short(text, n: int = 300) -> str:
    text = str(text or "").replace("\r", " ").replace("\n", " ")
    return text[:n] + ("…" if len(text) > n else "")


def iter_artifacts(directory: str, exts=None, max_files: int = 5000):
    exts = {e.lower() for e in (exts or [])}
    count = 0
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules")]
        for name in files:
            if exts and not any(name.lower().endswith(e) for e in exts):
                continue
            yield os.path.join(root, name)
            count += 1
            if count >= max_files:
                return


def clean_json_rows(text: str) -> list:
    """从混合日志/JSON Lines 中提取对象。Volatility 的 json renderer 每行一个对象。"""
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{") or not line.endswith("}"):
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    if rows:
        return rows
    # 兼容单个 JSON 数组/对象输出
    text = (text or "").strip()
    if text.startswith("["):
        try:
            obj = json.loads(text)
            return obj if isinstance(obj, list) else []
        except Exception:
            pass
    if text.startswith("{"):
        try:
            obj = json.loads(text)
            return [obj]
        except Exception:
            pass
    return []


def safe_rel(path: str) -> str:
    return re.sub(r"[\r\n\t]+", " ", str(path))
