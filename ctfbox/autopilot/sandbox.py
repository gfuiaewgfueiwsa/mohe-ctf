# -*- coding: utf-8 -*-
"""沙箱层：不可信二进制禁止在宿主机直接执行。

本机实测（2026-11-07）：Docker 未安装；WSL 无可用发行版；Windows Sandbox
未验证可用。因此 v3.3.0 对未知二进制只做静态分析，没有“落地执行”能力。

这里保留隔离后端的探测与执行门禁；后端可用后才允许执行，避免误把
宿主机当靶机跑样本。
"""
import os
import shutil
import subprocess
import sys

from ..common import CREATE_NO_WINDOW
from ..versioning import version_tag


class SandboxUnavailable(RuntimeError):
    """没有可用隔离后端，拒绝执行不可信样本。"""


def _exists(path: str) -> bool:
    return bool(path) and os.path.exists(path)


def detect() -> dict:
    """探测本机可用隔离后端，返回真实状态，不做乐观假设。"""
    docker = shutil.which("docker")
    wsl = shutil.which("wsl")
    wsl_ready = False
    if wsl:
        try:
            out = subprocess.run([wsl, "-l", "-q"], capture_output=True, text=True,
                                 errors="replace", timeout=8, creationflags=CREATE_NO_WINDOW)
            wsl_ready = out.returncode == 0 and bool((out.stdout or "").strip())
        except Exception:
            wsl_ready = False
    win_sandbox = _exists(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                       "System32", "WindowsSandbox.exe"))
    backends = []
    if docker:
        backends.append("docker")
    if wsl_ready:
        backends.append("wsl")
    if win_sandbox:
        backends.append("windows-sandbox")
    return {
        "docker": bool(docker),
        "wsl": bool(wsl_ready),
        "windows_sandbox": bool(win_sandbox),
        "backends": backends,
        "can_execute_untrusted": bool(backends),
    }


def policy_text(caps: dict = None) -> str:
    caps = caps or detect()
    if caps.get("can_execute_untrusted"):
        return "检测到隔离后端：%s。执行未知样本前仍需人工确认镜像/沙箱配置。" % \
               ", ".join(caps.get("backends") or [])
    return ("本机无可用隔离后端（Docker/WSL/Windows Sandbox 均未就绪），"
            "%s 对未知二进制只做静态分析，不执行样本。" % version_tag())


def require_isolation() -> dict:
    caps = detect()
    if not caps.get("can_execute_untrusted"):
        raise SandboxUnavailable(policy_text(caps))
    return caps
