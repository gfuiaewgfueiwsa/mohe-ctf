# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：CTFToolbox"""
import os
from PyInstaller.utils.hooks import collect_all, collect_submodules

SPECPATH = os.path.abspath(os.getcwd())

# === PE 版本资源由 ctfbox.__version__ 生成，杜绝 exe 属性与源码版本漂移 ===
# 以前 version_info.txt 是手写文件，长期停在 3.7.0.0，而界面/报告已是 4.x。
try:
    from ctfbox.versioning import write_version_info
    _VI = write_version_info(os.path.join(SPECPATH, "version_info.txt"))
    print("version_info:", _VI)
except Exception as e:  # 兜底：实在生成不了就用仓库存量文件，不让打包中断
    print("version_info regenerate skip", e)

datas = []
binaries = []
hiddenimports = []
for pkg in ("customtkinter", "scapy", "capstone", "elftools", "pefile",
            "windnd", "cv2", "PIL", "paramiko", "Crypto", "Cryptodome",
            "cryptography", "numpy", "qrcode", "gmssl", "Registry", "Evtx"):
    try:
        d, b, h = collect_all(pkg)
        datas += d; binaries += b; hiddenimports += h
    except Exception as e:
        print("collect_all skip", pkg, e)

# 显式收集 ctfbox 本地包全部子模块（含函数内动态 import 与新增 modules_polar，避免漏模块）
try:
    hiddenimports += collect_submodules("ctfbox")
    print("ctfbox submodules:", len([m for m in hiddenimports if m.startswith("ctfbox")]))
except Exception as e:
    print("collect_submodules ctfbox skip", e)

# 显式补 scapy 各协议层（动态导入，避免打包后读包缺层）
hiddenimports += [
    "scapy.layers.all", "scapy.layers.inet", "scapy.layers.l2",
    "scapy.layers.tls.all", "scapy.layers.usb", "scapy.layers.http",
    "scapy.layers.dns", "scapy.layers.dot11", "scapy.layers.tftp",
    "scapy.layers.ntp", "scapy.arch.pcapdnet",
    # v2.0 新增能力的直接依赖
    "gmssl.sm4", "gmssl.func", "Registry.Registry", "Evtx.Evtx", "Evtx.Views",
    "qrcode.image.pil", "qrcode.image.pure",
]

# 随包分发测试样例与实战解题脚本。
# 注：tools（约 3GB，含 runtime 与全部 portable 工具）不进 PyInstaller COLLECT，
# 由构建脚本在打包后用 robocopy 直接镜像到 dist\CTFToolbox\tools（更稳、避免 _internal 超长路径）。
for folder in ("samples", "scripts"):
    src = os.path.join(SPECPATH, folder)
    if os.path.isdir(src):
        datas.append((src, folder))

a = Analysis(
    ["main.py"],
    pathex=[SPECPATH],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["matplotlib", "pytest", "IPython", "jupyter", "tkinter.test"],
    noarchive=False,
)

# === 锁定 Tcl/Tk 运行库版本，避免 PATH 上其它版本(如 8.6.12)的 dll 被误收集，
#     与构建解释器自带的 _tcl_data/_tk_data 脚本(8.6.15)版本冲突导致 GUI 起不来 ===
import sys as _sys
_TCLTK_DLLS = {"tcl86t.dll", "tk86t.dll", "tcl86tg.dll", "tk86tg.dll",
               "libtcl8.6.dll", "libtk8.6.dll"}
_dlls_dir = os.path.join(_sys.base_prefix, "DLLs")
a.binaries = TOC([e for e in a.binaries
                  if os.path.basename(e[0]).lower() not in _TCLTK_DLLS])
for _fn in ("tcl86t.dll", "tk86t.dll"):
    _p = os.path.join(_dlls_dir, _fn)
    if os.path.exists(_p):
        a.binaries.append((_fn, _p, "BINARY"))

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CTFToolbox",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    version="version_info.txt",
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="CTFToolbox",
)
