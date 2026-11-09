# -*- coding: utf-8 -*-
"""版本号单一来源。

整个工程里只有 ``ctfbox/__init__.py`` 的 ``__version__`` 一处字面量；
UI 文案、报告头、result.json、PyInstaller 的 PE 版本资源全部由这里派生，
避免出现「源码 4.x / exe 右键属性 3.7.0.0 / 报告里 3.7.0」这类漂移。
"""
from __future__ import annotations

import os
import re

from . import __version__ as VERSION

APP_VERSION = VERSION

# 命名规范：产品名统一大写 CTF（`魔盒-CTF`），完整展示名 `魔盒-CTF v4.1.0`。
# 所有界面标题、报告页眉、PE 资源、文档一律引用这里，禁止再手写小写 `ctf`。
APP_NAME = "魔盒-CTF"


def app_title() -> str:
    """完整展示名，如 ``魔盒-CTF v4.1.0``。"""
    return "%s %s" % (APP_NAME, version_tag())


def version_tag() -> str:
    """展示用版本号，带 v 前缀，如 ``v4.1.0``。"""
    return "v" + APP_VERSION


def version_tuple() -> tuple:
    """PE 版本资源用的四段式 ``(major, minor, patch, 0)``。"""
    nums = []
    for seg in str(APP_VERSION).split("."):
        m = re.match(r"\d+", seg.strip())
        nums.append(int(m.group()) if m else 0)
    while len(nums) < 4:
        nums.append(0)
    return tuple(nums[:4])


# 中英双 StringTable：Windows 资源管理器按语言回退，缺英文表时部分系统显示空白
_TEMPLATE = """# -*- coding: utf-8 -*-
# 由 ctfbox/versioning.py 依据 ctfbox.__version__ 自动生成，请勿手工编辑。
VSVersionInfo(
    ffi=FixedFileInfo(
        filevers={vt},
        prodvers={vt},
        mask=0x3f,
        flags=0x0,
        OS=0x40004,
        fileType=0x1,
        subtype=0x0,
        date=(0, 0),
    ),
    kids=[
        StringFileInfo([
            StringTable(
                '080404B0',
                [
                    StringStruct('CompanyName', '{name}'),
                    StringStruct('FileDescription', '{name} 万能 CTF 集合工具箱'),
                    StringStruct('FileVersion', '{dot}'),
                    StringStruct('InternalName', '{name}'),
                    StringStruct('LegalCopyright', '仅限 CTF 比赛与授权测试使用'),
                    StringStruct('OriginalFilename', '{name}.exe'),
                    StringStruct('ProductName', '{name} 万能 CTF 集合工具箱'),
                    StringStruct('ProductVersion', '{dot}'),
                ],
            ),
            StringTable(
                '040904B0',
                [
                    StringStruct('CompanyName', '{name}'),
                    StringStruct('FileDescription', '{name} All-in-One CTF Toolkit'),
                    StringStruct('FileVersion', '{dot}'),
                    StringStruct('InternalName', '{name}'),
                    StringStruct('LegalCopyright', 'For CTF contests and authorized testing only'),
                    StringStruct('OriginalFilename', '{name}.exe'),
                    StringStruct('ProductName', '{name} All-in-One CTF Toolkit'),
                    StringStruct('ProductVersion', '{dot}'),
                ],
            ),
        ]),
        VarFileInfo([VarStruct('Translation', [0x804, 1200, 0x409, 1200])]),
    ],
)
"""


def render_version_info() -> str:
    """返回 PE 版本资源文本（不落盘，便于单测断言）。"""
    vt = version_tuple()
    dot = ".".join(str(x) for x in vt)
    return _TEMPLATE.format(vt="(%d, %d, %d, %d)" % vt, dot=dot, name=APP_NAME)


def write_version_info(path: str) -> str:
    """把 PE 版本资源写到 ``path``；内容与旧文件一致则跳过写入。"""
    text = render_version_info()
    path = os.path.abspath(path)
    try:
        with open(path, "r", encoding="utf-8") as fp:
            if fp.read() == text:
                return path
    except OSError:
        pass
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fp:
        fp.write(text)
    os.replace(tmp, path)
    return path
