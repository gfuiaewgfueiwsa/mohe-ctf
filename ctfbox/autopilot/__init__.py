# -*- coding: utf-8 -*-
"""魔盒-CTF 自动化编排层（Agent 决策环）。

三层结构：
  - tools/     确定性工具层，可独立单测、不依赖编排器
  - workspace  每题一个任务目录，输入/产物/日志/证据链/结论全部落盘
  - scope/sandbox  授权边界与隔离策略（不可信样本默认只做静态分析）

版本号唯一来源：`ctfbox.__version__`（经 `ctfbox.versioning` 派生）。此前这里、
workspace.result.json、wp.py 各自硬编码版本，重打包后会出现「源码 4.x / 结果 3.7.0」
的漂移。

仅用于 CTF 靶场与用户已获授权的目标。
"""
from .. import __version__ as _APP_VERSION
from ..versioning import version_tag as _version_tag

__version__ = _APP_VERSION
VERSION = _version_tag()
