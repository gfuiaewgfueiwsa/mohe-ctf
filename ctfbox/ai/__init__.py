# -*- coding: utf-8 -*-
"""内置本地小模型（默认关闭）作为 AutoPilot 之后的“裁判/粘合剂”。

定位：不负责解题主体，只在一键梭哈收尾后读取结构化报告，从固定工具白名单里
选择下一步动作与深度并交编排层执行。安全边界仍由责任闸门 + scope 白名单强制。
"""
from .config import ai_config, ai_enabled

__all__ = ["ai_config", "ai_enabled"]
