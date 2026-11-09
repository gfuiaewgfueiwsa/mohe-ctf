# -*- coding: utf-8 -*-
"""内置本地小模型（默认关闭）作为 AutoPilot 之后的“裁判/粘合剂”。

定位：不负责解题主体，只在确定性流程给出候选后做选择题（重排/路由）。
安全边界仍由责任闸门 + scope 白名单强制。

三个开关彼此独立，避免「打开总开关就处处拉起模型」：
  - ai_enabled()       模型文件 + runtime 就绪
  - conductor_enabled() 动作编排（默认关：实测 0 增益且每题 +4~8s）
  - rerank_enabled()    候选重排（默认关：只改顺序、不新增候选，首调 +7s）
"""
from .config import ai_config, ai_enabled, conductor_enabled, rerank_enabled

__all__ = ["ai_config", "ai_enabled", "conductor_enabled", "rerank_enabled"]
