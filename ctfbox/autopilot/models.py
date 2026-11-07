# -*- coding: utf-8 -*-
"""编排层通用数据模型：候选 flag、工具结果。"""
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List


def jsonable(value: Any) -> Any:
    """把 bytes / dataclass / 路径等转换成可 JSON 序列化的结构。"""
    if isinstance(value, (bytes, bytearray)):
        return {"_bytes_len": len(value), "_preview": bytes(value[:64]).hex(" ")}
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [jsonable(v) for v in value]
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


@dataclass
class Candidate:
    """候选 flag：必须带置信度与依据，禁止只给结论不给来源。"""
    value: str
    confidence: float          # 0.0 ~ 1.0
    source: str                # 工具@步骤，如 xor.repeating@step3
    reason: str = ""           # 命中依据：解码链 / 异或密钥 / 明文可读性
    chain: str = ""            # 解码链（可选）

    def to_dict(self):
        return asdict(self)


@dataclass
class ToolResult:
    ok: bool = True
    tool: str = ""
    summary: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    candidates: List[Candidate] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "ok": self.ok,
            "tool": self.tool,
            "summary": self.summary,
            "data": jsonable(self.data),
            "candidates": [c.to_dict() for c in self.candidates],
            "artifacts": list(self.artifacts),
            "notes": list(self.notes),
        }
