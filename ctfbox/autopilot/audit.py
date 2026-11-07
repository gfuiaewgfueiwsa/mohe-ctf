# -*- coding: utf-8 -*-
"""利用行为审计日志（v3.3.0）。

每条记录包含：时间、目标、工具、payload 摘要（sha256 + 前 200 字符）、
HTTP 状态/结果摘要。同时写入：
  - 当前任务目录 audit.jsonl（随任务工作区留存，可追溯）
  - workspace/audit/audit-YYYYMMDD.jsonl（全局审计，便于跨任务检索）
"""
import hashlib
import json
import os
import threading
import time

from ..common import WORKSPACE

AUDIT_DIR = os.path.join(WORKSPACE, "audit")


def payload_digest(payload) -> dict:
    """payload 摘要：不落完整载荷，只保留 hash 与前 200 字符。"""
    if payload is None or payload == "":
        return {"sha256": "", "preview": "", "len": 0}
    if isinstance(payload, (bytes, bytearray)):
        raw = bytes(payload)
        preview = raw[:200].hex(" ")
    else:
        raw = str(payload).encode("utf-8", "replace")
        preview = raw[:200].decode("utf-8", "replace")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "preview": preview, "len": len(raw)}


class AuditLog:
    """线程安全审计写入器。task_dir 为空时只写全局日志。"""

    def __init__(self, task_dir: str = ""):
        os.makedirs(AUDIT_DIR, exist_ok=True)
        self.task_path = os.path.join(task_dir, "audit.jsonl") if task_dir else ""
        self._lock = threading.Lock()
        self.count = 0

    def _write(self, path: str, item: dict):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a", encoding="utf-8") as fp:
                fp.write(json.dumps(item, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def record(self, target: str, tool: str, payload=None, result="",
               status: str = "unknown", extra: dict = None) -> dict:
        item = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": target,
            "tool": tool,
            "payload": payload_digest(payload),
            "result": str(result)[:500],
            "status": status,
        }
        if extra:
            item["extra"] = extra
        with self._lock:
            if self.task_path:
                self._write(self.task_path, item)
            global_path = os.path.join(
                AUDIT_DIR, "audit-" + time.strftime("%Y%m%d") + ".jsonl")
            self._write(global_path, item)
            self.count += 1
        return item

    def summary(self) -> dict:
        return {"entries": self.count,
                "task_path": self.task_path or "",
                "global_pattern": os.path.join(AUDIT_DIR, "audit-YYYYMMDD.jsonl")}
