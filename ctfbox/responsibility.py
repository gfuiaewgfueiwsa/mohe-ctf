# -*- coding: utf-8 -*-
"""软件责任说明：进入软件前的唯一闸门。

规则：
  1. GUI 每次启动展示责任说明，必须勾选同意才能进入；
  2. CLI 首次使用需 --accept-responsibility，确认结果持久化；
  3. 未同意时软件不进入任何功能页、不执行任何分析；
  4. 说明版本变化后旧确认失效。
"""
import hashlib
import json
import os
import time

from .common import WORKSPACE

RESPONSIBILITY_VERSION = "1"
CONFIG_DIR = os.path.join(WORKSPACE, "config")
RESPONSIBILITY_PATH = os.path.join(CONFIG_DIR, "responsibility.json")

RESPONSIBILITY_TEXT = """魔盒-CTF 软件责任说明（进入前必须阅读并同意）

一、授权与合法使用
1. 我确认：我对使用本软件测试的每一个目标，均已取得明确、合法、有效的授权
   （CTF 比赛题目实例、经授权的渗透测试、本人自有资产，或公开允许测试的靶场）。
2. 我理解：软件不判断目标归属，也不为我的行为背书；未授权测试、入侵、干扰、
   窃取数据等行为由我承担全部法律责任。
3. 我理解：软件集成的第三方工具可能有各自的许可证与使用条款，我应自行遵守。

二、能力与风险
1. 软件可向目标发送真实网络请求、构造并发送漏洞验证 payload、上传验证样本、
   读取/解包/修改本地文件、调用本地第三方工具。
2. 软件输出可能不准确、不完整，可能导致目标服务异常或数据变化；
   我应在具备回滚与隔离措施的环境中使用，并自行评估影响。
3. 自动化结果只是线索，是否采信、是否继续利用由我人工判断并承担后果。

三、数据与隐私
1. 软件会把输入副本、请求记录、payload 摘要、响应证据与运行日志写入
   workspace 任务目录；其中可能包含敏感信息，由我负责保管、脱敏与删除。
2. 软件自身不上传任务数据；第三方工具若联网，由其自身行为决定。

四、无担保与责任限制
本软件按“现状”提供，不附带任何明示或暗示担保。因使用或无法使用本软件
造成的任何直接或间接损失，开发者与分发者不承担责任。

五、确认
点击“同意并进入”表示我已逐条阅读、理解并接受以上全部内容；
不同意则退出软件，不进入任何功能。
"""

STATEMENT_SHA256 = hashlib.sha256(
    (RESPONSIBILITY_TEXT + "\nversion=" + RESPONSIBILITY_VERSION).encode("utf-8")
).hexdigest()


def _load() -> dict:
    try:
        with open(RESPONSIBILITY_PATH, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def is_accepted() -> bool:
    rec = _load()
    return (bool(rec.get("accepted")) and
            rec.get("version") == RESPONSIBILITY_VERSION and
            rec.get("statement_sha256") == STATEMENT_SHA256)


def accept(source: str = "cli", note: str = "") -> dict:
    record = {
        "accepted": True,
        "version": RESPONSIBILITY_VERSION,
        "statement_sha256": STATEMENT_SHA256,
        "accepted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
        "note": note,
    }
    os.makedirs(CONFIG_DIR, exist_ok=True)
    tmp = RESPONSIBILITY_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fp:
        json.dump(record, fp, ensure_ascii=False, indent=2)
    os.replace(tmp, RESPONSIBILITY_PATH)
    return record


def revoke() -> bool:
    data = _load()
    if not data:
        return False
    data["accepted"] = False
    data["revoked_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(RESPONSIBILITY_PATH, "w", encoding="utf-8") as fp:
        json.dump(data, fp, ensure_ascii=False, indent=2)
    return True


def status() -> dict:
    return {
        "accepted": is_accepted(),
        "version": RESPONSIBILITY_VERSION,
        "statement_sha256": STATEMENT_SHA256,
        "text": RESPONSIBILITY_TEXT,
        "path": RESPONSIBILITY_PATH,
        "record": _load(),
    }


def ensure_cli(argv) -> bool:
    """CLI 闸门：已接受或带 --accept-responsibility 则放行。"""
    if is_accepted():
        return True
    if "--accept-responsibility" in (argv or []):
        accept("cli", "CLI --accept-responsibility")
        return True
    print(RESPONSIBILITY_TEXT)
    print("未同意《软件责任说明》，无法进入软件。")
    print("同意请重新运行并添加 --accept-responsibility（确认结果会保存在本机）。")
    return False
