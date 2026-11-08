# -*- coding: utf-8 -*-
"""固定格式 Writeup（WP）生成器。

格式版本：mohe-wp-v1
  1. 题目信息
  2. 信息收集
  3. 解题过程（按验证顺序分节）
  4. Flag
  5. 修复建议
  6. 附录：证据与审计

WP 只使用工具运行期间的真实请求/响应证据，不编造步骤；未命中的阶段会明确写「未确认」。
"""
import os
import re
import time

from .. import __version__ as APP_VERSION
from ..common import WORKSPACE
from .triage import triage_lines

WP_VERSION = "mohe-wp-v1"


def _clean(value, limit=600):
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text.replace("|", "\\|")[:limit]


def _flag_lines(result):
    out = []
    for cand in result.get("candidates") or []:
        if float(cand.get("confidence") or 0) >= 0.8 and cand.get("value") not in out:
            out.append(cand.get("value"))
    for flag in ((result.get("exploit") or {}).get("flags") or []):
        if flag not in out:
            out.append(flag)
    return out


def _finding_types(findings):
    return {item.get("type") for item in findings or []}


def _remediation(types):
    rules = [
        (("weak-login",),
         "登录入口使用弱口令且无失败锁定；改为强口令策略、失败次数限制、验证码与多因素认证。"),
        (("user-enum",),
         "资料页直接以可预测的用户名查询且回显完整资料；改为服务端会话内取当前用户，"
         "对查询接口做鉴权与限流，错误信息统一化。"),
        (("cmd-entry", "cmdi-direct", "cmdi-read", "cmdi-filter-bypass"),
         "后台命令执行入口把参数直接拼进 shell；改为固定功能接口、参数白名单校验，"
         "禁止把用户输入交给 shell，并移除敏感目录的读权限。"),
        (("deser", "source-rce", "php-deser"),
         "存在反序列化/源码泄露风险；禁止对不可信输入 unserialize，移除页面源码回显，"
         "升级框架并限制 include 路径。"),
        (("sql-injection", "sqli"),
         "SQL 拼接导致注入；使用参数化查询，最小化数据库账号权限，关闭错误回显。"),
        (("upload-exec", "upload-stored", "upload-include-exec", "upload-read"),
         "上传目录允许脚本落地或可被包含执行；改为后缀/内容白名单、随机文件名、"
         "上传目录关闭脚本解析并禁止 include 该目录，上传与站点分域存放。"),
        (("cookie-weak",),
         "会话 Cookie 缺少 HttpOnly/Secure/SameSite；补齐安全属性并缩短会话有效期。"),
    ]
    out = []
    for keys, text in rules:
        if any(k in types for k in keys):
            out.append(text)
    if not out:
        out.append("按最小权限原则收敛入口；为所有认证/查询接口补充鉴权、限流与审计。")
    out.append("本 WP 由自动化工具生成，利用请求仅限 CTF 靶场/自有授权资产；请勿用于未授权目标。")
    return out


def _narrative(findings):
    lines = []
    idx = 0
    order = ("weak-login", "user-enum", "cmd-entry", "cmdi-direct",
             "cmdi-read", "cmdi-filter-bypass", "source-rce", "deser",
             "sql-injection", "sqli", "upload-exec", "upload-stored",
             "upload-include-exec", "upload-read", "ssti", "lfi", "ssrf", "xxe")
    seen_items, unique = set(), []
    for item in findings:
        key = (item.get("type"), item.get("url"), item.get("payload"),
               item.get("evidence"))
        if key in seen_items:
            continue
        seen_items.add(key)
        unique.append(item)
    seen = set()
    for kind in order:
        for item in unique:
            if item.get("type") != kind or id(item) in seen:
                continue
            seen.add(id(item))
            idx += 1
            title = {
                "weak-login": "弱口令登录",
                "user-enum": "登录后用户枚举",
                "cmd-entry": "发现后台命令执行入口",
                "cmdi-direct": "命令执行验证",
                "cmdi-read": "读取 Flag 文件",
                "cmdi-filter-bypass": "白名单/关键字过滤绕过",
                "source-rce": "源码泄露导致的命令执行",
                "deser": "反序列化利用",
                "upload-exec": "上传点脚本直接执行",
                "upload-stored": "上传文件可访问（按源码返回）",
                "upload-include-exec": "上传文件经包含入口执行",
                "upload-read": "只读读取器取得 Flag",
            }.get(kind, kind)
            lines += ["### 3.%d %s" % (idx, title), "",
                      "- 目标：`%s`" % (item.get("url") or "-"),
                      "- 载荷/参数：`%s`" % _clean(item.get("payload"), 200),
                      "- 证据：%s" % _clean(item.get("evidence"), 500),
                      "- 置信度：%s" % (item.get("confidence") or "-"),
                      "- 时间：%s" % (item.get("ts") or "-"), ""]
    support = ("cookie-weak", "csrf-poc")
    for item in unique:
        if id(item) in seen:
            continue
        if item.get("type") in support:
            continue
        idx += 1
        lines += ["### 3.%d %s" % (idx, item.get("type") or "验证项"), "",
                  "- 目标：`%s`" % (item.get("url") or "-"),
                  "- 载荷/参数：`%s`" % _clean(item.get("payload"), 200),
                  "- 证据：%s" % _clean(item.get("evidence"), 500),
                  "- 置信度：%s" % (item.get("confidence") or "-"), ""]
    extras = [item for item in unique if item.get("type") in support]
    if extras:
        lines += ["补充观察（不构成利用链，明细见附录）：", ""]
        for item in extras[:6]:
            lines.append("- %s：`%s` %s" % (
                item.get("type"), item.get("payload") or "-",
                _clean(item.get("evidence"), 200)))
        lines.append("")
    if not unique:
        lines += ["- 未确认可利用点；已执行的探测阶段见附录。", ""]
    elif not idx and extras:
        lines += ["- 未确认完整利用链；以上为本次运行的补充观察。", ""]
    return lines


def build_web_wp(result, meta=None, workdir=""):
    meta = dict(meta or {})
    exploit = result.get("exploit") or {}
    findings = exploit.get("findings") or []
    types = _finding_types(findings)
    name = (meta.get("name") or result.get("title") or
            result.get("target") or "Web 题目").strip()
    category = (meta.get("category") or "WEB").strip()
    cid = str(meta.get("id") or "").strip()
    platform = (meta.get("platform") or "CTF").strip()
    target = result.get("target") or exploit.get("target") or ""
    flags = _flag_lines(result)
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# %s（%s）Writeup" % (name, category), "",
        "> 格式：%s ｜ 平台：%s ｜ 题目 ID：%s ｜ 生成时间：%s" % (
            WP_VERSION, platform, cid or "-", now),
        "> 目标：`%s` ｜ 工具：魔盒-ctf v%s（声明闸门 + scope 双校验 + 审计）"
        % (target, APP_VERSION),
        "> 说明：以下步骤与证据均来自本次工具运行，未命中的阶段会明确标注。", "",
        "## 一、题目信息", "",
        "- 题目：%s" % name,
        "- 分类：%s" % category,
        "- 平台：%s" % platform,
        "- 题目 ID：%s" % (cid or "-"),
        "- 实例地址：`%s`" % target,
        "- 描述/提示：%s" % _clean(meta.get("description") or "-", 500), "",
        "## 二、信息收集", "",
        "- 页面标题：%s" % _clean(exploit.get("title") or result.get("title") or "-", 200),
        "- 技术栈：%s" % (", ".join(exploit.get("tech") or []) or "-"),
        "- 服务器：%s" % _clean(exploit.get("server") or "-", 200),
        "- 表单数：%s ｜ 参数目标：%s ｜ 已发现入口：%s" % (
            exploit.get("forms", "-"), exploit.get("targets", "-"),
            len(exploit.get("endpoints") or [])),
    ]
    endpoints = exploit.get("endpoints") or []
    if endpoints:
        lines += ["", "同源入口补全命中：", ""]
        lines += ["- `%s`" % url for url in endpoints[:20]]
    usernames = exploit.get("usernames") or []
    login_related = bool(exploit.get("credentials")) or bool(
        types & {"weak-login", "user-enum"})
    if usernames and login_related:
        lines += ["", "- 账号候选（由提示/URL 还原）：`%s`" % "`, `".join(usernames[:12])]
    fields = exploit.get("profile_fields") or {}
    if fields:
        lines += ["", "资料页字段：", "", "| 字段 | 值 |", "|---|---|"]
        for key, value in list(fields.items())[:12]:
            lines += ["| %s | %s |" % (_clean(key, 40), _clean(value, 120))]
    creds = exploit.get("credentials") or []
    if creds:
        lines += ["", "已确认凭据：", ""]
        for cred in creds[:6]:
            extra = cred.get("extra") or {}
            extra_text = "，".join("%s=%s" % (k, v) for k, v in extra.items() if v)
            lines.append("- `%s` → `%s / %s%s`" % (
                cred.get("form") or "-", cred.get("user"), cred.get("pass"),
                (" / " + extra_text) if extra_text else ""))
    lines += triage_lines(exploit.get("triage") or {}, level=3)
    lines += ["", "## 三、解题过程", ""] + _narrative(findings)
    lines += ["## 四、Flag", ""]
    if flags:
        lines += ["```", *flags, "```", ""]
    else:
        lines += ["未取得高置信 Flag；以下候选需人工复核：", ""]
        for cand in (result.get("candidates") or [])[:10]:
            lines.append("- `%s`（置信度 %.2f，%s）" % (
                cand.get("value"), float(cand.get("confidence") or 0),
                cand.get("reason") or "-"))
        if not (result.get("candidates") or []):
            lines.append("- 无")
        lines.append("")
    lines += ["## 五、修复建议", ""] + ["- " + text for text in _remediation(types)]
    lines += ["", "## 六、附录：证据与审计", "",
              "| 类型 | 目标 | 载荷摘要 | 证据 | 置信 |", "|---|---|---|---|---|"]
    if findings:
        for item in findings[:40]:
            lines.append("| %s | `%s` | `%s` | %s | %s |" % (
                item.get("type"), item.get("url"),
                _clean(item.get("payload"), 100),
                _clean(item.get("evidence"), 240),
                item.get("confidence") or "-"))
    else:
        lines.append("| - | - | - | 未确认 | - |")
    audit = exploit.get("audit") or {}
    lines += ["", "- 请求数：%s / %s" % (exploit.get("requests", "-"),
                                        exploit.get("budget", "-")),
              "- 审计条数：%s" % (audit.get("entries", "-")),
              "- 任务工作区：`%s`" % (workdir or result.get("workdir") or "-"),
              "- 说明：工具未生成免杀/持久化载荷；webshell/验证样本仅写入任务 artifacts。", ""]
    data = {
        "format": WP_VERSION,
        "generated_at": now,
        "name": name, "category": category, "id": cid,
        "platform": platform, "target": target,
        "flags": flags, "findings": len(findings),
        "requests": exploit.get("requests"),
        "triage": exploit.get("triage") or {},
    }
    return "\n".join(lines), data


def _write_wp(md, data, meta, ws, kind, success=False):
    task_path = os.path.join(ws.dir, "wp.md")
    with open(task_path, "w", encoding="utf-8") as fp:
        fp.write(md)
    out_dir = os.path.join(WORKSPACE, "wp")
    os.makedirs(out_dir, exist_ok=True)
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(meta.get("id") or data.get("name") or kind))
    copy_path = os.path.join(out_dir, "%s_%s.md" % (
        slug[:40], time.strftime("%Y%m%d_%H%M%S")))
    try:
        with open(copy_path, "w", encoding="utf-8") as fp:
            fp.write(md)
    except Exception:
        copy_path = ""
    # v4.0: 成功解出时，在软件根目录（exe 同级）也落一份 WP，方便用户直接找到
    root_copy = ""
    if success:
        try:
            from ..common import APP_DIR
            cat = str(data.get("category") or kind)
            root_name = "WP_%s_%s_%s.md" % (
                cat, slug[:24] or "task", time.strftime("%Y%m%d_%H%M%S"))
            root_path = os.path.join(APP_DIR, root_name)
            with open(root_path, "w", encoding="utf-8") as fp:
                fp.write(md)
            root_copy = root_path
        except Exception:
            root_copy = ""
    return task_path, copy_path, data, root_copy


def write_web_wp(result, meta, ws):
    """写入任务工作区 wp.md，并复制到 workspace/wp/；成功时额外在软件根目录落一份。"""
    md, data = build_web_wp(result, meta=meta, workdir=ws.dir)
    return _write_wp(md, data, meta, ws, "web", success=bool(result.get("success")))


def _evidence_rows(evidence):
    rows = []
    for item in evidence or []:
        res = item.get("result")
        if not isinstance(res, dict):
            res = {}
        rows.append({
            "step": item.get("step"),
            "ts": item.get("ts") or "",
            "tool": item.get("tool") or res.get("tool") or "-",
            "action": item.get("action") or "",
            "ok": res.get("ok"),
            "summary": res.get("summary") or "",
            "notes": [str(n) for n in (res.get("notes") or [])],
            "data": res.get("data") if isinstance(res.get("data"), dict) else {},
        })
    return rows


def _brief_data(data, limit=260):
    if not data:
        return ""
    keys = ("p_bits", "points", "elapsed", "entries", "encrypted", "format",
            "size", "entropy", "blocks", "high_entropy", "depth", "candidates")
    picked = {k: data[k] for k in keys if k in data and not isinstance(data[k], (list, dict))}
    if not picked:
        return ""
    return _clean(", ".join("%s=%s" % (k, v) for k, v in picked.items()), limit)


def build_file_wp(result, meta=None, workdir="", evidence=None):
    meta = dict(meta or {})
    rows = _evidence_rows(evidence)
    identify = result.get("identify") or {}
    hashes = {}
    for row in rows:
        if row["tool"] == "recon.fingerprint" and row["data"].get("hashes"):
            hashes = row["data"]["hashes"]
            break
    name = (meta.get("name") or os.path.basename(str(result.get("target") or "")) or
            "文件题目").strip()
    category = str(meta.get("category") or result.get("category") or "文件分析").strip()
    cid = str(meta.get("id") or "").strip()
    platform = (meta.get("platform") or "CTF").strip()
    target = result.get("target") or ""
    flags = _flag_lines(result)
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# %s（%s）Writeup" % (name, category), "",
        "> 格式：%s ｜ 平台：%s ｜ 题目 ID：%s ｜ 生成时间：%s" % (
            WP_VERSION, platform, cid or "-", now),
        "> 目标文件：`%s` ｜ 工具：魔盒-ctf v%s" % (target, APP_VERSION),
        "> 说明：以下步骤与证据均来自本次工具运行，未命中的阶段会明确标注。", "",
        "## 一、题目信息", "",
        "- 题目：%s" % name,
        "- 分类：%s" % category,
        "- 平台：%s" % platform,
        "- 题目 ID：%s" % (cid or "-"),
        "- 附件：`%s`" % target,
        "- 描述/提示：%s" % _clean(meta.get("description") or
                                   "；".join(str(h) for h in (meta.get("hints") or [])) or "-", 500),
        "",
        "## 二、信息收集", "",
        "- 文件类型：%s" % (identify.get("ftype") or result.get("file_type") or "-"),
        "- 大小：%s 字节 ｜ 熵：%s" % (
            identify.get("size", "-"),
            ("%.3f" % identify["entropy"]) if isinstance(identify.get("entropy"), (int, float)) else "-"),
        "- MD5：`%s`" % (hashes.get("md5") or "-"),
        "- SHA256：`%s`" % (hashes.get("sha256") or "-"),
    ]
    for row in rows:
        if row["tool"] in ("recon.strings", "recon.entropy", "archive.extract"):
            lines.append("- %s：%s" % (row["action"] or row["tool"], _clean(row["summary"], 240)))
    lines += triage_lines(result.get("triage") or {}, level=3)
    lines += ["", "## 三、解题过程", ""]
    idx = 0
    for row in rows:
        if row["tool"] in ("orchestrator", "triage"):
            continue
        idx += 1
        status = "未命中/跳过" if row["ok"] is False else "已执行"
        lines += ["### 3.%d %s" % (idx, row["action"] or row["tool"]), "",
                  "- 工具：`%s` ｜ 状态：%s ｜ 时间：%s" % (
                      row["tool"], status, row["ts"] or "-"),
                  "- 结果：%s" % _clean(row["summary"] or "-", 500)]
        brief = _brief_data(row["data"])
        if brief:
            lines.append("- 关键数据：%s" % brief)
        for note in row["notes"][:4]:
            lines.append("- 备注：%s" % _clean(note, 300))
        lines.append("")
    if not idx:
        lines += ["- 本次运行未产生可记录的步骤。", ""]
    lines += ["## 四、Flag", ""]
    if flags:
        lines += ["```", *flags, "```", ""]
    else:
        lines += ["未取得高置信 Flag；以下候选需人工复核：", ""]
        candidates = result.get("candidates") or []
        for cand in candidates[:10]:
            lines.append("- `%s`（置信度 %.2f，%s）" % (
                cand.get("value"), float(cand.get("confidence") or 0),
                cand.get("reason") or "-"))
        if not candidates:
            lines.append("- 无")
        lines.append("")
    lines += ["## 五、修复建议", "",
              "- 本题为离线附件分析，不涉及服务端修复面；以下为通用收敛建议：",
              "- 不可信附件只在隔离目录做静态分析，不执行样本，产物仅留任务 artifacts。",
              "- 若附件来自真实业务，按数据最小化原则排查泄露面，并轮换暴露的密钥/凭据。",
              "- 本 WP 由自动化工具生成，仅限 CTF 靶场与自有授权资产。", "",
              "## 六、附录：证据与审计", "",
              "| 步骤 | 工具 | 动作 | 状态 | 摘要 |", "|---|---|---|---|---|"]
    for row in rows:
        lines.append("| %s | `%s` | %s | %s | %s |" % (
            row["step"], row["tool"], _clean(row["action"], 60),
            "未命中" if row["ok"] is False else "已执行",
            _clean(row["summary"], 200)))
    lines += ["",
              "- 工具步骤数：%d" % len(rows),
              "- 证据链：`%s`" % (result.get("evidence_path") or "-"),
              "- 运行日志：`%s`" % (result.get("log_path") or "-"),
              "- 任务工作区：`%s`" % (workdir or result.get("workdir") or "-"),
              "- 说明：全程离线静态分析，未执行附件代码；网络类步骤默认限速并留审计。", ""]
    data = {
        "format": WP_VERSION,
        "generated_at": now,
        "name": name, "category": category, "id": cid,
        "platform": platform, "target": target,
        "flags": flags, "steps": len(rows),
        "triage": result.get("triage") or {},
    }
    return "\n".join(lines), data


def write_file_wp(result, meta, ws, evidence=None):
    md, data = build_file_wp(result, meta=meta, workdir=ws.dir, evidence=evidence)
    return _write_wp(md, data, meta, ws, "file", success=bool(result.get("success")))
