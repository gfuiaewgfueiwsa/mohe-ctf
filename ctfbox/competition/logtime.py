# -*- coding: utf-8 -*-
"""日志与系统分析：Windows 事件日志 / Linux auth.log/syslog 关键事件与时间线。

Windows 支持 .evtx 离线解析（python-evtx）与本机在线只读收集；
Linux 支持 auth.log/secure/syslog/messages 及 .gz 轮转日志。
全程只读，输出 timeline.csv / events.json。
"""
import csv
import gzip
import os
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from . import util

EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

EVENT_LABELS = {
    "4624": "登录成功", "4625": "登录失败", "4634": "注销", "4647": "用户注销",
    "4648": "显式凭据登录", "4672": "授予特殊权限", "4688": "进程创建",
    "4689": "进程退出", "4720": "创建用户", "4722": "启用账户", "4723": "修改密码",
    "4724": "重置密码", "4725": "禁用账户", "4726": "删除用户",
    "4728": "加入全局安全组", "4732": "加入本地安全组", "4756": "加入通用安全组",
    "4738": "账户属性变更", "4740": "账户锁定", "4767": "账户解锁",
    "4776": "凭据验证", "1102": "安全日志被清空", "104": "日志被清空",
    "4697": "服务安装", "7045": "服务安装", "4698": "计划任务创建",
    "4699": "计划任务删除", "4700": "计划任务启用", "4702": "计划任务修改",
    "4719": "审核策略变更", "4104": "PowerShell 脚本块", "4103": "PowerShell 模块日志",
    "1": "Sysmon 进程创建", "3": "Sysmon 网络连接", "11": "Sysmon 文件创建",
    "13": "Sysmon 注册表写入", "22": "Sysmon DNS 查询",
}

KEY_IDS = set(EVENT_LABELS)

SUSPICIOUS_CMD = re.compile(
    r"(mimikatz|sekurlsa|procdump.{0,30}lsass|comsvcs.{0,30}minidump|"
    r"powershell.{0,60}(-enc|encodedcommand|downloadstring|iex\b)|"
    r"certutil.{0,50}urlcache|bitsadmin.{0,40}transfer|"
    r"whoami\s+/priv|net\s+localgroup\s+administrators|"
    r"vssadmin.{0,30}delete.{0,20}shadows|wmic.{0,30}shadowcopy|"
    r"schtasks.{0,30}/create|reg(\.exe)?\s+add.{0,60}\\run\b|"
    r"net(\.exe)?\s+user\s+\S+\s+\S+\s+/add|"
    r"(?:bash|sh)\s+-i|nc(?:\.exe)?\s+.*-e|/dev/tcp/|curl\s+.*\|\s*(?:bash|sh)|"
    r"wget\s+.*-O\s*-\s*\|\s*(?:bash|sh))",
    re.I)


def _xml_event(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return None
    sys_node = root.find(EVENT_NS + "System")
    if sys_node is None:
        return None
    eid_node = sys_node.find(EVENT_NS + "EventID")
    eid = (eid_node.text or "").strip() if eid_node is not None else ""
    time_node = sys_node.find(EVENT_NS + "TimeCreated")
    ts = time_node.get("SystemTime", "") if time_node is not None else ""
    provider = sys_node.find(EVENT_NS + "Provider")
    computer = sys_node.find(EVENT_NS + "Computer")
    channel = sys_node.find(EVENT_NS + "Channel")
    level = sys_node.find(EVENT_NS + "Level")
    data = {}
    for node in root.iter(EVENT_NS + "Data"):
        key = node.get("Name") or "param"
        data[key] = node.text or ""
    userdata = root.find(EVENT_NS + "UserData")
    if userdata is not None:
        for node in userdata.iter():
            if node is not userdata and node.text and node.text.strip():
                data[node.tag.rsplit("}", 1)[-1]] = node.text.strip()
    message = ""
    rendering = root.find(EVENT_NS + "RenderingInfo")
    if rendering is not None:
        msg = rendering.find(EVENT_NS + "Message")
        if msg is not None:
            message = (msg.text or "").strip()
    return {
        "event_id": eid,
        "time": ts,
        "provider": provider.get("Name", "") if provider is not None else "",
        "computer": (computer.text or "") if computer is not None else "",
        "channel": (channel.text or "") if channel is not None else "",
        "level": (level.text or "") if level is not None else "",
        "data": data,
        "message": message,
    }


def _event_user(event):
    data = event.get("data") or {}
    for key in ("TargetUserName", "SubjectUserName", "User", "AccountName",
                "UserName", "param1"):
        value = data.get(key)
        if value and value not in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            return value
    return ""


def _event_ip(event):
    data = event.get("data") or {}
    for key in ("IpAddress", "SourceIp", "SourceNetworkAddress", "Address"):
        value = data.get(key)
        if value and value not in ("-", "127.0.0.1", "::1"):
            return value
    return ""


def _event_detail(event):
    data = event.get("data") or {}
    for key in ("CommandLine", "ProcessCommandLine", "Image", "NewProcessName",
                "ServiceFileName", "TaskContent", "TargetObject", "ObjectName"):
        value = data.get(key)
        if value:
            return "%s=%s" % (key, util.short(value, 400))
    if event.get("message"):
        return util.short(event["message"], 500)
    return util.short("; ".join("%s=%s" % (k, v) for k, v in list(data.items())[:6]), 500)


def _simplify_windows(event, source):
    eid = str(event.get("event_id") or "")
    if eid not in KEY_IDS:
        return None
    data = event.get("data") or {}
    user = _event_user(event)
    ip = _event_ip(event)
    detail = _event_detail(event)
    ts = event.get("time") or ""
    logon_type = data.get("LogonType", "")
    if eid in ("4624", "4625") and logon_type:
        detail = "LogonType=%s %s" % (logon_type, detail)
    return {
        "time": ts, "event_id": eid, "action": EVENT_LABELS.get(eid, eid),
        "source": source, "channel": event.get("channel", ""),
        "host": event.get("computer", ""), "user": user, "ip": ip,
        "detail": detail, "raw": util.short(event.get("message") or detail, 600),
    }


def _find_bursts(failures, window_min=10, threshold=5):
    """按 (user,ip) 做滑动窗口，返回失败次数达到阈值的区间。"""
    groups = defaultdict(list)
    for item in failures:
        groups[(item.get("user", ""), item.get("ip", ""))].append(item)
    bursts = []
    for key, items in groups.items():
        times = []
        for item in items:
            dt = _parse_iso(item["time"])
            if dt:
                times.append((dt, item))
        times.sort(key=lambda x: x[0])
        start = 0
        for end in range(len(times)):
            while times[end][0] - times[start][0] > timedelta(minutes=window_min):
                start += 1
            if end - start + 1 >= threshold:
                bursts.append({"user": key[0], "ip": key[1],
                               "count": end - start + 1,
                               "start": times[start][0], "end": times[end][0]})
                break
    return bursts


def _parse_iso(value):
    if not value:
        return None
    value = str(value).strip()
    text = value.replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.fromisoformat(text) if fmt is None else datetime.strptime(text, fmt)
            if dt.tzinfo is not None:
                dt = dt.astimezone().replace(tzinfo=None)
            return dt
        except Exception:
            continue
    return None


def _success_after_failures(events, failures):
    """登录成功后 30 分钟内同用户/IP 有 >=3 次失败，标记疑似爆破成功。"""
    accepted = [e for e in events if e["event_id"] == "4624"]
    out = []
    for ok in accepted:
        dt = _parse_iso(ok["time"])
        if not dt:
            continue
        user, ip = ok.get("user", ""), ok.get("ip", "")
        count = 0
        for fail in failures:
            if fail.get("user", "") != user:
                continue
            if ip and fail.get("ip", "") != ip:
                continue
            fdt = _parse_iso(fail["time"])
            if fdt and timedelta(0) <= dt - fdt <= timedelta(minutes=30):
                count += 1
        if count >= 3:
            out.append({"user": user, "ip": ip, "time": ok["time"],
                        "failures": count})
    return out


def _analyze_events_windows(events, result):
    failures = [e for e in events if e["event_id"] == "4625"]
    counts = Counter(e["event_id"] for e in events)
    if counts:
        util.add(result, "info", "Windows 关键事件统计",
                 ", ".join("%s(%s)=%s" % (k, EVENT_LABELS.get(k, ""), v)
                           for k, v in counts.most_common(20)))
    if failures:
        util.add(result, "info", "登录失败 %d 次" % len(failures),
                 "\n".join("%s %s from %s" % (e["time"], e["user"], e["ip"])
                           for e in failures[:30]))
        bursts = _find_bursts(failures)
        if bursts:
            util.add(result, "warn", "疑似暴力破解（10 分钟内 >=5 次失败）",
                     "\n".join("%s from %s：%d 次，%s ~ %s" % (
                         b["user"], b["ip"], b["count"], b["start"], b["end"])
                         for b in bursts[:20]), {"bursts": [
                             {k: str(v) for k, v in b.items()} for b in bursts]})
        success = _success_after_failures(events, failures)
        if success:
            util.add(result, "warn", "失败后登录成功（疑似爆破成功）",
                     "\n".join("%s %s from %s，前 30 分钟失败 %s 次" % (
                         s["time"], s["user"], s["ip"], s["failures"])
                         for s in success[:20]))
    cleared = [e for e in events if e["event_id"] in ("1102", "104")]
    if cleared:
        util.add(result, "warn", "日志被清空（反取证）",
                 "\n".join("%s %s %s" % (e["time"], e["source"], e["detail"])
                           for e in cleared[:10]))
    new_users = [e for e in events if e["event_id"] in ("4720", "4726", "4722", "4725")]
    if new_users:
        util.add(result, "warn", "账户创建/删除/启停",
                 "\n".join("%s %s %s" % (e["time"], e["action"], e["detail"])
                           for e in new_users[:20]))
    group_add = [e for e in events if e["event_id"] in ("4728", "4732", "4756")]
    if group_add:
        util.add(result, "warn", "账户加入安全组",
                 "\n".join("%s %s" % (e["time"], e["detail"]) for e in group_add[:20]))
    services = [e for e in events if e["event_id"] in ("7045", "4697", "4698")]
    if services:
        util.add(result, "warn", "服务/计划任务安装", "\n".join(
            "%s %s %s" % (e["time"], e["action"], e["detail"])
            for e in services[:20]))
    lockouts = [e for e in events if e["event_id"] == "4740"]
    if lockouts:
        util.add(result, "warn", "账户锁定事件 %d 次" % len(lockouts),
                 "\n".join("%s %s %s" % (e["time"], e["user"], e["ip"])
                           for e in lockouts[:20]))
    procs = [e for e in events if e["event_id"] in ("4688", "1") and
             SUSPICIOUS_CMD.search(e.get("detail", ""))]
    if procs:
        util.add(result, "warn", "可疑进程命令行 %d 条" % len(procs),
                 "\n".join("%s %s" % (e["time"], e["detail"])
                           for e in procs[:20]))
    rdp = [e for e in events if e["event_id"] == "4624" and
           "LogonType=10" in e.get("detail", "")]
    if rdp:
        util.add(result, "info", "RDP 登录 %d 次" % len(rdp),
                 "\n".join("%s %s from %s" % (e["time"], e["user"], e["ip"])
                           for e in rdp[:20]))
    explicit = [e for e in events if e["event_id"] == "4648"]
    if explicit:
        util.add(result, "info", "显式凭据登录 %d 次" % len(explicit),
                 "\n".join("%s %s" % (e["time"], e["detail"])
                           for e in explicit[:20]))


def _evtx_files(target):
    if os.path.isfile(target):
        return [target] if target.lower().endswith(".evtx") else []
    out = []
    for path in util.iter_artifacts(target, exts=(".evtx",), max_files=200):
        out.append(path)
    return out


def parse_evtx(path, result, max_events=200000):
    try:
        from Evtx.Evtx import Evtx
    except Exception:
        result["notes"].append(
            "缺少 python-evtx：pip install python-evtx（约 200 KB）；"
            "也可在 Windows 上使用在线事件收集。")
        return []
    events = []
    try:
        with Evtx(path) as log:
            for idx, rec in enumerate(log.records()):
                if idx >= max_events:
                    result["notes"].append("%s 超过 %s 条，已截断" % (
                        os.path.basename(path), max_events))
                    break
                try:
                    event = _xml_event(rec.xml())
                except Exception:
                    continue
                if not event:
                    continue
                simple = _simplify_windows(event, os.path.basename(path))
                if simple:
                    events.append(simple)
    except Exception as exc:
        result["notes"].append("EVTX 解析失败 %s：%s" % (path, exc))
    return events


WIN_LIVE_SCRIPT = r'''
$ErrorActionPreference = "Continue"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$out = @()
foreach ($name in @("Security","System")) {
  try {
    $out += Get-WinEvent -LogName $name -MaxEvents 2000 -ErrorAction Stop |
      ForEach-Object { [pscustomobject]@{
        TimeCreated = $_.TimeCreated.ToString("o"); Id = $_.Id;
        Provider = $_.ProviderName; LogName = $_.LogName;
        Level = $_.LevelDisplayName; Message = $_.Message; Xml = $_.ToXml() } }
  } catch { }
}
$out | ConvertTo-Json -Depth 4 -Compress
'''


def collect_live_windows(outdir, result, timeout=180):
    ps = util.which("powershell") or util.which("pwsh")
    if not ps:
        result["notes"].append("未找到 powershell，无法在线收集 Windows 事件日志")
        return []
    script = util.save_text(outdir, "collect_events.ps1", WIN_LIVE_SCRIPT)
    run = util.run_cmd([ps, "-NoProfile", "-ExecutionPolicy", "Bypass",
                        "-File", script], timeout=timeout)
    result["data"]["collector"] = {"rc": run["rc"], "elapsed": run["elapsed"],
                                   "stderr": util.short(run["stderr"], 500)}
    import json
    text = (run["stdout"] or "").strip().lstrip("\ufeff")
    rows = []
    try:
        rows = json.loads(text) if text.startswith("[") else []
    except Exception:
        rows = []
    events = []
    for row in rows if isinstance(rows, list) else [rows]:
        xml = row.get("Xml") or ""
        event = _xml_event(xml) if xml else None
        if event:
            event["time"] = row.get("TimeCreated") or event["time"]
            event["channel"] = row.get("LogName") or event["channel"]
            event["message"] = row.get("Message") or event["message"]
        else:
            event = {"event_id": str(row.get("Id") or ""),
                     "time": row.get("TimeCreated") or "",
                     "provider": row.get("Provider") or "",
                     "computer": "", "channel": row.get("LogName") or "",
                     "level": row.get("Level") or "", "data": {},
                     "message": row.get("Message") or ""}
        simple = _simplify_windows(event, event.get("channel") or "live")
        if simple:
            events.append(simple)
    return events


# ----------------------------------------------------------------------------
# Linux 日志
# ----------------------------------------------------------------------------
SYSLOG_TIME = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")
ISO_TIME = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
PROC_RE = re.compile(r"^\S+\s+([\w.\-]+)\s+([\w.\-/]+)(?:\[(\d+)\])?:\s*(.*)$")
SSH_FAIL = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam) for "
    r"(?:invalid user )?(\S+) from ([\w.:\-]+) port (\d+)", re.I)
SSH_OK = re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for "
                    r"(\S+) from ([\w.:\-]+) port (\d+)", re.I)
SSH_INVALID = re.compile(r"Invalid user (\S+) from ([\w.:\-]+)", re.I)
SSH_SESSION = re.compile(r"session opened for user (\S+)", re.I)
SUDO_RE = re.compile(r"sudo:\s+(\S+)\s*:.*?(?:USER=(\S+))?.*?COMMAND=(.*)$", re.I)
SU_RE = re.compile(r"su(?:\[|\b).*session opened for user (\S+)", re.I)
NEW_USER = re.compile(r"(?:new user|useradd).*?(?:name=)?(\S+)", re.I)
PASSWD_CHANGE = re.compile(r"password changed for (\S+)", re.I)
CRON_RE = re.compile(r"CRON.*CMD \((.*)\)", re.I)
UFW_BLOCK = re.compile(r"UFW BLOCK.*?SRC=([\d.:a-fA-F]+).*?DPT=(\d+)", re.I)
IPT_BLOCK = re.compile(r"iptables.*?SRC=([\d.:a-fA-F]+).*?DPT=(\d+)", re.I)


def _line_time(match, mtime_year=None):
    try:
        if match.re is ISO_TIME:
            dt = _parse_iso(match.group(1).replace(" ", "T", 1))
            return dt
        month, day, clock = match.groups()
        year = mtime_year or datetime.now().year
        dt = datetime.strptime("%s %s %s %s" % (year, month, day, clock),
                               "%Y %b %d %H:%M:%S")
        # 跨年日志：解析结果明显在未来则回退一年
        if dt > datetime.now() + timedelta(days=2):
            dt = dt.replace(year=year - 1)
        return dt
    except Exception:
        return None


def _classify_linux(line, host, proc, user, ip, detail, event):
    low = line.lower()
    if SSH_FAIL.search(line):
        m = SSH_FAIL.search(line)
        event.update({"action": "SSH 登录失败", "user": m.group(1),
                      "ip": m.group(2), "detail": m.group(0)})
        return "ssh-fail"
    if SSH_OK.search(line):
        m = SSH_OK.search(line)
        event.update({"action": "SSH 登录成功", "user": m.group(1),
                      "ip": m.group(2), "detail": m.group(0)})
        return "ssh-ok"
    if SSH_INVALID.search(line):
        m = SSH_INVALID.search(line)
        event.update({"action": "SSH 无效用户", "user": m.group(1),
                      "ip": m.group(2), "detail": m.group(0)})
        return "ssh-invalid"
    if "session opened for user" in low:
        m = SSH_SESSION.search(line)
        event.update({"action": "会话打开", "user": m.group(1) if m else user,
                      "detail": util.short(detail, 300)})
        return "session"
    if proc.startswith("sudo") or "sudo:" in low:
        m = SUDO_RE.search(line)
        event.update({"action": "sudo 命令",
                      "user": m.group(1) if m else user,
                      "detail": util.short(m.group(3) if m else detail, 500)})
        if m and SUSPICIOUS_CMD.search(m.group(3)):
            event["suspicious"] = True
        return "sudo"
    if proc.startswith("su") or "su: pam" in low:
        m = SU_RE.search(line)
        event.update({"action": "su 切换用户",
                      "user": m.group(1) if m else user,
                      "detail": util.short(detail, 300)})
        return "su"
    if NEW_USER.search(line) and any(x in low for x in ("useradd", "new user", "new group")):
        m = NEW_USER.search(line)
        event.update({"action": "用户/组创建", "detail": util.short(line, 400)})
        return "account"
    if PASSWD_CHANGE.search(line) or "password changed" in low:
        m = PASSWD_CHANGE.search(line)
        event.update({"action": "口令变更", "user": m.group(1) if m else user,
                      "detail": util.short(line, 400)})
        return "passwd"
    if "logrotate" in low or "truncated" in low or "removed" in low and "log" in low:
        event.update({"action": "日志轮转/截断", "detail": util.short(line, 400)})
        return "log-rotate"
    if CRON_RE.search(line):
        m = CRON_RE.search(line)
        event.update({"action": "计划任务", "detail": util.short(m.group(1), 400)})
        return "cron"
    if UFW_BLOCK.search(line) or IPT_BLOCK.search(line):
        m = UFW_BLOCK.search(line) or IPT_BLOCK.search(line)
        event.update({"action": "防火墙拦截", "ip": m.group(1),
                      "detail": "DPT=%s" % m.group(2)})
        return "firewall"
    if "authentication failure" in low or "failed password" in low:
        event.update({"action": "认证失败", "detail": util.short(detail, 300)})
        return "auth-fail"
    return ""


def _read_log(path):
    if path.lower().endswith(".gz"):
        try:
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fp:
                return fp.read(20 * 1024 * 1024)
        except Exception:
            return ""
    return util.read_text(path, 20 * 1024 * 1024)


def parse_linux_log(path, result, events, max_lines=200000):
    text = _read_log(path)
    if not text:
        return 0
    source = os.path.basename(path)
    try:
        year = datetime.fromtimestamp(os.path.getmtime(path)).year
    except Exception:
        year = datetime.now().year
    count = 0
    for line in text.splitlines()[:max_lines]:
        match = ISO_TIME.match(line) or SYSLOG_TIME.match(line)
        if not match:
            continue
        dt = _line_time(match, year)
        if not dt:
            continue
        rest = line[match.end():].strip()
        pm = PROC_RE.match(rest)
        host = pm.group(1) if pm else ""
        proc = pm.group(2) if pm else ""
        detail = pm.group(4) if pm else rest
        user = ""
        ip = ""
        um = re.search(r"user[ =](\w[\w.\-]*)", detail, re.I)
        if um:
            user = um.group(1)
        im = re.search(r"from ([\d.:a-fA-F]+)", detail)
        if im:
            ip = im.group(1)
        event = {"time": dt.strftime("%Y-%m-%d %H:%M:%S"),
                 "event_id": "", "action": "", "source": source,
                 "channel": "linux", "host": host, "user": user, "ip": ip,
                 "detail": util.short(detail, 500), "raw": util.short(line, 600),
                 "proc": proc}
        kind = _classify_linux(line, host, proc, user, ip, detail, event)
        if not kind:
            continue
        event["kind"] = kind
        event["event_id"] = kind
        events.append(event)
        count += 1
        if len(events) >= 300000:
            result["notes"].append("事件数超过 300000，已截断")
            break
    return count


def _analyze_linux(events, result):
    counts = Counter(e.get("kind", "") for e in events)
    if counts:
        util.add(result, "info", "Linux 关键事件统计",
                 ", ".join("%s=%s" % (k, v) for k, v in counts.most_common(20)))
    fails = [e for e in events if e.get("kind") == "ssh-fail"]
    if fails:
        util.add(result, "info", "SSH 失败 %d 次" % len(fails),
                 "\n".join("%s %s from %s" % (e["time"], e["user"], e["ip"])
                           for e in fails[:30]))
        bursts = _find_bursts(fails)
        if bursts:
            util.add(result, "warn", "疑似 SSH 暴力破解（10 分钟 >=5 次）",
                     "\n".join("%s from %s：%d 次，%s ~ %s" % (
                         b["user"], b["ip"], b["count"], b["start"], b["end"])
                         for b in bursts[:20]))
        oks = [e for e in events if e.get("kind") == "ssh-ok"]
        success = []
        for ok in oks:
            dt = _parse_iso(ok["time"])
            n = 0
            for fail in fails:
                if fail.get("user") != ok.get("user"):
                    continue
                if ok.get("ip") and fail.get("ip") != ok.get("ip"):
                    continue
                fdt = _parse_iso(fail["time"])
                if fdt and timedelta(0) <= dt - fdt <= timedelta(minutes=30):
                    n += 1
            if n >= 3:
                success.append((ok, n))
        if success:
            util.add(result, "warn", "SSH 失败后登录成功（疑似爆破成功）",
                     "\n".join("%s %s from %s，前 30 分钟失败 %s 次" % (
                         ok["time"], ok["user"], ok["ip"], n)
                         for ok, n in success[:20]))
    invalid = [e for e in events if e.get("kind") == "ssh-invalid"]
    if len(invalid) >= 10:
        users = Counter(e.get("user", "") for e in invalid)
        util.add(result, "warn", "SSH 用户名枚举/爆破痕迹 %d 次" % len(invalid),
                 "高频用户名：" + ", ".join("%s(%s)" % (k, v)
                                             for k, v in users.most_common(15)))
    root_ok = [e for e in events if e.get("kind") == "ssh-ok" and e.get("user") == "root"]
    if root_ok:
        util.add(result, "warn", "root 直接 SSH 登录 %d 次" % len(root_ok),
                 "\n".join("%s from %s" % (e["time"], e["ip"]) for e in root_ok[:20]))
    sudo_bad = [e for e in events if e.get("suspicious")]
    if sudo_bad:
        util.add(result, "warn", "可疑 sudo 命令 %d 条" % len(sudo_bad),
                 "\n".join("%s %s: %s" % (e["time"], e["user"], e["detail"])
                           for e in sudo_bad[:20]))
    account = [e for e in events if e.get("kind") == "account"]
    if account:
        util.add(result, "warn", "用户/组变更 %d 条" % len(account),
                 "\n".join("%s %s" % (e["time"], e["detail"]) for e in account[:20]))
    passwd = [e for e in events if e.get("kind") == "passwd"]
    if passwd:
        util.add(result, "warn", "口令变更 %d 条" % len(passwd),
                 "\n".join("%s %s" % (e["time"], e["detail"]) for e in passwd[:20]))
    rotate = [e for e in events if e.get("kind") == "log-rotate"]
    if rotate:
        util.add(result, "info", "日志轮转/截断 %d 条" % len(rotate),
                 "\n".join("%s %s" % (e["time"], e["detail"]) for e in rotate[:15]))
    firewall = [e for e in events if e.get("kind") == "firewall"]
    if firewall:
        ips = Counter(e.get("ip", "") for e in firewall)
        util.add(result, "info", "防火墙拦截 %d 条" % len(firewall),
                 "Top 源 IP：" + ", ".join("%s(%s)" % (k, v)
                                          for k, v in ips.most_common(15)))


def _write_timeline(events, outdir, result):
    events = sorted(events, key=lambda x: x.get("time", ""))
    csv_path = os.path.join(outdir, "artifacts", "timeline.csv")
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(["time", "source", "action", "host", "user", "ip",
                         "event_id", "detail"])
        for e in events:
            writer.writerow([e.get("time", ""), e.get("source", ""),
                             e.get("action", ""), e.get("host", ""),
                             e.get("user", ""), e.get("ip", ""),
                             e.get("event_id", ""), e.get("detail", "")])
    util.add_artifact(result, csv_path)
    json_path = util.save_json(outdir, "events.json", events[:100000])
    util.add_artifact(result, json_path)
    return events, csv_path


def _render(result):
    data = result["data"]
    lines = ["# 日志与时间线报告", ""]
    lines.append("- 目标：`%s`" % data.get("target", ""))
    lines.append("- 日志文件：%s，关键事件：%s" % (
        len(data.get("log_files") or []), data.get("events", 0)))
    lines.append("- 时间范围：%s ~ %s" % (
        data.get("first_time", ""), data.get("last_time", "")))
    lines.append("")
    lines.append("## 发现")
    for item in result["findings"]:
        lines.append("- [%s] %s" % (item["level"], item["title"]))
        if item["detail"]:
            for line in item["detail"].splitlines()[:15]:
                lines.append("  - %s" % line)
    events = data.get("timeline") or []
    if events:
        lines.append("")
        lines.append("## 时间线（前 80 条）")
        lines.append("| 时间 | 来源 | 动作 | 用户 | IP | 详情 |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for e in events[:80]:
            lines.append("| %s | %s | %s | %s | %s | %s |" % (
                e.get("time"), e.get("source"), e.get("action"),
                e.get("user"), e.get("ip"),
                util.short(e.get("detail", "").replace("|", "/"), 160)))
    lines.append("")
    lines.append("## 备注")
    for note in result["notes"]:
        lines.append("- %s" % note)
    return "\n".join(lines)


def _default_linux_logs():
    candidates = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog",
                  "/var/log/messages", "/var/log/audit/audit.log"]
    logs = [p for p in candidates if os.path.isfile(p)]
    for base in ("/var/log",):
        if os.path.isdir(base):
            for name in os.listdir(base):
                if name.startswith(("auth.log", "secure", "syslog", "messages")) and \
                        not any(x == name for x in logs):
                    logs.append(os.path.join(base, name))
    return logs


def analyze(target: str = "", outdir: str = "", platform: str = "auto",
            live: bool = False, log=None) -> dict:
    log = log or (lambda m: None)
    outdir = outdir or util.case_dir("logtime", target or "localhost")
    result = util.make_result("logtime", outdir)
    result["data"]["target"] = os.path.abspath(target) if target else "localhost"
    plat = platform
    if plat == "auto":
        plat = "windows" if os.name == "nt" else "linux"
    result["data"]["platform"] = plat
    events = []
    log_files = []
    if target and os.path.isdir(target):
        evtx = _evtx_files(target)
        for path in evtx[:200]:
            log_files.append(path)
            log("[logtime] evtx %s" % os.path.basename(path))
            events.extend(parse_evtx(path, result))
        texts = [p for p in util.iter_artifacts(
            target, exts=(".log", ".txt", ".gz"), max_files=300)
            if any(x in os.path.basename(p).lower() for x in
                   ("auth", "secure", "syslog", "message", "audit"))]
        for path in texts:
            log_files.append(path)
            parse_linux_log(path, result, events)
    elif target and os.path.isfile(target):
        log_files.append(target)
        if target.lower().endswith(".evtx") or _is_evtx(target):
            events.extend(parse_evtx(target, result))
        else:
            parse_linux_log(target, result, events)
    else:
        if plat == "windows":
            log("[logtime] 在线收集 Windows Security/System 事件 ...")
            events.extend(collect_live_windows(outdir, result))
        else:
            for path in _default_linux_logs():
                log_files.append(path)
                parse_linux_log(path, result, events)
    events = sorted(events, key=lambda x: x.get("time", ""))
    if not events:
        result["ok"] = False
        util.add(result, "warn", "未解析到关键日志事件",
                 "检查输入是否为 .evtx / auth.log / syslog；Windows 在线模式需管理员权限。")
    windows_events = any(e.get("channel") != "linux" and e.get("event_id") in KEY_IDS
                         for e in events)
    linux_events = any(e.get("channel") == "linux" or e.get("kind") for e in events)
    if windows_events:
        _analyze_events_windows(events, result)
    if linux_events:
        _analyze_linux(events, result)
    if windows_events or linux_events:
        result["data"]["platform"] = "mixed" if windows_events and linux_events else (
            "windows" if windows_events else "linux")
    events, csv_path = _write_timeline(events, outdir, result)
    result["data"].update({
        "log_files": log_files, "events": len(events),
        "first_time": events[0]["time"] if events else "",
        "last_time": events[-1]["time"] if events else "",
        "by_action": dict(Counter(e.get("action", "") for e in events).most_common()),
        "timeline_path": csv_path,
        "timeline": events[:500],
    })
    source_text = "%s 个" % len(log_files) if log_files else ("在线" if live else "0 个")
    result["summary"] = "日志 %s，关键事件 %s 条，时间 %s ~ %s" % (
        source_text, len(events),
        events[0]["time"] if events else "-", events[-1]["time"] if events else "-")
    result["notes"].append("只读分析；时间按日志原始时区/本地时间排序，跨时区需人工校正。")
    if linux_events:
        result["notes"].append("Linux syslog 无年份，按文件 mtime 年份补全并做跨年回退。")
    if live and plat == "windows":
        result["notes"].append("在线收集只读取当前账户有权限的通道；Security 日志通常需要管理员。")
    return util.finish(result, _render(result))


def _is_evtx(path):
    try:
        with open(path, "rb") as fp:
            return fp.read(8) == b"ElfFile\x00"
    except Exception:
        return False


def enhance(path, report, outdir):
    try:
        result = analyze(path, os.path.join(outdir, "logtime"))
    except Exception as exc:
        report.add("info", "日志时间线跳过", str(exc)[:200])
        return None
    for item in result.get("findings") or []:
        report.add(item["level"], item["title"], item["detail"])
    for out in result.get("artifacts") or []:
        report.extracted.append(out)
    return result
