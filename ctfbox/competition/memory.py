# -*- coding: utf-8 -*-
"""内存取证：Volatility 3 接入。

覆盖进程 / 网络 / 注册表自启动 / 凭据 / 文件提取，并附带镜像原始字符串快速扫描。
全程离线：只读镜像文件，不联网；没有内存镜像样本时如实标注「未做端到端验证」。
"""
import os
import re

from . import util

SUSPICIOUS_PROCESS = {
    "mimikatz.exe", "procdump.exe", "procdump64.exe", "psexec.exe",
    "psexesvc.exe", "cobaltstrike.exe", "beacon.exe", "meterpreter.exe",
    "nc.exe", "ncat.exe", "netcat.exe", "pwdump.exe", "wce.exe",
    "gsecdump.exe", "lazagne.exe", "rundll32.exe",
}

SUSPICIOUS_CMDLINE = re.compile(
    r"(sekurlsa|lsadump|procdump.{0,40}lsass|comsvcs.{0,40}minidump|"
    r"powershell.{0,80}(-enc|encodedcommand|downloadstring|iex\b|invoke-expression)|"
    r"certutil.{0,60}urlcache|bitsadmin.{0,40}transfer|"
    r"schtasks.{0,40}/create|reg(\.exe)?\s+add.{0,80}\\run\b|"
    r"net(\.exe)?\s+user\s+\S+\s+\S+\s+/add|vssadmin.{0,40}delete.{0,20}shadows|"
    r"wmic.{0,40}shadowcopy|whoami\s+/priv|net\s+localgroup\s+administrators)",
    re.I)

AUTORUN_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"System\CurrentControlSet\Services",
]

WINDOWS_PLUGINS = [
    ("pslist", ["windows.pslist"], 180),
    ("pstree", ["windows.pstree"], 180),
    ("cmdline", ["windows.cmdline"], 180),
    ("netscan", ["windows.netscan"], 240),
    ("hivelist", ["windows.registry.hivelist"], 180),
    ("hashdump", ["windows.hashdump"], 240),
    ("cachedump", ["windows.cachedump"], 240),
    ("lsadump", ["windows.lsadump"], 240),
    ("malfind", ["windows.malfind"], 300),
]

LINUX_PLUGINS = [
    ("pslist", ["linux.pslist"], 180),
    ("bash", ["linux.bash"], 240),
    ("sockstat", ["linux.sockstat"], 240),
    ("lsmod", ["linux.lsmod"], 180),
]


def _plugin_command(info, image, plugin, extra=None):
    args = ["-f", image, "-r", "json"] + list(plugin) + list(extra or [])
    return util.vol_command(info, args)


def _rows(raw):
    return util.clean_json_rows(raw)


def _pick(row, *names):
    for name in names:
        for key in row:
            if key.lower() == name.lower():
                return row[key]
    return ""


def _scan_rows(result, tag, rows, raw):
    util.flag_scan(raw, "Volatility/%s" % tag, result)
    for row in rows:
        text = " ".join(str(v) for v in row.values())
        if "flag{" in text.lower():
            util.flag_scan(text, "Volatility/%s 字段" % tag, result)


def quick_strings(image, result, max_scan_mb=1024, log=None):
    """不依赖 Volatility 的镜像明文扫描；跨分块保留 512B 重叠。"""
    size = os.path.getsize(image)
    limit = min(size, max(1, int(max_scan_mb)) * 1024 * 1024)
    flags, urls = [], []
    chunk_size = 4 * 1024 * 1024
    overlap = 512
    last = b""
    read = 0
    with open(image, "rb") as fp:
        while read < limit:
            chunk = fp.read(min(chunk_size, limit - read))
            if not chunk:
                break
            read += len(chunk)
            buf = last + chunk
            for flag in util.flag_scan(buf, "镜像字符串", result):
                if flag not in flags:
                    flags.append(flag)
            for url in re.findall(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,200}",
                                  buf):
                try:
                    text = url.decode("utf-8", "ignore")
                except Exception:
                    continue
                if text not in urls and len(urls) < 500:
                    urls.append(text)
            last = buf[-overlap:]
    data = {"scanned_bytes": read, "file_size": size, "flags": flags,
            "urls": urls}
    path = util.save_json(result["outdir"], "memory_strings.json", data)
    util.add_artifact(result, path)
    result["data"]["strings"] = data
    if flags:
        util.add(result, "flag", "镜像明文字符串命中 flag",
                 "; ".join(flags[:10]), {"flags": flags})
    if urls:
        util.add(result, "info", "镜像中提取到 URL（%d 条）" % len(urls),
                 "\n".join(urls[:20]))
    if log:
        log("[memory] 明文扫描 %.1f MB，flag=%d，URL=%d" % (
            read / 1024.0 / 1024.0, len(flags), len(urls)))


def _analyze_processes(result, rows):
    by_pid = {}
    suspicious = []
    for row in rows:
        pid = str(_pick(row, "PID", "pid"))
        name = str(_pick(row, "ImageFileName", "ImageFileName", "Process", "Name"))
        ppid = str(_pick(row, "PPID", "ppid"))
        by_pid[pid] = {"name": name, "ppid": ppid, "row": row}
        low = name.lower()
        if low in SUSPICIOUS_PROCESS:
            suspicious.append("%s(pid=%s,ppid=%s)" % (name, pid, ppid))
    for pid, item in by_pid.items():
        low = item["name"].lower()
        parent = by_pid.get(item["ppid"], {}).get("name", "").lower()
        if low in ("svchost.exe", "lsass.exe") and parent and \
                parent not in ("services.exe", "wininit.exe", "smss.exe"):
            suspicious.append("%s(pid=%s) 父进程异常=%s" % (
                item["name"], pid, parent or "?"))
    if rows:
        result["data"]["process_count"] = len(rows)
    if suspicious:
        util.add(result, "warn", "可疑进程 %d 个" % len(suspicious),
                 "\n".join(suspicious[:30]), {"items": suspicious})
    elif rows:
        util.add(result, "ok", "进程列表未命中已知可疑名", "共 %d 个进程" % len(rows))


def _analyze_cmdline(result, rows):
    hits = []
    for row in rows:
        args = str(_pick(row, "Args", "CommandLine", "Cmdline"))
        proc = str(_pick(row, "Process", "ImageFileName"))
        if args and SUSPICIOUS_CMDLINE.search(args):
            hits.append("%s | %s" % (proc, util.short(args, 240)))
    if hits:
        util.add(result, "warn", "可疑命令行 %d 条" % len(hits),
                 "\n".join(hits[:30]), {"items": hits})


def _analyze_network(result, rows):
    listening, external = [], []
    for row in rows:
        proto = str(_pick(row, "Proto", "Protocol"))
        faddr = str(_pick(row, "ForeignAddr", "Foreign Address", "Raddr"))
        fport = str(_pick(row, "ForeignPort", "Foreign Port", "Rport"))
        laddr = str(_pick(row, "LocalAddr", "Local Address", "Laddr"))
        lport = str(_pick(row, "LocalPort", "Local Port", "Lport"))
        state = str(_pick(row, "State"))
        owner = str(_pick(row, "Owner", "Process", "ImageFileName"))
        pid = str(_pick(row, "PID", "pid"))
        label = "%s %s:%s -> %s:%s %s %s(pid=%s)" % (
            proto, laddr, lport, faddr, fport, state, owner, pid)
        if state.upper().startswith("LISTEN") or faddr in ("0.0.0.0", "::", ""):
            listening.append(label)
        elif faddr not in ("127.0.0.1", "::1", "0.0.0.0", "::"):
            external.append(label)
    result["data"]["network"] = {"listening": len(listening),
                                 "external": len(external)}
    if external:
        util.add(result, "warn", "外联连接 %d 条" % len(external),
                 "\n".join(external[:30]), {"items": external})
    if listening:
        util.add(result, "info", "监听端口 %d 条" % len(listening),
                 "\n".join(listening[:30]))


def _analyze_credentials(result, tag, rows):
    if not rows:
        return
    records = []
    for row in rows[:200]:
        user = _pick(row, "Username", "UserName", "user", "User")
        rid = _pick(row, "RID", "rid")
        lm = _pick(row, "LMHash", "lmhash", "LM")
        ntlm = _pick(row, "NTHash", "nthash", "NT")
        plain = _pick(row, "Password", "password", "Plaintext")
        records.append({"user": str(user), "rid": str(rid),
                        "lm": str(lm)[:32], "ntlm": str(ntlm)[:32],
                        "password": str(plain)[:120]})
    data = {"plugin": tag, "count": len(records), "accounts": records}
    path = util.save_json(result["outdir"], "credentials_%s.json" % tag, data)
    util.add_artifact(result, path)
    result["data"].setdefault("credentials", []).append(data)
    preview = "\n".join("%s RID=%s NTLM=%s%s" % (
        item["user"], item["rid"], item["ntlm"] or "-",
        (" 明文=" + item["password"]) if item["password"] else "")
        for item in records[:20])
    util.add(result, "warn", "凭据导出（%s）%d 条" % (tag, len(records)),
             preview, {"file": path})


def _analyze_registry(result, key, rows):
    hits = []
    for row in rows[:500]:
        name = str(_pick(row, "Name", "ValueName", "Value"))
        data = str(_pick(row, "Data", "ValueData", "DataValue"))
        if name and data:
            hits.append("%s = %s" % (name, util.short(data, 240)))
    if hits:
        util.add(result, "warn", "注册表键有值：%s" % key,
                 "\n".join(hits[:30]), {"key": key})


def _analyze_dumpfiles(result, rows, dump_dir):
    files = []
    for row in rows[:2000]:
        name = str(_pick(row, "FileName", "Name"))
        if name:
            files.append(name)
    extracted = []
    if os.path.isdir(dump_dir):
        for path in util.iter_artifacts(dump_dir, max_files=5000):
            extracted.append(path)
            util.flag_scan(util.read_text(path, 4 * 1024 * 1024),
                           "提取文件 %s" % os.path.basename(path), result)
    result["data"]["dumpfiles"] = {"listed": len(files), "extracted": len(extracted),
                                   "dir": dump_dir}
    if extracted:
        util.add(result, "ok", "内存文件提取 %d 个" % len(extracted),
                 "\n".join(extracted[:30]))
    elif files:
        util.add(result, "info", "文件对象 %d 个（未提取内容）" % len(files),
                 "\n".join(files[:30]))


def _render(result):
    lines = ["# 内存取证报告", ""]
    lines.append("- 镜像：`%s`" % result["data"].get("image", ""))
    lines.append("- 大小：%s" % result["data"].get("image_size", "?"))
    vol = result["data"].get("volatility") or {}
    if vol.get("available"):
        lines.append("- Volatility：`%s`（%s）%s" % (
            vol.get("path") or "python -m volatility3", vol.get("kind"),
            vol.get("version") or ""))
    else:
        lines.append("- Volatility：未找到；%s" % vol.get("install", ""))
    strings = result["data"].get("strings") or {}
    lines.append("- 明文扫描：%s / %s，flag=%d，URL=%d" % (
        util.human_size(strings.get("scanned_bytes", 0)),
        util.human_size(strings.get("file_size", 0)),
        len(strings.get("flags") or []), len(strings.get("urls") or [])))
    lines.append("")
    lines.append("## 发现")
    for item in result["findings"]:
        lines.append("- [%s] %s" % (item["level"], item["title"]))
        if item["detail"]:
            for line in item["detail"].splitlines()[:20]:
                lines.append("  - %s" % line)
    plugins = result["data"].get("plugins") or {}
    if plugins:
        lines.append("")
        lines.append("## 插件执行")
        lines.append("| 插件 | 返回码 | 行数 | 耗时 | 输出 |")
        lines.append("| --- | --- | --- | --- | --- |")
        for name, info in plugins.items():
            lines.append("| %s | %s | %s | %ss | %s |" % (
                name, info.get("rc"), info.get("rows"), info.get("elapsed"),
                info.get("artifact", "")))
    lines.append("")
    lines.append("## 备注")
    for note in result["notes"]:
        lines.append("- %s" % note)
    return "\n".join(lines)


def analyze(image: str, outdir: str = "", os_type: str = "auto",
            dump_files: bool = False, max_scan_mb: int = 1024,
            plugin_timeout: int = 300, log=None) -> dict:
    """分析内存镜像。os_type: auto/windows/linux；dump_files=True 时提取文件内容。"""
    log = log or (lambda m: None)
    outdir = outdir or util.case_dir("memory", image)
    result = util.make_result("memory", outdir)
    result["data"]["image"] = os.path.abspath(image)
    if not os.path.isfile(image):
        result["ok"] = False
        util.add(result, "warn", "内存镜像不存在", image)
        return util.finish(result, _render(result))
    result["data"]["image_size"] = os.path.getsize(image)
    util.add_artifact(result, util.save_json(outdir, "meta.json", {
        "image": result["data"]["image"], "size": result["data"]["image_size"]}))

    log("[memory] 明文扫描 %s" % util.size_text(image))
    quick_strings(image, result, max_scan_mb=max_scan_mb, log=log)

    info = util.find_volatility()
    result["data"]["volatility"] = info
    if not info.get("available"):
        result["ok"] = False
        util.add(result, "warn", "未找到 Volatility 3",
                 "安装：%s\n也可用环境变量 VOLATILITY 指向 vol.exe / vol.py。"
                 % info.get("install", ""))
        result["notes"].append("无 Volatility：仅完成镜像明文扫描，未解析进程/网络/注册表。")
        return util.finish(result, _render(result))

    log("[memory] Volatility: %s" % (info.get("path") or info.get("kind")))
    plugin_rows = {}
    plugins_info = {}
    probe = util.run_cmd(_plugin_command(info, image, ["banners"]),
                         timeout=min(plugin_timeout, 180))
    banner_text = (probe["stdout"] + "\n" + probe["stderr"])
    util.add_artifact(result, util.save_text(outdir, "banners.txt", banner_text))
    os_guess = os_type
    if os_guess == "auto":
        low = banner_text.lower()
        if "linux" in low:
            os_guess = "linux"
        elif "windows" in low:
            os_guess = "windows"
        else:
            os_guess = "windows"
    result["data"]["os"] = os_guess
    if probe["rc"] != 0 and not plugin_rows:
        result["notes"].append(
            "banners 返回码 %s；%s" % (probe["rc"], util.short(probe["stderr"], 300)))

    plan = list(WINDOWS_PLUGINS if os_guess == "windows" else LINUX_PLUGINS)
    if os_guess == "windows" and dump_files:
        plan.append(("dumpfiles", ["windows.dumpfiles"], 600))
    dump_dir = os.path.join(outdir, "artifacts", "memfiles")

    for name, plugin, timeout in plan:
        extra = []
        if name == "dumpfiles":
            os.makedirs(dump_dir, exist_ok=True)
            extra = ["--dump-dir", dump_dir]
        cmd = _plugin_command(info, image, plugin, extra)
        log("[memory] %s ..." % name)
        run = util.run_cmd(cmd, timeout=min(plugin_timeout, timeout))
        rows = _rows(run["stdout"])
        plugin_rows[name] = rows
        raw = run["stdout"] + ("\n" + run["stderr"] if run["stderr"] else "")
        art = util.save_text(outdir, "%s.jsonl" % name, raw)
        plugins_info[name] = {"rc": run["rc"], "rows": len(rows),
                              "elapsed": run["elapsed"], "artifact": art,
                              "timeout": run["timeout"]}
        util.add_artifact(result, art)
        if run["rc"] != 0 or not rows:
            result["notes"].append("%s 无有效 JSON（rc=%s）：%s" % (
                name, run["rc"], util.short(run["stderr"], 240)))
        _scan_rows(result, name, rows, raw)
        if name in ("pslist", "pstree"):
            _analyze_processes(result, rows)
        elif name == "cmdline":
            _analyze_cmdline(result, rows)
        elif name == "netscan":
            _analyze_network(result, rows)
        elif name in ("hashdump", "cachedump", "lsadump"):
            _analyze_credentials(result, name, rows)
        elif name == "dumpfiles":
            _analyze_dumpfiles(result, rows, dump_dir)
        elif name == "bash":
            hits = [str(_pick(r, "Command", "CommandLine")) for r in rows]
            hits = [h for h in hits if h and h != "None"]
            if hits:
                util.add(result, "info", "bash 历史 %d 条" % len(hits),
                         "\n".join(hits[:30]))
        elif name == "lsmod":
            util.add(result, "info", "内核模块 %d 个" % len(rows),
                     ", ".join(str(_pick(r, "Module", "Name")) for r in rows[:40]))

    for key in AUTORUN_KEYS:
        cmd = _plugin_command(info, image, ["windows.registry.printkey"],
                              ["--key", key])
        log("[memory] registry %s ..." % key)
        run = util.run_cmd(cmd, timeout=min(plugin_timeout, 180))
        rows = _rows(run["stdout"])
        raw = run["stdout"] + ("\n" + run["stderr"] if run["stderr"] else "")
        tag = "reg_" + re.sub(r"\W+", "_", key)[-40:]
        art = util.save_text(outdir, "%s.jsonl" % tag, raw)
        plugins_info[tag] = {"rc": run["rc"], "rows": len(rows),
                             "elapsed": run["elapsed"],
                             "artifact": art,
                             "timeout": run["timeout"]}
        util.add_artifact(result, art)
        _scan_rows(result, tag, rows, raw)
        if rows:
            _analyze_registry(result, key, rows)

    result["data"]["plugins"] = plugins_info
    if not any(info.get("rows") for info in plugins_info.values()):
        result["ok"] = False
        result["notes"].append(
            "所有插件均未产出数据：镜像可能不是有效内存转储、缺少符号表，"
            "或镜像类型不受支持。已保留每个插件的原始错误输出。")
    result["summary"] = "镜像 %s，%s 插件 %d 个，flag %d 个" % (
        util.size_text(image), os_guess, len(plugins_info),
        sum(1 for f in result["findings"] if f["level"] == "flag"))
    result["notes"].append(
        "未内置内存镜像样本：插件命令/JSON 解析已做单元验证，"
        "端到端解析需在真实镜像上复核。")
    return util.finish(result, _render(result))
