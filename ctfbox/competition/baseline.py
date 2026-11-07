# -*- coding: utf-8 -*-
"""系统安全与加固基线：Windows Server / Linux 检查 + 加固/回滚脚本生成。

边界：检查命令只读；生成的 harden/rollback 脚本只落盘、不自动执行，
脚本内容仅做语法校验。Linux 支持离线 rootfs 目录分析，活动状态类检查会标注
「offline 未验证」。
"""
import os
import re
import stat

from . import util

AUDIT_GUIDS = {
    "Logon": "0CCE9215-69AE-11D9-BED3-505054503030",
    "Logoff": "0CCE9216-69AE-11D9-BED3-505054503030",
    "Account Lockout": "0CCE9217-69AE-11D9-BED3-505054503030",
    "Special Logon": "0CCE921B-69AE-11D9-BED3-505054503030",
    "Process Creation": "0CCE922B-69AE-11D9-BED3-505054503030",
    "Audit Policy Change": "0CCE922F-69AE-11D9-BED3-505054503030",
    "Security System Extension": "0CCE9211-69AE-11D9-BED3-505054503030",
    "Sensitive Privilege Use": "0CCE9228-69AE-11D9-BED3-505054503030",
}

RISKY_SERVICES = {
    "RemoteRegistry": "远程注册表", "TermService": "远程桌面", "WinRM": "WinRM 远程管理",
    "SNMP": "SNMP", "SNMPTRAP": "SNMP Trap", "TlntSvr": "Telnet 服务",
    "MSFTPSVC": "FTP 服务", "SSHD": "OpenSSH 服务", "LanmanServer": "SMB 服务端",
    "LanmanWorkstation": "SMB 客户端",
}

SYSCTL_EXPECT = {
    "net.ipv4.ip_forward": ("0", "开启 IP 转发"),
    "net.ipv4.conf.all.accept_redirects": ("0", "接受 ICMP 重定向"),
    "net.ipv4.conf.all.send_redirects": ("0", "发送 ICMP 重定向"),
    "net.ipv4.conf.all.accept_source_route": ("0", "接受源路由"),
    "net.ipv4.conf.all.rp_filter": ("1", "反向路径过滤"),
    "net.ipv4.tcp_syncookies": ("1", "SYN Cookie"),
    "kernel.randomize_va_space": ("2", "ASLR"),
    "kernel.kptr_restrict": ("2", "内核指针泄露"),
    "kernel.dmesg_restrict": ("1", "dmesg 限制"),
    "fs.protected_hardlinks": ("1", "硬链接保护"),
    "fs.protected_symlinks": ("1", "符号链接保护"),
}

RISKY_UNITS = ("telnet", "rsh", "rlogin", "rexec", "vsftpd", "proftpd",
               "pure-ftpd", "tftp", "xinetd", "inetd", "snmpd")


def _check(result, cid, title, status, detail="", remediation="", category=""):
    item = {"id": cid, "title": title, "status": status, "detail": detail,
            "remediation": remediation, "category": category}
    result["data"].setdefault("checks", []).append(item)
    level = {"fail": "warn", "warn": "warn", "pass": "ok",
             "info": "info", "unverified": "info"}.get(status, "info")
    util.add(result, level, title, detail, item)
    return item


def _powershell():
    return util.which("powershell") or util.which("pwsh")


WIN_COLLECT = r'''
$ErrorActionPreference = "Continue"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$out = [ordered]@{}
function T([string]$name, [scriptblock]$sb) {
  try { $out[$name] = & $sb } catch { $out[$name] = $null; $out["${name}_error"] = $_.Exception.Message }
}
T "os" { Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,LastBootUpTime,InstallDate }
T "computer" { Get-CimInstance Win32_ComputerSystem | Select-Object Name,Domain,PartOfDomain,Manufacturer,Model }
T "users" { @(Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,PasswordLastSet,PasswordExpires,LastLogon,Description) }
T "admins" { @(Get-LocalGroup -SID S-1-5-32-544 | Get-LocalGroupMember | Select-Object Name,ObjectClass,PrincipalSource) }
T "shares" { @(Get-SmbShare | Select-Object Name,Path,Description) }
T "share_access" { @(Get-SmbShare | ForEach-Object { $n = $_.Name; Get-SmbShareAccess -Name $n | Select-Object @{n="Share";e={$n}},AccountName,AccessControlType,AccessRight }) }
T "services" { @(Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName) }
T "unquoted" { @(Get-CimInstance Win32_Service | Where-Object { $_.PathName -match '^[^"].*\\ .*\.exe' } | Select-Object Name,PathName) }
T "hotfix" { @(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 30 HotFixID,InstalledOn,Description) }
T "firewall" { @(Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction) }
T "smb" { Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EnableSecuritySignature,EncryptData }
T "rdp" { @{ Deny = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections; NLA = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication } }
T "uac" { (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA }
T "autologon" { (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword }
T "always_elevated" { @{ HKLM = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated; HKCU = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated } }
T "audit" { (auditpol /get /category:* /r | Out-String) }
T "secedit" { $t = [IO.Path]::GetTempFileName(); secedit /export /cfg $t | Out-Null; $c = Get-Content $t -Raw; Remove-Item $t -Force -ErrorAction SilentlyContinue; $c }
T "security_log" { @(Get-WinEvent -ListLog Security -ErrorAction Stop | Select-Object LogName,IsEnabled,MaximumSizeInBytes,RecordCount,LastWriteTime) }
T "defender" { Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled,BehaviorMonitorEnabled }
T "execution_policy" { @(Get-ExecutionPolicy -List | Select-Object Scope,ExecutionPolicy) }
T "smb1_feature" { Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop | Select-Object FeatureName,State }
$out | ConvertTo-Json -Depth 6 -Compress
'''


def _run_windows_collector(outdir, result, timeout=120):
    ps = _powershell()
    if not ps:
        _check(result, "win-collect", "Windows 检查不可用", "unverified",
               "未找到 powershell/pwsh", "在 Windows 主机上运行本工具")
        return {}
    script = util.save_text(outdir, "collect_windows.ps1", WIN_COLLECT)
    run = util.run_cmd([ps, "-NoProfile", "-ExecutionPolicy", "Bypass",
                        "-File", script], timeout=timeout)
    result["data"]["collector"] = {"rc": run["rc"], "elapsed": run["elapsed"],
                                   "stderr": util.short(run["stderr"], 400)}
    text = (run["stdout"] or "").strip().lstrip("\ufeff")
    import json
    for line in reversed(text.splitlines()):
        line = line.strip().lstrip("\ufeff")
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except Exception:
                continue
    try:
        return json.loads(text)
    except Exception:
        _check(result, "win-collect", "Windows 检查数据解析失败", "unverified",
               util.short(run["stderr"] or text, 400))
        return {}


def _win_date(value):
    if not value:
        return None
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", str(value))
    if m:
        try:
            import datetime
            return datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except Exception:
            return None
    m = re.search(r"/Date\((\d+)", str(value))
    if m:
        try:
            import datetime
            return datetime.datetime.utcfromtimestamp(int(m.group(1)) / 1000.0).date()
        except Exception:
            return None
    return None


def _win_checks(data, result):
    osinfo = data.get("os") or {}
    computer = data.get("computer") or {}
    _check(result, "win-os", "Windows 系统信息", "info",
           "%s %s build=%s host=%s domain=%s part_of_domain=%s" % (
               osinfo.get("Caption", ""), osinfo.get("Version", ""),
               osinfo.get("BuildNumber", ""), computer.get("Name", ""),
               computer.get("Domain", ""), computer.get("PartOfDomain", "")),
           "")
    users = data.get("users") or []
    admins = data.get("admins") or []
    if users:
        guest = [u for u in users if str(u.get("Name", "")).lower() == "guest"]
        if guest and guest[0].get("Enabled"):
            _check(result, "win-guest", "Guest 账户启用", "warn",
                   "Guest 账户处于启用状态", "Disable-LocalUser -Name Guest")
        else:
            _check(result, "win-guest", "Guest 账户状态", "pass", "Guest 未启用",
                   "")
        never = [u.get("Name") for u in users if u.get("Enabled") and
                 u.get("PasswordExpires") is False]
        if never:
            _check(result, "win-pw-expire", "口令永不过期账户", "warn",
                   ", ".join(str(x) for x in never[:20]),
                   "为相关账户设置口令有效期")
        _check(result, "win-users", "本地账户清点", "info",
               "\n".join("%s enabled=%s pwd_required=%s last_set=%s" % (
                   u.get("Name"), u.get("Enabled"), u.get("PasswordRequired"),
                   u.get("PasswordLastSet")) for u in users[:30]), "")
    if admins:
        _check(result, "win-admins", "管理员组成员", "info",
               "\n".join("%s (%s)" % (a.get("Name"), a.get("ObjectClass"))
                         for a in admins[:30]), "定期复核管理员组成员")
    secedit = data.get("secedit") or ""

    def sec(key, default=""):
        m = re.search(r"(?mi)^\s*%s\s*=\s*(\S+)" % re.escape(key), secedit)
        return m.group(1) if m else default
    min_len = sec("MinimumPasswordLength")
    lockout = sec("LockoutBadCount")
    max_age = sec("MaximumPasswordAge")
    complexity = sec("PasswordComplexity")
    cleartext = sec("ClearTextPassword")
    if min_len:
        ok = min_len.isdigit() and int(min_len) >= 12
        _check(result, "win-pw-len", "最小口令长度", "pass" if ok else "warn",
               "MinimumPasswordLength=%s（建议 >=12）" % min_len,
               "net accounts /minpwlen:12")
    else:
        _check(result, "win-pw-len", "最小口令长度", "unverified",
               "secedit 未导出 MinimumPasswordLength", "")
    if lockout:
        ok = lockout.isdigit() and 0 < int(lockout) <= 10
        _check(result, "win-lockout", "账户锁定阈值", "pass" if ok else "warn",
               "LockoutBadCount=%s（0 表示不锁定）" % lockout,
               "net accounts /lockoutthreshold:5")
    if max_age and max_age.isdigit():
        ok = 0 < int(max_age) <= 90
        _check(result, "win-pw-age", "口令最长使用期", "pass" if ok else "warn",
               "MaximumPasswordAge=%s 天" % max_age, "net accounts /maxpwage:90")
    if complexity:
        _check(result, "win-pw-complexity", "口令复杂性", "pass" if complexity == "1" else "warn",
               "PasswordComplexity=%s" % complexity,
               "启用「密码必须符合复杂性要求」")
    if cleartext == "1":
        _check(result, "win-pw-cleartext", "可逆加密存储口令", "fail",
               "ClearTextPassword=1", "禁用「用可逆加密存储密码」")
    shares = data.get("shares") or []
    non_default = [s for s in shares if str(s.get("Name", "")).upper() not in
                   ("IPC$", "ADMIN$", "C$", "D$", "E$")]
    if non_default:
        _check(result, "win-shares", "非默认共享", "warn",
               "\n".join("%s -> %s (%s)" % (s.get("Name"), s.get("Path"),
                                             s.get("Description", ""))
                         for s in non_default[:20]),
               "关闭不需要的共享，限制共享 ACL")
    access = data.get("share_access") or []
    risky_access = [a for a in access if a.get("AccessControlType") == "Allow" and
                    str(a.get("AccountName", "")).lower() in
                    ("everyone", "anonymous logon", "users", "authenticated users")]
    if risky_access:
        _check(result, "win-share-acl", "共享 ACL 过宽", "warn",
               "\n".join("%s %s %s" % (a.get("Share"), a.get("AccountName"),
                                        a.get("AccessRight"))
                         for a in risky_access[:20]),
               "移除 Everyone/匿名/Users 的共享写权限")
    services = data.get("services") or []
    risky = [s for s in services if str(s.get("Name", "")) in RISKY_SERVICES and
             str(s.get("State", "")).lower() == "running"]
    if risky:
        _check(result, "win-services", "高风险服务运行中", "warn",
               "\n".join("%s(%s) %s start=%s account=%s" % (
                   s.get("Name"), RISKY_SERVICES.get(s.get("Name"), ""),
                   s.get("State"), s.get("StartMode"), s.get("StartName"))
                   for s in risky[:20]),
               "按需关闭 RemoteRegistry/Telnet/FTP/SNMP 等服务")
    unquoted = data.get("unquoted") or []
    if unquoted:
        _check(result, "win-unquoted", "未加引号的服务路径", "warn",
               "\n".join("%s -> %s" % (s.get("Name"), s.get("PathName"))
                         for s in unquoted[:20]),
               "给服务 ImagePath 加引号，防止路径劫持")
    hotfix = data.get("hotfix") or []
    if hotfix:
        dates = [_win_date(h.get("InstalledOn")) for h in hotfix]
        dates = [d for d in dates if d]
        last = max(dates) if dates else None
        if last:
            import datetime
            age = (datetime.date.today() - last).days
            _check(result, "win-hotfix", "补丁更新时间", "pass" if age <= 120 else "warn",
                   "最近补丁 %s，距今 %s 天（共 %s 条）" % (last, age, len(hotfix)),
                   "结合 WSUS/Windows Update 复核缺失补丁")
        else:
            _check(result, "win-hotfix", "补丁更新时间", "unverified",
                   "Get-HotFix 未返回可用日期", "")
    else:
        _check(result, "win-hotfix", "补丁更新时间", "unverified",
               "未读取到补丁列表", "在目标主机执行 Get-HotFix 复核")
    fw = data.get("firewall") or []
    if fw:
        off = [p for p in fw if not p.get("Enabled")]
        _check(result, "win-firewall", "防火墙配置", "warn" if off else "pass",
               "\n".join("%s enabled=%s inbound=%s" % (
                   p.get("Name"), p.get("Enabled"), p.get("DefaultInboundAction"))
                   for p in fw),
               "启用所有防火墙配置文件")
    smb = data.get("smb") or {}
    if smb:
        if smb.get("EnableSMB1Protocol"):
            _check(result, "win-smb1", "SMBv1 已启用", "warn",
                   "EnableSMB1Protocol=True", "Set-SmbServerConfiguration -EnableSMB1Protocol $false")
        else:
            _check(result, "win-smb1", "SMBv1", "pass", "SMBv1 未启用", "")
        if smb.get("RequireSecuritySignature") is False:
            _check(result, "win-smb-sign", "SMB 签名未强制", "warn",
                   "RequireSecuritySignature=False",
                   "Set-SmbServerConfiguration -RequireSecuritySignature $true")
    rdp = data.get("rdp") or {}
    if rdp:
        if str(rdp.get("Deny")) == "0":
            _check(result, "win-rdp", "远程桌面已开启", "info",
                   "fDenyTSConnections=0（RDP 可访问）", "限制来源并启用 NLA")
        if str(rdp.get("NLA")) == "0":
            _check(result, "win-rdp-nla", "RDP 未启用 NLA", "warn",
                   "UserAuthentication=0", "启用「仅允许运行使用网络级别身份验证的远程桌面」")
    uac = data.get("uac")
    if uac is not None:
        _check(result, "win-uac", "UAC", "pass" if str(uac) == "1" else "fail",
               "EnableLUA=%s" % uac, "启用 UAC 并重启")
    if data.get("autologon"):
        _check(result, "win-autologon", "注册表存在自动登录口令", "fail",
               "Winlogon.DefaultPassword 非空", "移除自动登录口令，改用受管凭据")
    elevated = data.get("always_elevated") or {}
    if str(elevated.get("HKLM")) == "1" or str(elevated.get("HKCU")) == "1":
        _check(result, "win-always-elevated", "AlwaysInstallElevated 已启用", "warn",
               "HKLM=%s HKCU=%s" % (elevated.get("HKLM"), elevated.get("HKCU")),
               "删除 AlwaysInstallElevated 策略")
    audit = data.get("audit") or ""
    if audit:
        rows = [line.split(",") for line in audit.splitlines() if line.count(",") >= 4]
        bad = []
        for guid, name in AUDIT_GUIDS.items():
            for row in rows:
                if len(row) < 5:
                    continue
                joined = ",".join(row).lower()
                if guid.lower() in joined:
                    values = [x.strip().strip('"') for x in row]
                    setting = values[6] if len(values) > 6 else values[4]
                    if setting == "0" or any(
                            x.lower() in ("no auditing", "无审核") for x in values):
                        bad.append(name)
                    break
        if bad:
            _check(result, "win-audit", "关键审核策略未开启", "warn",
                   "未审核：" + ", ".join(bad),
                   "auditpol /set /subcategory:<GUID> /success:enable /failure:enable")
        else:
            _check(result, "win-audit", "关键审核策略", "pass",
                   "登录/账户锁定/策略变更/进程创建等关键项已配置审核", "")
    else:
        _check(result, "win-audit", "审核策略", "unverified",
               "auditpol 无输出（可能权限不足）", "以管理员运行 auditpol /get /category:*")
    logs = data.get("security_log") or []
    if logs:
        log = logs[0] if isinstance(logs, list) else logs
        size = log.get("MaximumSizeInBytes") or 0
        enabled = log.get("IsEnabled")
        if enabled is False:
            _check(result, "win-seclog", "Security 日志未启用", "fail",
                   "IsEnabled=False", "启用 Security 日志")
        elif size and size < 64 * 1024 * 1024:
            _check(result, "win-seclog", "Security 日志容量偏小", "warn",
                   "MaximumSizeInBytes=%s（建议 >=64MB）" % size,
                   "增大 Security 日志容量")
        else:
            _check(result, "win-seclog", "Security 日志配置", "pass",
                   "size=%s records=%s" % (size, log.get("RecordCount")), "")
    defender = data.get("defender") or {}
    if defender:
        rt = defender.get("RealTimeProtectionEnabled")
        av = defender.get("AntivirusEnabled")
        _check(result, "win-defender", "Defender 状态",
               "pass" if (rt is not False and av is not False) else "warn",
               "Antivirus=%s RealTime=%s" % (av, rt),
               "启用 Defender 实时保护或确认第三方 AV 已接管")
    policy = data.get("execution_policy") or []
    if policy:
        _check(result, "win-exec-policy", "PowerShell 执行策略", "info",
               "\n".join("%s=%s" % (p.get("Scope"), p.get("ExecutionPolicy"))
                         for p in policy), "生产服务器建议 AllSigned/RemoteSigned")
    feature = data.get("smb1_feature") or {}
    if feature and str(feature.get("State", "")).lower() == "enabled":
        _check(result, "win-smb1-feature", "SMB1 功能仍安装", "warn",
               "SMB1Protocol State=Enabled",
               "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol")


# ----------------------------------------------------------------------------
# Linux（离线 rootfs 或本机 /）
# ----------------------------------------------------------------------------
def _read(root, rel, limit=2 * 1024 * 1024):
    path = os.path.join(root, rel.lstrip("/\\").replace("/", os.sep))
    if not os.path.isfile(path):
        return ""
    try:
        return util.read_text(path, limit)
    except Exception:
        return ""


def _mode(root, rel):
    path = os.path.join(root, rel.lstrip("/\\").replace("/", os.sep))
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except Exception:
        return None


def _parse_kv(text):
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _linux_root(target):
    if target and os.path.isdir(target):
        if os.path.isfile(os.path.join(target, "etc", "passwd")):
            return os.path.abspath(target)
        nested = os.path.join(target, "rootfs")
        if os.path.isfile(os.path.join(nested, "etc", "passwd")):
            return os.path.abspath(nested)
    if os.name != "nt" and os.path.isdir("/etc"):
        return "/"
    return ""


def _linux_checks(root, result):
    passwd = _read(root, "/etc/passwd")
    shadow = _read(root, "/etc/shadow")
    if not passwd:
        _check(result, "linux-root", "Linux 根文件系统", "unverified",
               "目标目录缺少 etc/passwd；请指向已挂载的 rootfs 目录",
               "例如 --comp baseline --target /mnt/rootfs")
        return
    _check(result, "linux-root", "Linux 根文件系统", "info", root, "")
    users = []
    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        users.append({"name": parts[0], "uid": parts[2], "gid": parts[3],
                      "gecos": parts[4], "home": parts[5], "shell": parts[6]})
    uid0 = [u for u in users if u["uid"] == "0"]
    extra_root = [u["name"] for u in uid0 if u["name"] != "root"]
    if extra_root:
        _check(result, "linux-uid0", "非 root 的 UID 0 账户", "fail",
               ", ".join(extra_root), "移除或修改这些账户的 UID")
    seen = {}
    dup = []
    for u in users:
        if u["uid"] in seen:
            dup.append("%s/%s uid=%s" % (seen[u["uid"]], u["name"], u["uid"]))
        else:
            seen[u["uid"]] = u["name"]
    if dup:
        _check(result, "linux-dup-uid", "重复 UID", "warn", "\n".join(dup[:20]),
               "统一 UID 分配")
    shells = [u for u in users if u["shell"] not in
              ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false")]
    if shells:
        _check(result, "linux-shells", "可登录账户", "info",
               "\n".join("%s uid=%s shell=%s" % (u["name"], u["uid"], u["shell"])
                         for u in shells[:30]), "定期复核可登录账户")
    shadow_map = {}
    weak, empty, locked = [], [], []
    for line in shadow.splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        name, pwd = parts[0], parts[1]
        shadow_map[name] = parts
        if pwd == "":
            empty.append(name)
        elif pwd.startswith(("!", "*")):
            locked.append(name)
        elif pwd.startswith(("$1$", "$2a$", "$2b$", "$2y$", "$5$", "$6$", "$y$",
                             "$7$", "$argon2")):
            if pwd.startswith("$1$"):
                weak.append(name)
        elif len(pwd) == 13:
            weak.append(name)
    if empty:
        _check(result, "linux-empty-pw", "空口令账户", "fail",
               ", ".join(empty[:30]), "立即为这些账户设置强口令或锁定")
    if weak:
        _check(result, "linux-weak-hash", "弱口令哈希算法", "warn",
               ", ".join(weak[:30]), "迁移到 yescrypt/bcrypt/SHA-512")
    if locked:
        _check(result, "linux-locked", "已锁定/无口令哈希账户", "info",
               ", ".join(locked[:30]), "")
    login_defs = _parse_kv(_read(root, "/etc/login.defs"))
    max_days = login_defs.get("PASS_MAX_DAYS", "")
    min_len = login_defs.get("PASS_MIN_LEN", "")
    min_days = login_defs.get("PASS_MIN_DAYS", "")
    if max_days:
        ok = max_days.isdigit() and 0 < int(max_days) <= 90
        _check(result, "linux-pw-age", "口令最长使用期", "pass" if ok else "warn",
               "PASS_MAX_DAYS=%s" % max_days, "设置 PASS_MAX_DAYS 90")
    if min_len:
        ok = min_len.isdigit() and int(min_len) >= 12
        _check(result, "linux-pw-len", "口令最小长度", "pass" if ok else "warn",
               "PASS_MIN_LEN=%s" % min_len, "设置 PASS_MIN_LEN 12（并配置 pam_pwquality）")
    if min_days:
        _check(result, "linux-pw-mindays", "口令最短使用期", "info",
               "PASS_MIN_DAYS=%s" % min_days, "")
    # 关键文件权限
    for rel, max_mode, label in (
            ("/etc/passwd", 0o644, "passwd"), ("/etc/shadow", 0o640, "shadow"),
            ("/etc/group", 0o644, "group"), ("/etc/gshadow", 0o640, "gshadow"),
            ("/etc/sudoers", 0o440, "sudoers"),
            ("/etc/ssh/sshd_config", 0o600, "sshd_config")):
        mode = _mode(root, rel)
        if mode is None:
            continue
        actual = "%04o" % mode
        if mode & 0o002:
            _check(result, "linux-perm-" + label, "%s 权限过宽" % rel, "fail",
                   "%s=%s（other 可写）" % (rel, actual), "chmod %04o %s" % (max_mode, rel))
        elif rel == "/etc/shadow" or rel == "/etc/gshadow":
            if mode & 0o004:
                _check(result, "linux-perm-" + label, "%s 权限过宽" % rel, "fail",
                       "%s=%s（other 可读）" % (rel, actual), "chmod 640 %s" % rel)
        elif mode & 0o022:
            _check(result, "linux-perm-" + label, "%s 权限过宽" % rel, "warn",
                   "%s=%s（group/other 可写）" % (rel, actual),
                   "chmod %04o %s" % (max_mode, rel))
    # SSH
    ssh = _read(root, "/etc/ssh/sshd_config")
    if ssh:
        directives = {}
        for line in ssh.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if parts:
                directives[parts[0].lower()] = parts[1] if len(parts) > 1 else ""
        def val(key):
            return directives.get(key, "")
        if val("permitrootlogin").lower() == "yes":
            _check(result, "linux-ssh-root", "SSH 允许 root 登录", "warn",
                   "PermitRootLogin yes", "设置 PermitRootLogin no 或 prohibit-password")
        if val("permitemptypasswords").lower() == "yes":
            _check(result, "linux-ssh-empty", "SSH 允许空口令", "fail",
                   "PermitEmptyPasswords yes", "设置 PermitEmptyPasswords no")
        if val("passwordauthentication").lower() == "yes":
            _check(result, "linux-ssh-password", "SSH 口令登录", "info",
                   "PasswordAuthentication yes", "如条件允许改用密钥并关闭口令登录")
        elif not val("passwordauthentication"):
            _check(result, "linux-ssh-password", "SSH 口令登录", "info",
                   "未显式配置 PasswordAuthentication（OpenSSH 默认 yes）",
                   "显式设置 PasswordAuthentication no")
        if val("x11forwarding").lower() == "yes":
            _check(result, "linux-ssh-x11", "SSH X11 转发", "info",
                   "X11Forwarding yes", "如不需要关闭")
        tries = val("maxauthtries")
        if tries.isdigit() and int(tries) > 4:
            _check(result, "linux-ssh-tries", "SSH MaxAuthTries 过大", "info",
                   "MaxAuthTries=%s" % tries, "设置 MaxAuthTries 4")
        grace = val("logingracetime")
        if grace.isdigit() and int(grace) > 60:
            _check(result, "linux-ssh-grace", "SSH LoginGraceTime 过长", "info",
                   "LoginGraceTime=%s" % grace, "设置 LoginGraceTime 30")
        weak_alg = []
        for key in ("ciphers", "macs", "kexalgorithms"):
            value = val(key).lower()
            if any(x in value for x in ("3des", "arcfour", "blowfish", "md5", "sha1",
                                        "diffie-hellman-group1")):
                weak_alg.append("%s=%s" % (key, value))
        if weak_alg:
            _check(result, "linux-ssh-alg", "SSH 弱算法", "warn",
                   "\n".join(weak_alg), "移除 3DES/RC4/MD5/SHA1/DH-group1")
        if val("permitrootlogin").lower() not in ("no", "prohibit-password",
                                                  "without-password"):
            _check(result, "linux-ssh-root-default", "SSH root 登录策略", "info",
                   "PermitRootLogin 未显式关闭", "显式设置 PermitRootLogin no")
    else:
        _check(result, "linux-ssh", "SSH 配置", "unverified",
               "未找到 /etc/ssh/sshd_config", "")
    # sudoers
    sudoers = _read(root, "/etc/sudoers")
    extra = ""
    sudoers_d = os.path.join(root, "etc", "sudoers.d")
    if os.path.isdir(sudoers_d):
        for name in os.listdir(sudoers_d):
            extra += _read(root, "/etc/sudoers.d/" + name)
    nopass = [line.strip() for line in (sudoers + "\n" + extra).splitlines()
              if "NOPASSWD" in line and not line.strip().startswith("#")]
    if nopass:
        _check(result, "linux-sudo-nopass", "sudoers 存在 NOPASSWD", "warn",
               "\n".join(nopass[:20]), "移除不必要的 NOPASSWD，限制 sudo 命令")
    for rel in ("/etc/sudoers",):
        mode = _mode(root, rel)
        if mode is not None and mode & 0o002:
            _check(result, "linux-sudo-perm", "sudoers 可被其他用户修改", "fail",
                   "%s=%04o" % (rel, mode), "chmod 440 /etc/sudoers && visudo -c")
    # sysctl
    sysctl = _read(root, "/etc/sysctl.conf")
    sysctl_d = os.path.join(root, "etc", "sysctl.d")
    if os.path.isdir(sysctl_d):
        for name in sorted(os.listdir(sysctl_d)):
            if name.endswith(".conf"):
                sysctl += "\n" + _read(root, "/etc/sysctl.d/" + name)
    values = _parse_kv(sysctl)
    insecure = []
    for key, (want, desc) in SYSCTL_EXPECT.items():
        if key in values and values[key].split()[0] != want:
            insecure.append("%s=%s（建议 %s，%s）" % (key, values[key], want, desc))
    if insecure:
        _check(result, "linux-sysctl", "内核参数加固不足", "warn",
               "\n".join(insecure), "写入 /etc/sysctl.d/99-mohe.conf 并 sysctl --system")
    elif values:
        _check(result, "linux-sysctl", "内核参数", "info",
               "未发现显式不安全配置；缺省项需结合运行态复核", "")
    # 审计
    audit_rules = _read(root, "/etc/audit/audit.rules")
    audit_d = os.path.join(root, "etc", "audit", "rules.d")
    rule_files = []
    if os.path.isdir(audit_d):
        for name in sorted(os.listdir(audit_d)):
            if name.endswith(".rules"):
                rule_files.append(name)
                audit_rules += "\n" + _read(root, "/etc/audit/rules.d/" + name)
    if audit_rules.strip():
        missing = []
        for token, label in (("/etc/passwd", "passwd 变更"), ("/etc/shadow", "shadow 变更"),
                             ("execve", "命令执行"), ("-w /etc/sudoers", "sudoers 变更")):
            if token not in audit_rules:
                missing.append(label)
        if missing:
            _check(result, "linux-audit", "审计规则不完整", "warn",
                   "缺少：" + ", ".join(missing) + "；规则文件：" +
                   (", ".join(rule_files) or "audit.rules"), "补充 audit 规则并 augenrules --load")
        else:
            _check(result, "linux-audit", "审计规则", "pass",
                   "规则文件：%s" % (", ".join(rule_files) or "audit.rules"), "")
    else:
        _check(result, "linux-audit", "审计规则", "unverified",
               "未找到 audit 规则；可能未安装 auditd", "安装 auditd 并配置关键文件/命令审计")
    # 计划任务
    cron_world = []
    cron_dirs = ["etc/cron.d", "etc/cron.daily", "etc/cron.hourly",
                 "etc/cron.weekly", "etc/cron.monthly", "var/spool/cron"]
    for rel in cron_dirs:
        directory = os.path.join(root, rel.replace("/", os.sep))
        if not os.path.isdir(directory):
            continue
        for name in os.listdir(directory):
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                mode = stat.S_IMODE(os.stat(path).st_mode)
                if mode & 0o002:
                    cron_world.append("%s (%04o)" % (path, mode))
    if cron_world:
        _check(result, "linux-cron", "计划任务文件可被其他用户修改", "fail",
               "\n".join(cron_world[:20]), "chmod o-w 相关 cron 文件")
    # 高风险服务
    enabled = []
    wants = os.path.join(root, "etc", "systemd", "system", "multi-user.target.wants")
    if os.path.isdir(wants):
        for name in os.listdir(wants):
            low = name.lower()
            if any(x in low for x in RISKY_UNITS):
                enabled.append("systemd: " + name)
    for rel in ("etc/xinetd.d", "etc/inetd.conf"):
        directory = os.path.join(root, rel.replace("/", os.sep))
        if os.path.isdir(directory):
            for name in os.listdir(directory):
                if any(x in name.lower() for x in RISKY_UNITS):
                    enabled.append("xinetd: " + name)
        elif os.path.isfile(directory):
            text = util.read_text(directory, 512 * 1024)
            for line in text.splitlines():
                if line and not line.startswith("#") and any(
                        x in line.lower() for x in RISKY_UNITS):
                    enabled.append("inetd: " + line.strip()[:100])
    if enabled:
        _check(result, "linux-risky-svc", "高风险网络服务", "warn",
               "\n".join(enabled[:20]), "关闭 telnet/rsh/ftp/tftp 等明文或陈旧服务")
    # 防火墙/SELinux
    fw_present = [rel for rel in ("etc/firewalld", "etc/ufw", "etc/sysconfig/iptables",
                                  "etc/nftables.conf")
                  if os.path.exists(os.path.join(root, rel.replace("/", os.sep)))]
    if fw_present:
        _check(result, "linux-firewall", "防火墙配置", "info",
               "存在：" + ", ".join(fw_present) +
               "；离线分析无法确认运行态", "在目标主机执行 firewall-cmd --state / ufw status")
    else:
        _check(result, "linux-firewall", "防火墙配置", "warn",
               "未发现 firewalld/ufw/nftables 配置", "安装并启用主机防火墙")
    selinux = _read(root, "/etc/selinux/config")
    if selinux:
        m = re.search(r"(?m)^\s*SELINUX\s*=\s*(\w+)", selinux)
        if m:
            state = m.group(1).lower()
            _check(result, "linux-selinux", "SELinux", "pass" if state == "enforcing" else "info",
                   "SELINUX=%s" % state, "建议 enforcing")
    else:
        apparmor = os.path.exists(os.path.join(root, "etc", "apparmor"))
        _check(result, "linux-mac", "强制访问控制", "info",
               "AppArmor 配置存在" if apparmor else "未发现 SELinux/AppArmor 配置",
               "启用 SELinux 或 AppArmor")
    # 离线状态下无法确认补丁/运行态
    _check(result, "linux-offline", "离线基线边界", "unverified",
           "rootfs 离线分析无法确认：运行中服务、补丁级别、防火墙/审计运行态、内核版本",
           "在目标主机运行在线检查或结合配置管理/漏洞扫描复核")


# ----------------------------------------------------------------------------
# 脚本生成
# ----------------------------------------------------------------------------
WIN_HARDEN = r'''# MoHe CTF v3.7.0 - Windows hardening script (GENERATED, NOT EXECUTED)
# Review every action before running. Run in an elevated PowerShell on the target host.
# The script captures current state to hardening_state.json for rollback.ps1.
$ErrorActionPreference = "Stop"
$stateFile = Join-Path $PSScriptRoot "hardening_state.json"
$auditBackup = Join-Path $PSScriptRoot "audit_backup.csv"
$state = [ordered]@{}
function Capture([string]$name, [scriptblock]$sb) {
  try { $state[$name] = & $sb } catch { $state[$name] = $null }
}
Capture "GuestEnabled" { (Get-LocalUser -Name Guest -ErrorAction Stop).Enabled }
Capture "SMB1" { (Get-SmbServerConfiguration).EnableSMB1Protocol }
Capture "SmbSigning" { (Get-SmbServerConfiguration).RequireSecuritySignature }
Capture "Firewall" { @(Get-NetFirewallProfile | Select-Object Name,Enabled) }
Capture "RDPNLA" { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -ErrorAction Stop).UserAuthentication }
Capture "UAC" { (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction Stop).EnableLUA }
Capture "SecEdit" { $t = [IO.Path]::GetTempFileName(); secedit /export /cfg $t | Out-Null; $c = Get-Content $t -Raw; Remove-Item $t -Force -ErrorAction SilentlyContinue; $c }
try { auditpol /backup /file:"$auditBackup" | Out-Null } catch { Write-Warning "auditpol backup failed: $_" }
$state | ConvertTo-Json -Depth 5 | Set-Content -Path $stateFile -Encoding UTF8
Write-Host "State saved to $stateFile"

# --- password policy ---
try { net accounts /minpwlen:12 /maxpwage:90 /lockoutthreshold:5 | Out-Null } catch { Write-Warning $_ }
# --- guest account ---
try { Disable-LocalUser -Name Guest -ErrorAction SilentlyContinue } catch { Write-Warning $_ }
# --- SMB ---
try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force } catch { Write-Warning $_ }
try { Set-SmbServerConfiguration -RequireSecuritySignature $true -Force } catch { Write-Warning $_ }
# --- firewall ---
try { Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True } catch { Write-Warning $_ }
# --- RDP NLA (does not enable RDP) ---
try { Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1 } catch { Write-Warning $_ }
# --- UAC (reboot required) ---
try { Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1 } catch { Write-Warning $_ }
# --- audit policy by GUID (language independent) ---
$guids = @(
  "{0CCE9215-69AE-11D9-BED3-505054503030}",
  "{0CCE9216-69AE-11D9-BED3-505054503030}",
  "{0CCE9217-69AE-11D9-BED3-505054503030}",
  "{0CCE921B-69AE-11D9-BED3-505054503030}",
  "{0CCE922B-69AE-11D9-BED3-505054503030}",
  "{0CCE922F-69AE-11D9-BED3-505054503030}",
  "{0CCE9211-69AE-11D9-BED3-505054503030}"
)
foreach ($g in $guids) { try { auditpol /set /subcategory:"$g" /success:enable /failure:enable | Out-Null } catch { Write-Warning $_ } }
# --- PowerShell script block logging ---
try {
  $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
  New-Item -Path $p -Force | Out-Null
  Set-ItemProperty -Path $p -Name EnableScriptBlockLogging -Value 1
} catch { Write-Warning $_ }
Write-Host "Hardening actions completed. Reboot may be required for UAC."
'''

WIN_ROLLBACK = r'''# MoHe CTF v3.7.0 - Windows rollback script (GENERATED, NOT EXECUTED)
# Restores values captured by harden.ps1 in hardening_state.json.
$ErrorActionPreference = "Continue"
$stateFile = Join-Path $PSScriptRoot "hardening_state.json"
$auditBackup = Join-Path $PSScriptRoot "audit_backup.csv"
if (-not (Test-Path $stateFile)) { Write-Error "Missing $stateFile"; exit 1 }
$state = Get-Content $stateFile -Raw | ConvertFrom-Json
if ($null -ne $state.GuestEnabled) {
  if ([bool]$state.GuestEnabled) { Enable-LocalUser -Name Guest -ErrorAction SilentlyContinue }
  else { Disable-LocalUser -Name Guest -ErrorAction SilentlyContinue }
}
if ($null -ne $state.SMB1) { Set-SmbServerConfiguration -EnableSMB1Protocol ([bool]$state.SMB1) -Force }
if ($null -ne $state.SmbSigning) { Set-SmbServerConfiguration -RequireSecuritySignature ([bool]$state.SmbSigning) -Force }
foreach ($p in @($state.Firewall)) {
  if ($null -ne $p) { Set-NetFirewallProfile -Profile $p.Name -Enabled ([bool]$p.Enabled) }
}
if ($null -ne $state.RDPNLA) { Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -Value ([int]$state.RDPNLA) }
if ($null -ne $state.UAC) { Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value ([int]$state.UAC) }
if ($state.SecEdit) {
  if ($state.SecEdit -match "MinimumPasswordLength\s*=\s*(\d+)") { net accounts /minpwlen:$($matches[1]) | Out-Null }
  if ($state.SecEdit -match "LockoutBadCount\s*=\s*(\d+)") { net accounts /lockoutthreshold:$($matches[1]) | Out-Null }
  if ($state.SecEdit -match "MaximumPasswordAge\s*=\s*(\d+)") { net accounts /maxpwage:$($matches[1]) | Out-Null }
}
if (Test-Path $auditBackup) { auditpol /restore /file:"$auditBackup" | Out-Null }
$p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (Test-Path $p) { Remove-ItemProperty -Path $p -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue }
Write-Host "Rollback completed. Reboot may be required for UAC."
'''

LINUX_HARDEN = r'''#!/usr/bin/env bash
# MoHe CTF v3.7.0 - Linux hardening script (GENERATED, NOT EXECUTED)
# Review before running as root on the target host. Creates a backup directory.
set -euo pipefail
BACKUP_DIR="/var/backups/mohe-hardening-$(date +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR"
backup() { if [ -e "$1" ]; then cp -a "$1" "$BACKUP_DIR/$(basename "$1")"; fi; }
backup /etc/ssh/sshd_config
backup /etc/login.defs
backup /etc/sudoers
echo "Backup directory: $BACKUP_DIR"

# SSH hardening
if [ -f /etc/ssh/sshd_config ]; then
  sed -i -E 's/^[#[:space:]]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  grep -qi '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
  sed -i -E 's/^[#[:space:]]*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
  grep -qi '^PermitEmptyPasswords' /etc/ssh/sshd_config || echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config
  sed -i -E 's/^[#[:space:]]*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config
  grep -qi '^MaxAuthTries' /etc/ssh/sshd_config || echo 'MaxAuthTries 4' >> /etc/ssh/sshd_config
  chmod 600 /etc/ssh/sshd_config
  if command -v sshd >/dev/null 2>&1; then sshd -t; fi
  systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service ssh reload 2>/dev/null || true
fi

# Password aging
if [ -f /etc/login.defs ]; then
  sed -i -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
  sed -i -E 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
  sed -i -E 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 12/' /etc/login.defs
  sed -i -E 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
fi

# Kernel sysctl (separate file so rollback can remove it cleanly)
cat > /etc/sysctl.d/99-mohe-hardening.conf <<'EOF'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
sysctl --system >/dev/null 2>&1 || true

# Audit rules (only if auditd rules directory exists)
if [ -d /etc/audit/rules.d ]; then
  cat > /etc/audit/rules.d/99-mohe-hardening.rules <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-a always,exit -F arch=b64 -S execve -k exec
EOF
  augenrules --load 2>/dev/null || true
fi

# File permissions
chmod 640 /etc/shadow /etc/gshadow 2>/dev/null || true
chmod 440 /etc/sudoers 2>/dev/null || true
echo "Hardening completed. Review services and firewall separately."
'''

LINUX_ROLLBACK = r'''#!/usr/bin/env bash
# MoHe CTF v3.7.0 - Linux rollback script (GENERATED, NOT EXECUTED)
# Usage: sudo ./rollback_linux.sh [backup_dir]
set -euo pipefail
BACKUP_DIR="${1:-$(ls -dt /var/backups/mohe-hardening-* 2>/dev/null | head -1)}"
if [ -z "${BACKUP_DIR:-}" ] || [ ! -d "$BACKUP_DIR" ]; then
  echo "Usage: $0 <backup_dir>" >&2
  exit 1
fi
restore() { if [ -f "$BACKUP_DIR/$(basename "$1")" ]; then cp -a "$BACKUP_DIR/$(basename "$1")" "$1"; fi; }
restore /etc/ssh/sshd_config
restore /etc/login.defs
restore /etc/sudoers
rm -f /etc/sysctl.d/99-mohe-hardening.conf /etc/audit/rules.d/99-mohe-hardening.rules
sysctl --system >/dev/null 2>&1 || true
augenrules --load 2>/dev/null || true
systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service ssh reload 2>/dev/null || true
echo "Rollback completed from $BACKUP_DIR"
'''


def _validate_ps1(path):
    ps = _powershell()
    if not ps:
        return {"ok": None, "note": "powershell 不可用，跳过语法校验"}
    escaped = path.replace("'", "''")
    cmd = ("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::"
           "ParseFile('%s',[ref]$t,[ref]$e); if($e -and $e.Count){"
           "$e | ForEach-Object { Write-Output $_.Message }; exit 1}" % escaped)
    run = util.run_cmd([ps, "-NoProfile", "-ExecutionPolicy", "Bypass",
                        "-Command", cmd], timeout=60)
    return {"ok": run["rc"] == 0, "rc": run["rc"],
            "stderr": util.short(run["stderr"], 400)}


def _validate_sh(path):
    bash = util.which("bash")
    if not bash:
        return {"ok": None, "note": "bash 不可用，跳过语法校验"}
    run = util.run_cmd([bash, "-n", path], timeout=30)
    return {"ok": run["rc"] == 0, "rc": run["rc"],
            "stderr": util.short(run["stderr"], 400)}


def _write_scripts(outdir, result):
    scripts = {}
    for name, content, validator in (
            ("harden_windows.ps1", WIN_HARDEN, _validate_ps1),
            ("rollback_windows.ps1", WIN_ROLLBACK, _validate_ps1),
            ("harden_linux.sh", LINUX_HARDEN, _validate_sh),
            ("rollback_linux.sh", LINUX_ROLLBACK, _validate_sh)):
        path = util.save_text(outdir, name, content)
        util.add_artifact(result, path)
        chk = validator(path)
        result["data"].setdefault("script_checks", {})[name] = chk
        scripts[name] = path
    readme = (
        "MoHe CTF v3.7.0 baseline scripts (GENERATED ONLY)\n"
        "================================================\n"
        "These scripts were NOT executed by the analyzer.\n"
        "Review every command before use; run as Administrator/root on the target host.\n"
        "Windows: run harden_windows.ps1 first; it writes hardening_state.json and\n"
        "audit_backup.csv for rollback_windows.ps1.\n"
        "Linux: harden_linux.sh creates /var/backups/mohe-hardening-<timestamp>;\n"
        "rollback_linux.sh [backup_dir] restores the saved files and removes\n"
        "/etc/sysctl.d/99-mohe-hardening.conf and the audit rule file.\n"
        "No persistence, no anti-virus evasion, no credential changes.\n")
    path = util.save_text(outdir, "README_scripts.txt", readme)
    util.add_artifact(result, path)
    return scripts


def _render(result):
    data = result["data"]
    checks = data.get("checks") or []
    lines = ["# 系统安全与加固基线报告", ""]
    lines.append("- 平台：%s" % data.get("platform", ""))
    lines.append("- 目标：`%s`" % data.get("target", ""))
    lines.append("- 检查：%s 项，通过 %s，警告/失败 %s，未验证 %s" % (
        len(checks), len([c for c in checks if c["status"] == "pass"]),
        len([c for c in checks if c["status"] in ("warn", "fail")]),
        len([c for c in checks if c["status"] == "unverified"])))
    lines.append("")
    lines.append("## 检查项")
    lines.append("| 状态 | 检查项 | 证据 | 加固建议 |")
    lines.append("| --- | --- | --- | --- |")
    for c in checks:
        lines.append("| %s | %s | %s | %s |" % (
            c["status"], c["title"].replace("|", "/"),
            util.short(c["detail"].replace("\n", " / ").replace("|", "/"), 220),
            c["remediation"].replace("|", "/")))
    scripts = data.get("scripts") or {}
    if scripts:
        lines.append("")
        lines.append("## 生成脚本（未执行）")
        for name, path in scripts.items():
            chk = (data.get("script_checks") or {}).get(name) or {}
            lines.append("- `%s`：%s（语法校验=%s）" % (name, path, chk.get("ok")))
    lines.append("")
    lines.append("## 备注")
    for note in result["notes"]:
        lines.append("- %s" % note)
    return "\n".join(lines)


def analyze(target: str = "", outdir: str = "", platform: str = "auto",
            generate_scripts: bool = True, log=None) -> dict:
    """执行基线检查。target 为空时：Windows 查本机；Linux 查 /。"""
    log = log or (lambda m: None)
    outdir = outdir or util.case_dir("baseline", target or "localhost")
    result = util.make_result("baseline", outdir)
    result["data"]["target"] = os.path.abspath(target) if target else "localhost"
    plat = platform
    if plat == "auto":
        if os.name == "nt":
            plat = "windows"
        else:
            plat = "linux"
    result["data"]["platform"] = plat
    if plat == "windows":
        if os.name != "nt":
            _check(result, "win-platform", "Windows 检查", "unverified",
                   "当前系统不是 Windows，无法执行在线检查；可生成脚本模板",
                   "在 Windows 主机运行")
        else:
            log("[baseline] Windows 只读检查 ...")
            data = _run_windows_collector(outdir, result)
            _win_checks(data, result)
    else:
        root = _linux_root(target) if target else "/"
        log("[baseline] Linux 配置检查：%s" % (root or "未定位"))
        if not root:
            _check(result, "linux-root", "Linux 根文件系统", "unverified",
                   "未找到包含 etc/passwd 的 rootfs：%s" % target,
                   "把目标根分区挂载到目录后重试")
        else:
            _linux_checks(root, result)
    if generate_scripts:
        scripts = _write_scripts(outdir, result)
        result["data"]["scripts"] = scripts
        result["notes"].append("加固/回滚脚本已生成但未执行；执行前必须逐条复核。")
    result["notes"].append("基线检查只读取配置/状态，不修改系统；离线 Linux 检查不确认运行态。")
    checks = result["data"].get("checks") or []
    result["summary"] = "%s 基线：%s 项，告警/失败 %s，未验证 %s" % (
        plat, len(checks), len([c for c in checks if c["status"] in ("warn", "fail")]),
        len([c for c in checks if c["status"] == "unverified"]))
    return util.finish(result, _render(result))
