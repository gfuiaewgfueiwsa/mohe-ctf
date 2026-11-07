# -*- coding: utf-8 -*-
"""移动应用取证：APK 清单审计、DEX/资源硬编码凭据、证书与私钥、jadx/apktool 接入。

内置二进制 AndroidManifest.xml（AXML）与 DEX 字符串解析，外部工具缺失时
仍能完成基础审计；jadx/apktool 仅做本地反编译，不联网。
"""
import base64
import hashlib
import json
import os
import re
import struct
import zipfile
import xml.etree.ElementTree as ET

from . import util

ANDROID_NS = "http://schemas.android.com/apk/res/android"

DANGEROUS_PERMS = {
    "android.permission.READ_SMS": "读取短信",
    "android.permission.RECEIVE_SMS": "接收短信",
    "android.permission.SEND_SMS": "发送短信",
    "android.permission.READ_CONTACTS": "读取联系人",
    "android.permission.WRITE_CONTACTS": "写联系人",
    "android.permission.READ_CALL_LOG": "读取通话记录",
    "android.permission.WRITE_CALL_LOG": "写通话记录",
    "android.permission.CALL_PHONE": "直接拨号",
    "android.permission.CAMERA": "相机",
    "android.permission.RECORD_AUDIO": "录音",
    "android.permission.ACCESS_FINE_LOCATION": "精确定位",
    "android.permission.ACCESS_COARSE_LOCATION": "粗略定位",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "后台定位",
    "android.permission.READ_PHONE_STATE": "读取设备信息",
    "android.permission.READ_PHONE_NUMBERS": "读取手机号",
    "android.permission.READ_EXTERNAL_STORAGE": "读外部存储",
    "android.permission.WRITE_EXTERNAL_STORAGE": "写外部存储",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "管理全部文件",
    "android.permission.BODY_SENSORS": "身体传感器",
    "android.permission.REQUEST_INSTALL_PACKAGES": "安装应用",
    "android.permission.SYSTEM_ALERT_WINDOW": "悬浮窗",
    "android.permission.PACKAGE_USAGE_STATS": "应用使用统计",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "无障碍服务",
    "android.permission.BIND_DEVICE_ADMIN": "设备管理器",
}

KNOWN_RES = {
    0x01010003: "name", 0x01010006: "permission", 0x01010009: "protectionLevel",
    0x0101000f: "debuggable", 0x01010010: "exported", 0x01010018: "authorities",
    0x0101001b: "grantUriPermissions", 0x01010024: "value", 0x01010025: "resource",
    0x01010027: "scheme", 0x01010028: "host", 0x01010202: "targetActivity",
    0x0101020c: "minSdkVersion", 0x01010270: "targetSdkVersion",
    0x01010280: "allowBackup", 0x010104ec: "usesCleartextTraffic",
    0x01010527: "networkSecurityConfig",
}

SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret|client[_-]?secret|password|passwd|pwd|"
    r"access[_-]?key|auth[_-]?token|token)\b\s*[:=]\s*[\"']([^\"'\r\n]{4,160})[\"']")
URL_RE = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,240}")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
GOOGLE_KEY_RE = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]{32,}?"
    r"-----END (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                   r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def _uleb(data, pos):
    result = 0
    shift = 0
    while pos < len(data) and shift < 35:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7f) << shift
        if not byte & 0x80:
            break
        shift += 7
    return result, pos


def _string_pool(chunk):
    if len(chunk) < 28:
        return []
    count, _styles, flags, strings_start, _styles_start = struct.unpack_from(
        "<IIIII", chunk, 8)
    utf8 = bool(flags & 0x100)
    offsets = []
    for i in range(min(count, 200000)):
        pos = 28 + i * 4
        if pos + 4 > len(chunk):
            break
        offsets.append(struct.unpack_from("<I", chunk, pos)[0])
    strings = []
    for off in offsets:
        pos = strings_start + off
        if pos >= len(chunk):
            strings.append("")
            continue
        try:
            if utf8:
                # UTF-8 池：u16 字符数（varint）+ u8 字节数（varint）
                _, pos = _uleb(chunk, pos)
                byte_len, pos = _uleb(chunk, pos)
                strings.append(chunk[pos:pos + byte_len].decode("utf-8", "replace"))
            else:
                length = struct.unpack_from("<H", chunk, pos)[0]
                pos += 2
                if length & 0x8000:
                    length = ((length & 0x7fff) << 16) | struct.unpack_from(
                        "<H", chunk, pos)[0]
                    pos += 2
                strings.append(chunk[pos:pos + length * 2].decode(
                    "utf-16-le", "replace"))
        except Exception:
            strings.append("")
    return strings


def _typed_value(data_type, data, strings, raw):
    if raw != 0xFFFFFFFF and raw < len(strings):
        return strings[raw]
    if data_type == 0x03:
        return strings[data] if data < len(strings) else ""
    if data_type == 0x01:
        return "@0x%08x" % data
    if data_type == 0x02:
        return "?0x%08x" % data
    if data_type in (0x10, 0x11):
        return str(data)
    if data_type == 0x12:
        return "true" if data else "false"
    if data_type == 0x04:
        return str(struct.unpack("<f", struct.pack("<I", data))[0])
    if data_type in (0x05, 0x06):
        return "0x%08x" % data
    if data_type == 0x00:
        return ""
    return str(data)


def parse_axml(data):
    """解析二进制 AndroidManifest.xml，返回与 ET 兼容的 dict 树。"""
    if len(data) < 8 or struct.unpack_from("<H", data, 0)[0] != 0x0003:
        return None
    strings = []
    resmap = []
    root = None
    stack = []
    pos = 8
    while pos + 8 <= len(data):
        ctype, header_size, size = struct.unpack_from("<HHI", data, pos)
        if size < 8 or pos + size > len(data):
            break
        chunk = data[pos:pos + size]
        if ctype == 0x0001:
            strings = _string_pool(chunk)
        elif ctype == 0x0180:
            count = (size - header_size) // 4
            resmap = list(struct.unpack_from("<%dI" % count, chunk, header_size)) \
                if count > 0 else []
        elif ctype == 0x0102:
            line = struct.unpack_from("<I", chunk, 8)[0]
            name_idx = struct.unpack_from("<I", chunk, 20)[0]
            tag = strings[name_idx] if name_idx < len(strings) else ""
            attr_start = struct.unpack_from("<H", chunk, 24)[0]
            attr_size = struct.unpack_from("<H", chunk, 26)[0] or 20
            attr_count = struct.unpack_from("<H", chunk, 28)[0]
            attrs = {}
            base = 16 + attr_start
            for i in range(attr_count):
                off = base + i * attr_size
                if off + 20 > len(chunk):
                    break
                ns_idx, nm_idx, raw = struct.unpack_from("<III", chunk, off)
                vtype = chunk[off + 15]
                vdata = struct.unpack_from("<I", chunk, off + 16)[0]
                name = strings[nm_idx] if nm_idx < len(strings) else ""
                ns = strings[ns_idx] if ns_idx < len(strings) else ""
                rid = resmap[nm_idx] if nm_idx < len(resmap) else 0
                if not name and rid in KNOWN_RES:
                    name = KNOWN_RES[rid]
                key = ("android:" + name
                       if (ns.endswith("/android") or rid in KNOWN_RES) and name
                       else name)
                attrs[key] = _typed_value(vtype, vdata, strings, raw)
            elem = {"tag": tag, "attrs": attrs, "children": [], "line": line}
            if stack:
                stack[-1]["children"].append(elem)
            elif root is None:
                root = elem
            stack.append(elem)
        elif ctype == 0x0103:
            if stack:
                stack.pop()
        pos += size
    return root


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def parse_text_manifest(text):
    try:
        root = ET.fromstring(text)
    except Exception:
        return None

    def conv(elem):
        attrs = {}
        for key, value in elem.attrib.items():
            if key.startswith("{" + ANDROID_NS + "}"):
                attrs["android:" + key.rsplit("}", 1)[-1]] = value
            else:
                attrs[_local(key)] = value
        return {"tag": _local(elem.tag), "attrs": attrs,
                "children": [conv(c) for c in list(elem)], "line": 0}
    return conv(root)


def _walk(node, tag=None):
    if not node:
        return
    if tag is None or node.get("tag") == tag:
        yield node
    for child in node.get("children") or []:
        yield from _walk(child, tag)


def _first(node, tag):
    return next(_walk(node, tag), None)


def _int(value, default=0):
    try:
        return int(str(value), 0)
    except Exception:
        return default


def _bool(value):
    return str(value).lower() in ("true", "1")


def audit_manifest(manifest, result):
    if not manifest:
        util.add(result, "warn", "AndroidManifest.xml 解析失败",
                 "不是有效的文本/二进制 AXML 清单")
        return {}
    attrs = manifest.get("attrs") or {}
    sdk = _first(manifest, "uses-sdk") or {}
    sdk_attrs = sdk.get("attrs") or {}
    package = attrs.get("package", "")
    min_sdk = _int(sdk_attrs.get("android:minSdkVersion", attrs.get(
        "android:minSdkVersion", 0)))
    target_sdk = _int(sdk_attrs.get("android:targetSdkVersion", attrs.get(
        "android:targetSdkVersion", min_sdk)))
    info = {
        "package": package,
        "version_name": attrs.get("android:versionName", ""),
        "version_code": attrs.get("android:versionCode", ""),
        "min_sdk": min_sdk, "target_sdk": target_sdk,
        "permissions": [], "dangerous_permissions": [],
        "custom_permissions": [], "components": [],
    }
    for node in _walk(manifest):
        if node.get("tag") in ("uses-permission", "uses-permission-sdk-23"):
            name = (node.get("attrs") or {}).get("android:name", "")
            if name and name not in info["permissions"]:
                info["permissions"].append(name)
                if name in DANGEROUS_PERMS:
                    info["dangerous_permissions"].append({
                        "name": name, "label": DANGEROUS_PERMS[name]})
        elif node.get("tag") == "permission":
            a = node.get("attrs") or {}
            info["custom_permissions"].append({
                "name": a.get("android:name", ""),
                "protection": a.get("android:protectionLevel", ""),
            })
    app = _first(manifest, "application") or {}
    app_attrs = app.get("attrs") or {}
    info["application"] = {
        "debuggable": _bool(app_attrs.get("android:debuggable", "false")),
        "allow_backup": _bool(app_attrs.get("android:allowBackup", "true")),
        "cleartext": _bool(app_attrs.get("android:usesCleartextTraffic", "false")),
        "network_security_config": app_attrs.get(
            "android:networkSecurityConfig", ""),
        "theme": app_attrs.get("android:theme", ""),
    }
    for node in (app.get("children") or []):
        tag = node.get("tag")
        if tag not in ("activity", "activity-alias", "service", "receiver", "provider"):
            continue
        a = node.get("attrs") or {}
        filters = [c for c in (node.get("children") or [])
                   if c.get("tag") == "intent-filter"]
        explicit = a.get("android:exported")
        exported = _bool(explicit) if explicit is not None else bool(filters)
        permission = a.get("android:permission", "")
        actions, categories, schemes = [], [], []
        for flt in filters:
            for c in flt.get("children") or []:
                ca = c.get("attrs") or {}
                if c.get("tag") == "action":
                    actions.append(ca.get("android:name", ""))
                elif c.get("tag") == "category":
                    categories.append(ca.get("android:name", ""))
                elif c.get("tag") == "data":
                    for key in ("android:scheme", "android:host",
                                "android:mimeType", "android:path"):
                        if ca.get(key):
                            schemes.append("%s=%s" % (key.split(":")[-1], ca[key]))
        comp = {
            "type": tag, "name": a.get("android:name", ""),
            "exported": exported, "explicit": explicit,
            "permission": permission,
            "intent_filters": len(filters),
            "actions": [x for x in actions if x],
            "categories": [x for x in categories if x],
            "data": sorted(set(schemes)),
        }
        if tag == "provider":
            comp["authorities"] = a.get("android:authorities", "")
            comp["grant_uri_permissions"] = _bool(
                a.get("android:grantUriPermissions", "false"))
        info["components"].append(comp)
    result["data"]["manifest"] = info
    if package:
        util.add(result, "info", "APK 基本信息",
                 "package=%s version=%s(%s) minSdk=%s targetSdk=%s" % (
                     package, info["version_name"], info["version_code"],
                     min_sdk, target_sdk))
    if info["permissions"]:
        util.add(result, "info", "声明权限 %d 个" % len(info["permissions"]),
                 "\n".join(info["permissions"][:80]))
    if info["dangerous_permissions"]:
        util.add(result, "warn", "危险权限 %d 个" % len(info["dangerous_permissions"]),
                 "\n".join("%s（%s）" % (p["name"], p["label"])
                           for p in info["dangerous_permissions"]))
    app_flags = info["application"]
    issues = []
    if app_flags["debuggable"]:
        issues.append("android:debuggable=true（可调试，允许 JDWP 附加）")
    if app_flags["allow_backup"]:
        issues.append("android:allowBackup=true（adb backup 可能导出私有数据）")
    if app_flags["cleartext"]:
        issues.append("android:usesCleartextTraffic=true（允许明文 HTTP）")
    if issues:
        util.add(result, "warn", "Application 安全配置风险", "\n".join(issues))
    exported = [c for c in info["components"] if c["exported"]]
    risky = [c for c in exported if not c["permission"]]
    if exported:
        util.add(result, "warn", "导出组件 %d 个（其中无权限保护 %d 个）" % (
            len(exported), len(risky)),
            "\n".join("%s %s filters=%s actions=%s permission=%s" % (
                c["type"], c["name"], c["intent_filters"],
                ",".join(c["actions"][:4]) or "-", c["permission"] or "-")
                for c in exported[:40]))
    providers = [c for c in info["components"] if c["type"] == "provider"]
    for comp in providers:
        if comp["exported"] and comp.get("grant_uri_permissions"):
            util.add(result, "warn", "导出 Provider 允许 URI 授权：%s" % comp["name"],
                     "authorities=%s" % comp.get("authorities", ""))
    return info


def _dex_strings(data, limit=300000):
    if data[:4] != b"dex\n" or len(data) < 0x70:
        return []
    count = struct.unpack_from("<I", data, 0x38)[0]
    off = struct.unpack_from("<I", data, 0x3c)[0]
    strings = []
    for i in range(min(count, limit)):
        pos = off + i * 4
        if pos + 4 > len(data):
            break
        sdata = struct.unpack_from("<I", data, pos)[0]
        if sdata >= len(data):
            continue
        try:
            _size, p = _uleb(data, sdata)
            end = data.find(b"\x00", p)
            if end < 0:
                end = min(len(data), p + 4096)
            strings.append(data[p:end].decode("utf-8", "replace"))
        except Exception:
            continue
    return strings


def scan_text(text, result, source, found):
    """扫描一段文本，记录凭据/密钥/URL/JWT/flag，返回命中的敏感项。"""
    hits = []
    for match in SECRET_RE.finditer(text):
        key, value = match.group(1), match.group(2)
        if value.lower() in ("true", "false", "null", "none", "password"):
            continue
        item = {"type": "secret", "key": key, "value": value[:160],
                "source": source}
        if item not in found["secrets"]:
            found["secrets"].append(item)
            hits.append(item)
    for match in JWT_RE.finditer(text):
        item = {"type": "jwt", "value": match.group(0)[:240], "source": source}
        if item not in found["jwts"]:
            found["jwts"].append(item)
            hits.append(item)
    for regex, label in ((GOOGLE_KEY_RE, "google-api-key"),
                         (AWS_KEY_RE, "aws-access-key")):
        for match in regex.finditer(text):
            item = {"type": label, "value": match.group(0), "source": source}
            if item not in found["keys"]:
                found["keys"].append(item)
                hits.append(item)
    for match in PRIVATE_KEY_RE.finditer(text):
        item = {"type": "private-key", "source": source,
                "sha256": hashlib.sha256(match.group(0).encode()).hexdigest(),
                "size": len(match.group(0))}
        if item not in found["private_keys"]:
            found["private_keys"].append(item)
            hits.append(item)
    for match in URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;)\"'")
        if url not in found["urls"] and len(found["urls"]) < 1000:
            found["urls"].append(url)
    for match in IP_RE.finditer(text):
        ip = match.group(0)
        if ip not in ("0.0.0.0", "127.0.0.1") and ip not in found["ips"]:
            found["ips"].append(ip)
    for flag in util.flag_scan(text, source, result):
        if flag not in found["flags"]:
            found["flags"].append(flag)
    return hits


def _cert_info(cert, source):
    try:
        before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        pub = cert.public_key()
        info = {
            "source": source,
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial": hex(cert.serial_number),
            "not_before": str(before), "not_after": str(after),
            "signature": cert.signature_hash_algorithm.name
            if cert.signature_hash_algorithm else "",
            "sha256": cert.fingerprint(__import__(
                "cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256()).hex(),
            "key_type": type(pub).__name__,
            "key_size": getattr(pub, "key_size", ""),
        }
        text = info["subject"] + " " + info["issuer"]
        info["debug_cert"] = "Android Debug" in text or "CN=Android Debug" in text
        return info
    except Exception as exc:
        return {"source": source, "error": str(exc)}


def _load_certs(data, source):
    certs = []
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
        for cert in pkcs7.load_der_pkcs7_certificates(data) or []:
            certs.append(_cert_info(cert, source))
    except Exception:
        pass
    if certs:
        return certs
    try:
        from cryptography import x509
        for loader in (x509.load_der_x509_certificate, x509.load_pem_x509_certificate):
            try:
                certs.append(_cert_info(loader(data), source))
                break
            except Exception:
                continue
    except Exception:
        pass
    return certs


def _scan_zip_entries(zf, outdir, result, found):
    text_exts = (".txt", ".json", ".xml", ".properties", ".pem", ".key",
                 ".crt", ".cer", ".conf", ".config", ".yml", ".yaml", ".html",
                 ".js", ".sql", ".ini", ".csv")
    entries = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        name = info.filename
        lower = name.lower()
        if lower.startswith(("assets/", "res/raw/", "meta-inf/")) and (
                lower.endswith(text_exts)) and info.file_size <= 2 * 1024 * 1024:
            try:
                blob = zf.read(info)
            except Exception:
                continue
            if blob[:4] == b"\x03\x00\x08\x00":
                continue
            text = blob.decode("utf-8", "replace")
            path = util.save_bytes(outdir, "apk_entries/" + name, blob)
            util.add_artifact(result, path)
            entries.append(name)
            scan_text(text, result, "APK 条目 %s" % name, found)
        elif lower.endswith((".so", ".dex")) and info.file_size <= 16 * 1024 * 1024:
            try:
                blob = zf.read(info)
            except Exception:
                continue
            for flag in util.flag_scan(blob, "APK 二进制 %s" % name, result):
                if flag not in found["flags"]:
                    found["flags"].append(flag)
    return entries


def _run_jadx(apk, outdir, result, log):
    jadx = util.find_jadx()
    out = os.path.join(outdir, "jadx")
    result["data"]["jadx"] = {"path": jadx, "output": out, "ran": False}
    if not jadx:
        result["notes"].append(
            "未找到 jadx：可从 https://github.com/skylot/jadx/releases 下载，"
            "解压到 tools/portable/jadx（约 40 MB，需 JRE；随包 JRE 会被自动使用）。")
        return ""
    args = [jadx, "--no-res", "-d", out, apk]
    if jadx.lower().endswith((".bat", ".cmd")):
        args = ["cmd", "/c"] + args
    log("[mobile] jadx 反编译 ...")
    run = util.run_cmd(args, timeout=600, env=util.jadx_env())
    result["data"]["jadx"].update({"ran": True, "rc": run["rc"],
                                   "elapsed": run["elapsed"],
                                   "stderr": util.short(run["stderr"], 500)})
    if run["rc"] != 0:
        result["notes"].append("jadx 失败（rc=%s）：%s" % (
            run["rc"], util.short(run["stderr"], 300)))
    return out if os.path.isdir(out) else ""


def _run_apktool(apk, outdir, result, log):
    apktool = util.find_apktool()
    out = os.path.join(outdir, "apktool")
    result["data"]["apktool"] = {"path": apktool, "output": out, "ran": False}
    if not apktool:
        result["notes"].append(
            "未找到 apktool：可下载 apktool.jar（约 20 MB）放到 "
            "tools/portable/apktool；已用内置 AXML 解析清单。")
        return ""
    if apktool.lower().endswith(".jar"):
        args = ["java", "-jar", apktool, "d", "-f", "-o", out, apk]
    else:
        args = [apktool, "d", "-f", "-o", out, apk]
        if apktool.lower().endswith((".bat", ".cmd")):
            args = ["cmd", "/c"] + args
    log("[mobile] apktool 反编译 ...")
    run = util.run_cmd(args, timeout=600, env=util.jadx_env())
    result["data"]["apktool"].update({"ran": True, "rc": run["rc"],
                                      "elapsed": run["elapsed"],
                                      "stderr": util.short(run["stderr"], 500)})
    if run["rc"] != 0:
        result["notes"].append("apktool 失败（rc=%s）：%s" % (
            run["rc"], util.short(run["stderr"], 300)))
    return out if os.path.isdir(out) else ""


def _scan_dir(directory, result, found, exts, limit=3000):
    for path in util.iter_artifacts(directory, exts=exts, max_files=limit):
        try:
            text = util.read_text(path, 1024 * 1024)
        except Exception:
            continue
        scan_text(text, result, os.path.relpath(path, directory), found)


def _render(result):
    data = result["data"]
    lines = ["# APK 取证报告", ""]
    lines.append("- 文件：`%s`" % data.get("apk", ""))
    lines.append("- 大小：%s" % data.get("apk_size_text", ""))
    manifest = data.get("manifest") or {}
    if manifest:
        lines.append("- 包名：%s，版本：%s(%s)，minSdk=%s targetSdk=%s" % (
            manifest.get("package"), manifest.get("version_name"),
            manifest.get("version_code"), manifest.get("min_sdk"),
            manifest.get("target_sdk")))
        lines.append("- 权限：%s 个（危险 %s 个），导出组件：%s 个" % (
            len(manifest.get("permissions") or []),
            len(manifest.get("dangerous_permissions") or []),
            len([c for c in manifest.get("components") or [] if c.get("exported")])))
    for label, key in (("证书", "certs"), ("应用条目", "entries")):
        items = data.get(key) or []
        if items:
            lines.append("- %s：%s 个" % (label, len(items)))
    lines.append("")
    lines.append("## 发现")
    for item in result["findings"]:
        lines.append("- [%s] %s" % (item["level"], item["title"]))
        if item["detail"]:
            for line in item["detail"].splitlines()[:20]:
                lines.append("  - %s" % line)
    certs = data.get("certs") or []
    if certs:
        lines.append("")
        lines.append("## 签名证书")
        for cert in certs:
            lines.append("- %s：subject=`%s` issuer=`%s` SHA256=`%s`%s" % (
                cert.get("source"), cert.get("subject", ""),
                cert.get("issuer", ""), cert.get("sha256", ""),
                "（Debug 证书）" if cert.get("debug_cert") else ""))
    secrets = data.get("secrets") or []
    if secrets:
        lines.append("")
        lines.append("## 硬编码敏感项")
        for item in secrets[:40]:
            lines.append("- %s: %s = `%s`（%s）" % (
                item.get("type"), item.get("key", ""),
                util.short(item.get("value", ""), 120), item.get("source", "")))
    if data.get("urls"):
        lines.append("")
        lines.append("## URL（前 40）")
        for url in data["urls"][:40]:
            lines.append("- %s" % url)
    lines.append("")
    lines.append("## 工具")
    for name in ("jadx", "apktool"):
        info = data.get(name) or {}
        lines.append("- %s：%s（ran=%s）%s" % (
            name, info.get("path") or "未找到", info.get("ran"),
            info.get("output") or ""))
    lines.append("")
    lines.append("## 备注")
    for note in result["notes"]:
        lines.append("- %s" % note)
    return "\n".join(lines)


def analyze(apk: str, outdir: str = "", decompile="auto", apktool: bool = False,
            log=None) -> dict:
    """分析 APK。decompile: auto/off/jadx；apktool=True 时额外跑 apktool。"""
    log = log or (lambda m: None)
    outdir = outdir or util.case_dir("mobile", apk)
    result = util.make_result("mobile", outdir)
    result["data"]["apk"] = os.path.abspath(apk)
    if not os.path.isfile(apk):
        result["ok"] = False
        util.add(result, "warn", "APK 文件不存在", apk)
        return util.finish(result, _render(result))
    result["data"]["apk_size_text"] = util.size_text(apk)
    found = {"secrets": [], "jwts": [], "keys": [], "private_keys": [],
             "urls": [], "ips": [], "flags": []}
    try:
        zf = zipfile.ZipFile(apk)
    except Exception as exc:
        result["ok"] = False
        util.add(result, "warn", "不是有效 ZIP/APK", str(exc))
        return util.finish(result, _render(result))

    names = zf.namelist()
    result["data"]["zip_entries"] = len(names)
    manifest_raw = b""
    if "AndroidManifest.xml" in names:
        manifest_raw = zf.read("AndroidManifest.xml")
        manifest = parse_axml(manifest_raw) or parse_text_manifest(
            manifest_raw.decode("utf-8", "replace"))
        util.save_bytes(outdir, "AndroidManifest.xml", manifest_raw)
        util.add_artifact(result, os.path.join(outdir, "artifacts", "AndroidManifest.xml"))
        audit_manifest(manifest, result)
    else:
        util.add(result, "warn", "APK 内没有 AndroidManifest.xml", "可能不是完整 APK")

    dex_strings = []
    for name in names:
        if name.lower().endswith(".dex"):
            try:
                data = zf.read(name)
            except Exception:
                continue
            if data[:4] != b"dex\n":
                continue
            dex_strings.extend(_dex_strings(data))
            util.flag_scan(data, "DEX %s" % name, result)
    result["data"]["dex_strings"] = len(dex_strings)
    if dex_strings:
        joined = "\n".join(dex_strings)
        path = util.save_text(outdir, "dex_strings.txt", joined[:12 * 1024 * 1024])
        util.add_artifact(result, path)
        scan_text(joined, result, "DEX 字符串", found)
        util.add(result, "info", "DEX 字符串 %d 条" % len(dex_strings),
                 "\n".join(x for x in dex_strings[:20] if x)[:2000])

    certs = []
    for name in names:
        lower = name.lower()
        if lower.startswith("meta-inf/") and lower.endswith((".rsa", ".dsa", ".ec", ".der", ".cer")):
            try:
                blob = zf.read(name)
            except Exception:
                continue
            util.save_bytes(outdir, "certs/" + os.path.basename(name), blob)
            util.add_artifact(result, os.path.join(
                outdir, "artifacts", "certs", os.path.basename(name)))
            certs.extend(_load_certs(blob, name))
    result["data"]["certs"] = certs
    if certs:
        util.add(result, "info", "签名证书 %d 张" % len(certs),
                 "\n".join("%s | %s | %s" % (
                     c.get("subject", ""), c.get("issuer", ""),
                     "DEBUG" if c.get("debug_cert") else "release")
                     for c in certs))
        for cert in certs:
            if cert.get("debug_cert"):
                util.add(result, "warn", "APK 使用 Android Debug 证书签名",
                         "可被同包名替换/调试，发布包不应使用 debug 签名")
    else:
        util.add(result, "info", "未解析到签名证书",
                 "META-INF 中缺少 CERT.RSA/DSA/EC，或使用了 v2/v3 签名方案")

    entries = _scan_zip_entries(zf, outdir, result, found)
    result["data"]["entries"] = entries
    # 资源 XML 也可能是文本（未编译），补扫
    for name in names:
        if name.startswith("res/") and name.lower().endswith(".xml") and \
                name not in entries:
            try:
                blob = zf.read(name)
            except Exception:
                continue
            if blob[:4] == b"\x03\x00\x08\x00" or len(blob) > 2 * 1024 * 1024:
                continue
            scan_text(blob.decode("utf-8", "replace"), result,
                      "资源 %s" % name, found)

    jadx_dir = apktool_dir = ""
    if decompile != "off":
        if decompile in ("auto", "jadx"):
            jadx_dir = _run_jadx(apk, outdir, result, log)
            if jadx_dir:
                _scan_dir(jadx_dir, result, found, (".java", ".kt", ".xml", ".json"))
                util.add_artifact(result, jadx_dir)
        if apktool:
            apktool_dir = _run_apktool(apk, outdir, result, log)
            if apktool_dir:
                _scan_dir(apktool_dir, result, found, (".smali", ".xml", ".yml", ".json"))
                util.add_artifact(result, apktool_dir)

    result["data"].update({
        "secrets": found["secrets"], "jwts": found["jwts"], "keys": found["keys"],
        "private_keys": found["private_keys"], "urls": found["urls"],
        "ips": found["ips"], "flags": found["flags"],
        "jadx_output": jadx_dir, "apktool_output": apktool_dir,
    })
    if found["secrets"]:
        util.add(result, "warn", "硬编码凭据/密钥 %d 项" % len(found["secrets"]),
                 "\n".join("%s = %s（%s）" % (
                     x.get("key"), util.short(x.get("value", ""), 120),
                     x.get("source", "")) for x in found["secrets"][:30]))
    if found["private_keys"]:
        util.add(result, "warn", "内置私钥 %d 个" % len(found["private_keys"]),
                 "\n".join("%s sha256=%s" % (x["source"], x["sha256"][:16])
                           for x in found["private_keys"][:10]))
    if found["jwts"]:
        util.add(result, "warn", "硬编码 JWT %d 个" % len(found["jwts"]),
                 "\n".join(x["value"][:160] for x in found["jwts"][:10]))
    if found["keys"]:
        util.add(result, "warn", "云服务 API Key %d 个" % len(found["keys"]),
                 "\n".join("%s = %s" % (x["type"], x["value"])
                           for x in found["keys"][:10]))
    if found["urls"]:
        util.add(result, "info", "硬编码 URL %d 个" % len(found["urls"]),
                 "\n".join(found["urls"][:30]))
    if found["ips"]:
        util.add(result, "info", "硬编码 IP %d 个" % len(found["ips"]),
                 "\n".join(found["ips"][:30]))
    result["summary"] = "APK %s，权限 %s，导出组件 %s，证书 %s，敏感项 %s，URL %s" % (
        (result["data"].get("manifest") or {}).get("package", "?"),
        len((result["data"].get("manifest") or {}).get("permissions") or []),
        len([c for c in (result["data"].get("manifest") or {}).get("components") or []
             if c.get("exported")]),
        len(certs), len(found["secrets"]) + len(found["keys"]) + len(found["private_keys"]),
        len(found["urls"]))
    if not result["notes"]:
        result["notes"].append("未发现 jadx/apktool 时仅做内置 AXML/DEX/资源解析；"
                               "反编译源码级审计需外部工具。")
    return util.finish(result, _render(result))


def enhance(apk, report, outdir):
    """把 APK 摘要并入常规文件分析报告。"""
    try:
        result = analyze(apk, os.path.join(outdir, "apk_deep"), decompile="off")
    except Exception as exc:
        report.add("info", "APK 深度分析跳过", str(exc)[:200])
        return None
    for item in result.get("findings") or []:
        report.add(item["level"], item["title"], item["detail"])
    for path in result.get("artifacts") or []:
        report.extracted.append(path)
    return result
