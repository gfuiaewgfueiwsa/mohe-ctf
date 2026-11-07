# -*- coding: utf-8 -*-
"""首层精准判型：先定主考点，再决定只跑哪些阶段与脚本。

设计原则：
  - 只读、轻量：最多采样文件头尾各 2 MB，不在此处跑重工具；
  - 证据优先：每个结论都带可复核的信号（扩展名/魔数/关键字/表单/序列化）；
  - 低置信回退：拿不准时给保守阶段，不假装确定；
  - 脚本选择与阶段绑定：scriptlib 只运行这里点名、且在白名单内的脚本。
"""
import os
import re
from dataclasses import dataclass, field
from typing import List
from urllib.parse import urlsplit

AUDIO_EXTS = (".wav", ".mp3", ".flac", ".ogg", ".au", ".aiff", ".aif", ".m4a",
              ".wma", ".ape", ".opus", ".amr", ".mid", ".midi")
VIDEO_EXTS = (".mp4", ".mov", ".mkv", ".webm", ".flv", ".avi", ".ts", ".m4v",
              ".wmv", ".3gp", ".mpg", ".mpeg", ".m2ts", ".ogv", ".rmvb")
IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif", ".tiff",
              ".ico", ".cur")
DISK_EXTS = (".vmdk", ".vhd", ".vhdx", ".vdi", ".ova", ".img", ".raw", ".dd", ".e01")
OFFICE_OLE_EXTS = (".doc", ".xls", ".ppt", ".msg", ".msi")

TEXT_ENCODING_WORDS = ("base64", "base32", "base58", "base85", "base91", "base100",
                       "hex", "十六进制", "rot13", "rot47", "凯撒", "caesar",
                       "维吉尼亚", "vigenere", "栅栏", "railfence", "培根", "bacon",
                       "摩斯", "morse", "url编码", "unicode", "jsfuck", "aaencode",
                       "编码", "解码", "密文", "cipher")
WEB_HINT_WORDS = ("上传", "upload", "登录", "login", "csrf", "sql", "注入", "injection",
                  "命令执行", "rce", "cmd", "反序列化", "unserialize", "pop", "phar",
                  "ssti", "模板", "文件包含", "lfi", "include", "ssrf", "xxe", "xml",
                  "xss", "jwt", "idor", "越权", "备份", "源码", "弱口令", "爆破")

SQL_PARAMS = {"id", "uid", "user", "userid", "user_id", "username", "uname", "pass",
              "password", "pwd", "query", "q", "search", "keyword", "order", "sort",
              "select", "table", "name", "cat", "category", "news", "article"}
CMD_PARAMS = {"cmd", "exec", "command", "shell", "run", "ping", "ip", "host",
              "domain", "target", "addr", "address"}
FILE_PARAMS = {"file", "filename", "path", "page", "include", "template", "view",
               "doc", "document", "load", "module", "dir", "folder", "upload"}
URL_PARAMS = {"url", "uri", "link", "src", "source", "dest", "destination",
              "redirect", "next", "fetch", "proxy", "xml", "feed", "callback"}
TOKEN_PARAMS = {"token", "jwt", "auth", "role", "admin", "user_id", "uid", "id",
                "account", "email"}


@dataclass
class Triage:
    kind: str = "file"
    category: str = "unknown"
    subtype: str = "unknown"
    confidence: float = 0.3
    evidence: List[str] = field(default_factory=list)
    stages: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    web_phases: List[dict] = field(default_factory=list)

    def to_dict(self):
        return {
            "kind": self.kind, "category": self.category, "subtype": self.subtype,
            "confidence": round(self.confidence, 2), "evidence": list(self.evidence),
            "stages": list(self.stages), "scripts": list(self.scripts),
            "skipped": list(self.skipped), "notes": list(self.notes),
            "web_phases": [dict(p) for p in self.web_phases],
        }

    def summary(self):
        ev = "；".join(self.evidence[:4]) or "无强信号"
        return "%s/%s 置信 %.2f（%s）" % (self.category, self.subtype,
                                         self.confidence, ev)


def _peek(path, size=2 * 1024 * 1024):
    try:
        with open(path, "rb") as fp:
            return fp.read(size)
    except Exception:
        return b""


def _tail(path, size=1024 * 1024):
    try:
        with open(path, "rb") as fp:
            fp.seek(0, os.SEEK_END)
            end = fp.tell()
            fp.seek(max(0, end - size))
            return fp.read()
    except Exception:
        return b""


def _decode_text(raw, limit=2 * 1024 * 1024):
    if not raw:
        return ""
    chunk = raw[:limit]
    for enc in ("utf-8", "gb18030", "utf-16"):
        try:
            return chunk.decode(enc)
        except Exception:
            continue
    return chunk.decode("utf-8", "ignore")


def _hint_text(hints, meta=None):
    parts = [str(h) for h in (hints or []) if h]
    for key in ("name", "category", "description"):
        value = (meta or {}).get(key)
        if value:
            parts.append(str(value))
    return "\n".join(parts)


def _uniq(items):
    return list(dict.fromkeys(items))


# ---------------------------------------------------------------- 文件判型
def file_triage(path: str, info: dict, raw: bytes = None,
                hints=None, meta=None) -> Triage:
    """根据识别结果与轻量采样，给出主考点、阶段序列和脚本清单。"""
    cat = (info or {}).get("category") or "unknown"
    ftype = (info or {}).get("ftype") or ""
    ext = ((info or {}).get("ext") or os.path.splitext(path)[1]).lower()
    size = int((info or {}).get("size") or 0)
    ent = float((info or {}).get("entropy") or 0.0)
    name = os.path.basename(path).lower()
    ht = _hint_text(hints, meta).lower()
    head = raw[:2 * 1024 * 1024] if raw else _peek(path)
    text = _decode_text(raw) if (info or {}).get("is_text") else ""

    t = Triage(kind="file", category=cat)

    def ev(item):
        if item not in t.evidence:
            t.evidence.append(item)

    def script(*ids):
        t.scripts = _uniq(t.scripts + [i for i in ids if i])

    def stage(*names):
        t.stages = _uniq(t.stages + [n for n in names if n])

    # ---------- 文本 ----------
    if cat == "text":
        t.subtype = "text_unknown"
        t.confidence = 0.55
        stage("strings", "codes")
        script("encode_decode_hub")
        if re.search(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[|\bunserialize\s*\(|\b(?:system|exec|shell_exec|passthru|assert)\s*\(", text):
            t.subtype = "web_source"
            t.confidence = 0.8
            ev("文本包含 PHP 源码/危险函数")
            stage("deep_text")
            t.stages = [s for s in t.stages if s != "codes"]
            if re.search(r"\bunserialize\s*\(", text):
                ev("源码出现 unserialize(")
            if re.search(r"\b(?:system|exec|shell_exec|passthru)\s*\(", text):
                ev("源码出现命令执行函数")
        if re.search(r"(?im)^\s*(?:n|e|c|p|q|dp|dq|d)\s*[:=]\s*[0-9a-fx]", text):
            params = len(re.findall(r"(?im)^\s*(?:n|e|c|p|q|dp|dq|d)\s*[:=]", text))
            if params >= 2 or "rsa" in ht:
                t.subtype = "rsa"
                t.confidence = 0.85
                ev("RSA 参数 %d 组" % max(params, 2))
                stage("rsa")
                script("rsa_all_in_one")
        if len(re.findall(r"\(\s*\d{2,}\s*,\s*\d{2,}\s*\)", text)) >= 8 or \
                ("椭圆" in ht or "ecc" in ht) and "p" in text:
            t.subtype = "ecc"
            t.confidence = 0.8
            ev("大量曲线坐标点/题面提示 ECC")
            stage("ecc")
        if re.search(r"\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}", text):
            t.subtype = "jwt" if t.subtype == "text_unknown" else t.subtype
            if t.subtype == "jwt":
                t.confidence = 0.8
            ev("发现 JWT")
            script("jwt_crack")
        stripped = re.sub(r"\s+", "", text)
        binary_rows = [ln.strip() for ln in text.splitlines()
                       if re.fullmatch(r"[01]{8,}", ln.strip())]
        if (32 <= len(stripped) <= 128 and len(binary_rows) < 8
                and re.fullmatch(r"[A-Fa-f0-9]+", stripped or "x")):
            if t.subtype == "text_unknown":
                t.subtype = "hash"
                t.confidence = 0.75
            ev("整段为纯十六进制（疑似哈希）")
            stage("hash")
            script("hash_identify")
        if re.search(r"[\u200b\u200c\u200d\u2060\ufe0f\ufeff]{8,}", text):
            t.subtype = "zero_width" if t.subtype == "text_unknown" else t.subtype
            t.confidence = max(t.confidence, 0.8)
            ev("出现成串零宽/不可见字符")
            script("zero_width_stego")
        if "异或" in ht or "xor" in ht or re.search(r"(?i)\bkey\s*[:=]\s*0x[0-9a-f]{1,4}", text):
            if t.subtype == "text_unknown":
                t.subtype = "xor"
                t.confidence = 0.7
            ev("题面/文本出现异或线索")
            stage("xor")
            script("xor_repeating_key", "xor_single_byte")
        if t.subtype == "text_unknown" and any(w in (ht + text.lower()) for w in TEXT_ENCODING_WORDS):
            t.subtype = "encoding"
            t.confidence = 0.6
            ev("出现编码/古典密码关键词")
            script("base_family_decode", "classical_crack", "vigenere_crack")
        # 无空白短文本：既可能是编码，也可能是单字节/重复密钥 XOR 密文；爆破成本低
        spaces = text.count(" ") + text.count("\n") + text.count("\t")
        if (t.subtype == "text_unknown" and 8 <= len(text) <= 4096
                and spaces <= max(1, len(text) // 20)
                and len(set(text)) >= 8
                and not re.search(r"(?i)flag\{|<\?php|^\s*(?:def|class|import)\b", text)):
            ev("无空白短文本，疑似 XOR/编码密文")
            stage("xor")
            script("xor_repeating_key", "xor_single_byte")
        if len(binary_rows) >= 8:
            ev("发现 %d 行 0/1 像素矩阵" % len(binary_rows))
            script("pixel_matrix_qr")
        if re.search(r"(?i)(?:access\.log|nginx|GET\s+\S+\s+HTTP/)", text[:200000]):
            ev("疑似访问日志（按纯文本检索线索）")
        return t

    # ---------- 压缩包 ----------
    if cat == "archive":
        sub = "zip" if head[:2] == b"PK" else "archive"
        t.subtype = sub
        t.confidence = 0.8
        stage("archive")
        members = []
        if head[:2] == b"PK":
            try:
                import zipfile
                with zipfile.ZipFile(path) as zf:
                    members = zf.namelist()[:2000]
                    encrypted = any(i.flag_bits & 0x1 for i in zf.infolist())
                    small_enc = encrypted and all(i.file_size <= 64 for i in zf.infolist())
                if encrypted:
                    ev("ZIP 成员已加密")
                    t.notes.append("ZIP 已加密：先用内置弱口令/CRC 套件，失败再人工字典")
                    if small_enc:
                        script("zip_crc_crack")
            except Exception:
                pass
        joined = "/".join(members).lower()
        if "word/document.xml" in joined:
            t.subtype = "docx"
            ev("ZIP 内含 word/document.xml")
            script("docx_hidden_extract")
        elif "xl/workbook.xml" in joined:
            t.subtype = "xlsx"
            ev("ZIP 内含 xl/workbook.xml")
            script("docx_hidden_extract")
        elif "ppt/presentation.xml" in joined:
            t.subtype = "pptx"
            ev("ZIP 内含 ppt/presentation.xml")
            script("docx_hidden_extract")
        elif "androidmanifest.xml" in joined:
            t.subtype = "apk"
            t.confidence = 0.9
            ev("ZIP 内含 AndroidManifest.xml")
            stage("deep_archive")
        elif "meta-inf/manifest.mf" in joined:
            t.subtype = "jar"
            ev("ZIP 内含 META-INF/MANIFEST.MF")
        if t.subtype == "zip" and any(
                k in joined for k in ("flag", "secret", "key", "password")):
            ev("成员名含 flag/secret/key")
        return t

    # ---------- 图片 ----------
    if cat == "image":
        t.subtype = "image"
        t.confidence = 0.85
        stage("stego_image")
        scripts = ["qrcode_decode", "exif_dump"]
        if ext == ".png" or head[:8] == b"\x89PNG\r\n\x1a\n":
            t.subtype = "png"
            scripts += ["lsb_stego_png", "png_ihdr_fix"]
        elif ext == ".gif" or head[:3] == b"GIF":
            t.subtype = "gif"
            scripts += ["gif_split_frames"]
        elif ext in (".jpg", ".jpeg") or head[:3] == b"\xff\xd8\xff":
            t.subtype = "jpeg"
        if "qr" in ht or "二维码" in ht or "qrcode" in name:
            t.subtype = "qr_image"
            t.confidence = 0.9
            ev("题面/文件名提示二维码")
            scripts = ["qrcode_decode"] + scripts
        ev("%s 图片" % t.subtype)
        script(*scripts)
        return t

    # ---------- 音频 / 视频 ----------
    if cat == "media":
        is_audio = ext in AUDIO_EXTS or b"WAVE" in head[:16] or head[:4] == b"fLaC" or head[:3] == b"ID3"
        is_video = (not is_audio) and (ext in VIDEO_EXTS or "视频" in ftype)
        if is_audio:
            t.subtype = "audio"
            t.confidence = 0.85
            ev("音频容器 %s" % (ext or ftype))
            stage("deep_audio")
            script("audio_spectrogram")
            if ext == ".wav" or b"WAVE" in head[:16]:
                script("audio_lsb_wav")
        elif is_video:
            t.subtype = "video"
            t.confidence = 0.8
            ev("视频容器 %s" % (ext or ftype))
            stage("deep_video")
        else:
            t.subtype = "media_unknown"
            t.confidence = 0.5
            stage("deep_audio", "deep_video")
        return t

    # ---------- 流量 ----------
    if cat == "capture":
        t.subtype = "pcap"
        t.confidence = 0.92
        ev("PCAP 魔数 %s" % head[:4].hex())
        stage("deep_traffic")
        candidate = head + _tail(path, 512 * 1024)
        low = candidate.lower()
        if b"usb" in low or "usb" in ht or "hid" in ht:
            t.subtype = "pcap_usb"
            ev("流量中出现 USB/HID 特征")
            script("usb_hid_keylog")
        if "dns" in ht or "域名" in ht or "隧道" in ht or "exfil" in ht:
            t.subtype = t.subtype if t.subtype != "pcap" else "pcap_dns"
            script("pcap_dns_exfil")
        script("pcap_http_extract")
        return t

    # ---------- 取证 ----------
    if cat == "forensic":
        t.confidence = 0.85
        if head[:4] == b"regf" or name in ("sam", "system", "software", "security",
                                           "ntuser.dat") or "ntuser" in name:
            t.subtype = "registry"
            ev("Windows 注册表 hive")
            stage("deep_forensic")
            script("registry_hive_parse")
        elif head[:8] == b"ElfFile\x00" or ext == ".evtx":
            t.subtype = "evtx"
            ev("Windows 事件日志 evtx")
            stage("deep_forensic")
            script("evtx_deep_parse")
        elif ext == ".asar" or head[:4] == b"\x04\x00\x00\x00":
            t.subtype = "asar"
            ev("Electron ASAR")
            stage("deep_forensic")
        elif ext in (".swp", ".swo", ".swn") or head[:6] == b"b0VIM ":
            t.subtype = "vim_swap"
            ev("vim swap")
            stage("deep_forensic")
        elif ext in DISK_EXTS or "磁盘" in ht or "镜像" in ht or "内存" in ht:
            t.subtype = "disk_image"
            ev("磁盘/内存镜像")
            stage("deep_forensic")
        else:
            t.subtype = "forensic_unknown"
            stage("deep_forensic")
        return t

    # ---------- 文档 ----------
    if cat == "document":
        t.confidence = 0.85
        if head[:4] == b"%PDF" or ext == ".pdf":
            t.subtype = "pdf"
            ev("PDF 文档")
            stage("deep_document")
            script("pdf_hidden_extract")
        elif ext in OFFICE_OLE_EXTS or head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            t.subtype = "office_ole"
            ev("OLE 复合文档")
            stage("deep_document")
        else:
            t.subtype = "document_unknown"
            stage("deep_document")
        return t

    # ---------- 数据库 ----------
    if cat == "database":
        t.subtype = "sqlite"
        t.confidence = 0.92
        ev("SQLite 魔数")
        stage("deep_database")
        return t

    # ---------- 密钥 / 加密容器 ----------
    if cat == "crypto":
        t.subtype = "pem" if head.startswith(b"-----BEGIN") else "crypto_artifact"
        t.confidence = 0.75
        ev("PEM/加密容器特征")
        stage("deep_crypto")
        return t

    # ---------- 可执行 ----------
    if cat == "executable":
        t.confidence = 0.8
        if ext in (".pyc", ".pyo") or head[:2] in (b"\x42\x0d", b"\x55\x0d", b"\x6f\x0d",
                                                   b"\xa7\x0d", b"\xcb\x0d", b"\xee\x0c"):
            t.subtype = "pyc"
            t.confidence = 0.92
            ev("Python 字节码")
            stage("deep_reverse")
            script("pyc_magic_repair")
            return t
        if head[:2] == b"MZ":
            t.subtype = "pe"
            ev("PE 可执行")
            blob = head + _tail(path, 2 * 1024 * 1024)
            if b"MEI\x0c\x0b\x0a\x0b\x0e" in blob or b"pyi-" in blob:
                t.subtype = "pe_pyinstaller"
                t.confidence = 0.9
                ev("PyInstaller 标记")
            elif b"BSJB" in blob:
                t.subtype = "pe_dotnet"
                t.confidence = 0.85
                ev(".NET 元数据标记 BSJB")
            elif b"UPX0" in blob and b"UPX1" in blob:
                t.subtype = "pe_upx"
                t.confidence = 0.85
                ev("UPX 加壳段")
            stage("binary_struct", "deep_reverse")
            if size <= 64 * 1024 * 1024:
                stage("decompile")
            return t
        if head[:4] == b"\x7fELF":
            pwn_signals = [s for s in (b"/bin/sh", b"gets\x00", b"system\x00",
                                       b"__stack_chk_fail", b"pop rdi") if s in head]
            rev_signals = [s for s in (b"Correct", b"Wrong", b"flag{", b"Input",
                                       b"input:", b"password") if s in head]
            if pwn_signals and (b"/bin/sh" in head or b"gets\x00" in head):
                t.subtype = "elf_pwn"
                t.confidence = 0.85
                ev("ELF 含 " + "/".join(s.decode("latin-1").strip("\x00")
                                        for s in pwn_signals[:3]))
                stage("binary_struct", "pwn_static")
                script("checksec_binary")
            elif rev_signals:
                t.subtype = "elf_reverse"
                t.confidence = 0.75
                ev("ELF 含校验提示串")
                stage("binary_struct", "deep_reverse")
                if size <= 64 * 1024 * 1024:
                    stage("decompile")
            else:
                t.subtype = "elf"
                stage("binary_struct", "pwn_static", "deep_reverse")
                script("checksec_binary")
            return t
        if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                        b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
            t.subtype = "macho_or_class"
            ev("Mach-O / Java class")
            stage("strings", "deep_reverse")
            return t

    # ---------- 未知 ----------
    t.subtype = "encrypted_container" if ent > 7.9 else "unknown_binary"
    t.confidence = 0.4
    ev("高熵 %.2f" % ent if ent > 7.9 else "无已知签名")
    stage("strings", "entropy", "deep_unknown", "xor")
    script("strings_enhanced", "file_carver")
    if size <= 128 * 1024 * 1024:
        script("entropy_map")
    if ent > 7.9:
        t.notes.append("高熵未知数据：优先确认是否加密容器；不在此阶段跑全量异或")
    return t


# ---------------------------------------------------------------- Web 判型
def _bump(scores, name, delta, reason):
    item = scores.setdefault(name, {"score": 0.0, "reasons": []})
    item["score"] += delta
    if reason and reason not in item["reasons"]:
        item["reasons"].append(reason)


def web_triage(session, hints=None) -> Triage:
    """给 Web 利用阶段打分排序；没有证据的阶段不执行。"""
    t = Triage(kind="web", category="web")
    ht = _hint_text(hints).lower()
    forms = list(getattr(session, "forms", []) or [])
    targets = list(getattr(session, "targets", []) or [])
    param_hints = list(getattr(session, "param_hints", []) or [])
    serialized = list(getattr(session, "serialized", []) or [])
    serialized_hints = dict(getattr(session, "serialized_hints", {}) or {})
    tech = [str(x) for x in (getattr(session, "tech", []) or [])]
    tokens = list(getattr(session, "tokens", []) or [])
    home_text = (getattr(session, "home_text", "") or "")[:300000]
    login_required = bool(getattr(session, "login_required", False))
    php_src = ""
    try:
        php_src = "\n".join(str(s) for s in
                            (getattr(session, "php_sources", []) or []))
    except Exception:
        php_src = ""
    src_unserialize = bool(re.search(r"(?i)\bunserialize\s*\(", php_src))
    source_text = (home_text + "\n" + php_src).lower()

    scores = {}
    for name in ("direct_upload", "login_csrf", "deser", "sqli", "cmdi",
                 "ssti_lfi", "ssrf_xxe", "xss_jwt_idor"):
        _bump(scores, name, 0.0, "")
    _bump(scores, "sqli", 0.2, "无证据基线")
    _bump(scores, "xss_jwt_idor", 0.2, "无证据基线")
    _bump(scores, "direct_upload", 0.1, "无证据基线")
    _bump(scores, "login_csrf", 0.1, "无证据基线")

    names = []
    file_inputs = False
    password_forms = False
    csrf_tokens = False
    for form in forms:
        fields = [str(k) for k in (form.get("fields") or {})]
        names += [f.lower() for f in fields]
        if form.get("files"):
            file_inputs = True
            _bump(scores, "direct_upload", 4.0, "存在文件上传表单")
            _bump(scores, "ssrf_xxe", 0.8, "上传入口可测 XXE/包装器")
        low_fields = {f.lower() for f in fields}
        if low_fields & {"pass", "password", "pwd", "passwd"}:
            password_forms = True
            _bump(scores, "login_csrf", 3.5, "存在登录口令表单")
            _bump(scores, "sqli", 1.0, "登录参数可测注入")
        if low_fields & {"csrf", "csrf_token", "token", "_token", "authenticity_token"}:
            csrf_tokens = True
            _bump(scores, "login_csrf", 1.2, "表单含 CSRF token")
        action = str(form.get("action") or "").lower()
        if any(k in action for k in ("login", "signin", "auth")):
            _bump(scores, "login_csrf", 1.0, "表单 action 指向登录入口")
        if any(k in action for k in ("upload", "file", "attach")):
            _bump(scores, "direct_upload", 2.0, "表单 action 指向上传接口")
    names += [str(x[1]).lower() for x in param_hints if isinstance(x, (list, tuple)) and len(x) > 1]
    names += [str((t0 or {}).get("param") or "").lower() for t0 in targets]
    names = [n for n in _uniq(names) if n]

    if set(names) & SQL_PARAMS:
        _bump(scores, "sqli", 2.0, "参数名含 SQL 常见字段 " +
              ",".join(sorted(set(names) & SQL_PARAMS))[:60])
    if set(names) & CMD_PARAMS:
        hit = ",".join(sorted(set(names) & CMD_PARAMS))[:60]
        _bump(scores, "cmdi", 2.8, "参数名含命令/主机字段 " + hit)
        if set(names) & {"ip", "host", "domain", "target", "addr", "address"}:
            _bump(scores, "ssrf_xxe", 1.5, "主机/地址参数可测 SSRF")
    if set(names) & FILE_PARAMS:
        hit = ",".join(sorted(set(names) & FILE_PARAMS))[:60]
        _bump(scores, "ssti_lfi", 2.2, "参数名含文件/页面字段 " + hit)
        _bump(scores, "ssrf_xxe", 0.8, "文件参数可测 XXE/包装器")
    if set(names) & URL_PARAMS:
        hit = ",".join(sorted(set(names) & URL_PARAMS))[:60]
        _bump(scores, "ssrf_xxe", 2.6, "参数名含 URL/跳转字段 " + hit)
        _bump(scores, "xss_jwt_idor", 0.8, "URL 参数可测跳转/XSS")
    if set(names) & TOKEN_PARAMS and (tokens or login_required):
        _bump(scores, "xss_jwt_idor", 1.4, "身份字段可测越权/JWT")
    if targets:
        _bump(scores, "sqli", 0.5, "存在可注入参数入口")
        _bump(scores, "ssti_lfi", 0.3, "存在可注入参数入口")

    # 入口路径是最强证据：/sqli、/ping、/ssti、/lfi、/fetch 等直接指向考点
    paths = []
    for link in list(getattr(session, "links", []) or [])[:40]:
        try:
            paths.append(urlsplit(str(link)).path.lower())
        except Exception:
            continue
    for tgt in targets[:20]:
        try:
            paths.append(urlsplit(str((tgt or {}).get("url") or "")).path.lower())
        except Exception:
            continue
    segments = set()
    for path in _uniq([p for p in paths if p]):
        segments.update(s for s in re.split(r"[/._-]+", path) if s)
    path_rules = (
        ("sqli", 2.5, ("sqli", "sql", "inject", "union", "query")),
        ("cmdi", 2.5, ("cmdi", "cmd", "ping", "exec", "shell", "rce", "system")),
        ("ssti_lfi", 2.0, ("ssti", "template", "render", "lfi", "include")),
        ("ssti_lfi", 1.2, ("file", "files", "page", "view", "download", "read")),
        ("ssrf_xxe", 2.0, ("ssrf", "fetch", "proxy", "request")),
        ("ssrf_xxe", 1.2, ("xml", "xxe")),
        ("xss_jwt_idor", 1.8, ("xss", "search", "comment", "guestbook")),
        ("xss_jwt_idor", 1.2, ("user", "profile", "account", "admin", "uid")),
        ("login_csrf", 1.0, ("login", "signin", "auth", "dashboard")),
        ("direct_upload", 1.0, ("upload", "uploads", "attach", "attachment")),
    )
    for phase, delta, words in path_rules:
        hit = sorted(w for w in words if w in segments)
        if hit:
            _bump(scores, phase, delta, "入口路径指向 " + ",".join(hit[:3]))

    for item in serialized[:10]:
        where = "%s@%s" % ((item or {}).get("kind", "?"), (item or {}).get("where", "?"))
        _bump(scores, "deser", 5.0, "响应/参数出现序列化数据 " + where)
    classes = serialized_hints.get("classes") or []
    if classes:
        _bump(scores, "deser", 4.0, "页面提示类 " + ",".join(map(str, classes))[:80])
    if src_unserialize:
        _bump(scores, "deser", 3.5, "泄露源码出现 unserialize(")
    if re.search(r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(", php_src):
        _bump(scores, "cmdi", 3.0, "源码出现命令执行函数")
    if re.search(r"(?i)\b(?:include|require)(?:_once)?\s*\(?\s*\$", php_src):
        _bump(scores, "ssti_lfi", 2.5, "源码出现动态 include/require")
    if re.search(r"(?i)(?:select|insert|update|delete)\b.{0,80}(?:\$_|\.\s*\$)", php_src):
        _bump(scores, "sqli", 1.8, "源码出现 SQL 拼接")

    tech_text = " ".join(tech).lower()
    if any(k in tech_text for k in ("php", "laravel", "thinkphp", "wordpress")):
        _bump(scores, "sqli", 0.6, "PHP 技术栈")
        _bump(scores, "deser", 0.6, "PHP 技术栈")
    if any(k in tech_text for k in ("java", "spring", "thymeleaf", "freemarker", "jsp")):
        _bump(scores, "deser", 1.2, "Java 技术栈")
        _bump(scores, "ssti_lfi", 1.0, "Java 模板技术栈")
    if any(k in tech_text for k in ("flask", "jinja2", "django")):
        _bump(scores, "ssti_lfi", 1.5, "Python 模板技术栈")
    if "asp.net" in tech_text:
        _bump(scores, "deser", 1.0, "ASP.NET ViewState 可测反序列化")
    if tokens:
        _bump(scores, "xss_jwt_idor", 2.5, "发现 JWT")
    if login_required:
        _bump(scores, "xss_jwt_idor", 0.8, "目标需要登录（越权/会话）")
        _bump(scores, "sqli", 0.5, "登录入口可测注入")

    hint_rules = (
        ("direct_upload", 4.5, ("上传", "upload", "文件上传")),
        ("login_csrf", 4.0, ("登录", "login", "csrf", "弱口令", "爆破")),
        ("deser", 5.0, ("反序列化", "unserialize", "pop链", "phar", "ysoserial", "serialize")),
        ("sqli", 4.5, ("sql", "注入", "injection", "union")),
        ("cmdi", 4.5, ("命令执行", "rce", "命令注入", "cmd", "system")),
        ("ssti_lfi", 4.5, ("ssti", "模板注入", "文件包含", "lfi", "include", "任意文件读取")),
        ("ssrf_xxe", 4.5, ("ssrf", "xxe", "xml实体", "xml")),
        ("xss_jwt_idor", 4.5, ("xss", "jwt", "idor", "越权", "伪造")),
    )
    for phase, delta, words in hint_rules:
        hit = [w for w in words if w in ht]
        if hit:
            _bump(scores, phase, delta, "题面提示 " + ",".join(hit[:3]))
    if "后台" in ht:
        _bump(scores, "cmdi", 0.8, "题面提示后台")
        _bump(scores, "login_csrf", 0.5, "题面提示后台")

    threshold = 1.5
    chosen = []
    for name, item in scores.items():
        score = item["score"]
        if name in ("direct_upload", "login_csrf"):
            if score >= 2.0:
                chosen.append((name, score, item["reasons"]))
        elif score >= threshold:
            chosen.append((name, score, item["reasons"]))
    if not chosen:
        chosen = [("sqli", 1.0, ["无强证据，回退高频 SQL 探测"]),
                  ("xss_jwt_idor", 1.0, ["无强证据，回退高频参数探测"])]
    # 登录/上传优先执行；其余严格按证据分排序。上限即全部已知阶段，
    # 真正决定是否执行的是证据阈值，而不是固定截断。
    priority = {"direct_upload": 0, "login_csrf": 1}
    chosen.sort(key=lambda x: (priority.get(x[0], 2), -x[1]))
    cap = 8
    chosen = chosen[:cap]
    t.web_phases = [{"phase": n, "score": round(s, 2), "reasons": r}
                    for n, s, r in chosen]
    t.stages = [p["phase"] for p in t.web_phases]
    t.confidence = min(0.95, 0.45 + 0.1 * len(chosen))
    for p in t.web_phases:
        t.evidence.append("%s=%.1f（%s）" % (p["phase"], p["score"],
                                            "；".join(p["reasons"][:2])))
    skipped = [n for n, item in scores.items()
               if n not in t.stages and item["score"] > 0
               and item["reasons"] and item["reasons"] != ["无证据基线"]]
    t.skipped = ["%s(%.1f)" % (n, scores[n]["score"]) for n in skipped]
    t.notes.append("Web 阶段按证据评分选择（阈值 1.5，登录/上传 2.0）；"
                   "未达阈值阶段已跳过，不做全量遍历")
    if file_inputs:
        t.notes.append("检测到上传表单：仅生成打靶验证样本，不提供免杀/持久化")
    if csrf_tokens or password_forms:
        t.notes.append("登录流程使用任务内 Cookie，不代填真实凭据")
    return t


# ---------------------------------------------------------------- 报告辅助
def triage_lines(triage: dict, level: int = 2) -> list:
    """把判型结果转成 WP/报告可读行；level=3 用作小节。"""
    if not triage:
        return []
    head = "#" * max(2, min(4, int(level)))
    lines = ["", "%s 首层判型（主考点路由）" % head, "",
             "- 类型：`%s/%s`（置信 %.2f）" % (
                 triage.get("category"), triage.get("subtype"),
                 triage.get("confidence", 0)),
             "- 证据：%s" % ("；".join(triage.get("evidence") or []) or "-")]
    if triage.get("stages"):
        lines.append("- 执行阶段：%s" % " → ".join(triage["stages"]))
    if triage.get("scripts"):
        lines.append("- 自动脚本：%s" % ", ".join(triage["scripts"]))
    if triage.get("skipped"):
        lines.append("- 已跳过：%s" % ", ".join(triage["skipped"]))
    if triage.get("web_phases"):
        lines.append("- Web 阶段评分：%s" % "；".join(
            "%s=%.1f" % (p.get("phase"), p.get("score", 0))
            for p in triage["web_phases"]))
    for note in triage.get("notes") or []:
        lines.append("- %s" % note)
    return lines
