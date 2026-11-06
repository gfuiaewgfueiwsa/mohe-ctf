# -*- coding: utf-8 -*-
"""RAC 第一步 —— Recognize：题目识别与参数自动提取。

输入：题目描述文本（可选）+ 附件文件列表（可选）
输出：TaskCard（题型分类 + 置信度 + 提取出的参数 + 附件类型线索）

提取的参数键（统一小写）：
  n/e/c/p/q/d/dp/dq   RSA 参数（支持十进制与 0x 十六进制）
  host/port/url       目标地址（Web/Pwn 题）
  md5/sha1/sha256     哈希（按长度特征识别）
  ciphertext          长密文串（Base64/Hex）
  user/pass           用户名/口令
  flag_prefix         题目 flag 前缀（比赛平台名）
  code                附件中的疑似源码语言线索
"""
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# 题型分类关键词（命中一次 +1，核心词 +2）
# ---------------------------------------------------------------------------
CATEGORY_KEYWORDS = {
    "crypto": [
        ("rsa", 2), ("openssl", 1), ("公钥", 2), ("私钥", 2), ("密钥", 1),
        ("n=", 2), ("e=", 2), ("c=", 1), ("dp", 1), ("dq", 1),
        ("加密", 1), ("解密", 1), ("密文", 2), ("明文", 1),
        ("椭圆曲线", 2), ("ecc", 1), ("维吉尼亚", 2), ("凯撒", 2), ("栅栏", 2),
        ("摩斯", 2), ("base64", 1), ("base32", 1), ("哈希", 1), ("hash", 1),
        ("md5", 1), ("sha1", 1), ("sha256", 1), ("jwt", 2), ("padding oracle", 2),
        ("lcg", 2), ("tea", 1), ("xtea", 2), ("xxtea", 2), ("rc4", 2),
        ("共模", 2), ("广播", 1), ("分解", 1), ("素数", 2), ("质数", 1),
    ],
    "misc": [
        ("隐写", 2), ("stego", 2), ("steg", 1), ("lsb", 2), ("零宽", 2),
        ("二维码", 2), ("qrcode", 2), ("图片", 1), ("png", 1), ("jpg", 1), ("gif", 1),
        ("压缩包", 2), ("zip", 1), ("rar", 1), ("伪加密", 2), ("crc", 1),
        ("音频", 2), ("wav", 1), ("mp3", 1), ("频谱", 2), ("语谱图", 2),
        ("像素", 1), ("文件恢复", 1), ("磁盘", 1), ("编码", 1), ("佛曰", 2),
        ("兽音", 2), ("敲击码", 2), ("当铺", 2), ("与佛论禅", 2), ("brainfuck", 2),
        ("misc", 1), ("谜题", 1), ("拼图", 1), ("摩斯密码", 2),
    ],
    "web": [
        ("web", 2), ("http", 1), ("https", 1), ("sql", 1), ("sql注入", 2), ("sqlmap", 2),
        ("xss", 2), ("ssti", 2), ("ssrf", 2), ("csrf", 1), ("cookie", 1),
        ("session", 1), ("上传", 1), ("getshell", 2), ("一句话", 2), ("webshell", 2),
        ("目录扫描", 2), ("git泄露", 2), (".git", 2), ("robots", 1), ("备份文件", 2),
        ("php", 1), ("注入", 1), ("header", 1), ("boa", 1), ("cms", 1),
        ("swagger", 1), ("actuator", 1), ("jwt", 1), ("weak password", 1), ("弱口令", 1),
    ],
    "pwn": [
        ("pwn", 2), ("栈溢出", 2), ("堆溢出", 2), ("堆", 1), ("ret2text", 3),
        ("ret2libc", 3), ("ret2shellcode", 3), ("shellcode", 2), ("canary", 2),
        ("rop", 2), ("格式化字符串", 3), ("nc", 1), ("gets", 2), ("read(", 1),
        ("syscall", 2), ("uaf", 2), ("fastbin", 2), ("off-by-one", 2),
        ("32位", 1), ("64位", 1), ("elf", 1), ("保护", 1), ("后门", 1), ("system", 1),
    ],
    "reverse": [
        ("逆向", 3), ("reverse", 2), ("rev", 1), ("apk", 2), ("反编译", 2),
        ("pyc", 2), ("pyinstaller", 2), ("脱壳", 2), ("ida", 2), ("ghidra", 2),
        ("upx", 2), ("混淆", 1), ("crackme", 2), ("z3", 2), ("符号执行", 2),
        ("dump", 1), ("汇编", 2), (".net", 1), ("dnspy", 2), ("Android", 1),
    ],
    "forensics": [
        ("取证", 3), ("forensics", 2), ("流量", 2), ("pcap", 3), ("pcapng", 3),
        ("wireshark", 2), ("内存取证", 3), ("volatility", 2), ("注册表", 2),
        ("evtx", 2), ("事件日志", 2), ("usb流量", 3), ("键盘流量", 3), ("鼠标流量", 3),
        ("蓝牙", 2), ("dns隧道", 3), ("icmp", 1), ("日志分析", 2), ("镜像", 1),
        (".ntfs", 1), ("ads", 1), ("vmdk", 1), ("藏帧", 1),
    ],
}
NEIGHBORS = {  # 相邻类别（弱加权 +10）
    "crypto": ("misc", "reverse"), "misc": ("crypto", "forensics"),
    "web": ("pwn", "crypto"), "pwn": ("reverse", "web"),
    "reverse": ("pwn", "crypto"), "forensics": ("misc", "web"),
}

# ---------------------------------------------------------------------------
# 参数提取正则
# ---------------------------------------------------------------------------
_RSA_KEY = r"(?:n|e|c|p|q|d|dp|dq)"
RE_RSA_PARAM = re.compile(
    r"(?<![\w])(" + _RSA_KEY + r")\s*[=:：]\s*(0[xX][0-9a-fA-F]{4,}|\d{4,})(?![\w])")
RE_HOST_KV = re.compile(
    r"(?:host|server|ip|主机|服务器|靶机|目标)\s*[=:：]\s*([A-Za-z0-9_.\-]{3,80})", re.I)
RE_PORT_KV = re.compile(r"(?:port|端口)\s*[=:：]\s*(\d{1,5})", re.I)
RE_IP_PORT = re.compile(
    r"\b(\d{1,3}(?:\.\d{1,3}){3})\s*[:：]\s*(\d{2,5})\b")
RE_HOST_PORT = re.compile(
    r"\b([A-Za-z0-9][A-Za-z0-9_.\-]{2,60}\.(?:com|cn|org|net|edu|io|top|xyz|club|site|vip|online|cc|me|tv))\s*[:：]\s*(\d{2,5})\b")
RE_NC = re.compile(r"\bnc\s+([A-Za-z0-9_.\-]{3,80})\s+(\d{2,5})\b", re.I)
RE_URL = re.compile(r"\bhttps?://[^\s\"'<>\\()\u4e00-\u9fff]{4,}", re.I)
RE_MD5 = re.compile(r"\b([0-9a-fA-F]{32})\b")
RE_SHA1 = re.compile(r"\b([0-9a-fA-F]{40})\b")
RE_SHA256 = re.compile(r"\b([0-9a-fA-F]{64})\b")
RE_B64 = re.compile(r"\b([A-Za-z0-9+/]{20,}={0,2})\b")
RE_HEXSTR = re.compile(r"\b((?:[0-9a-fA-F]{2}){24,})\b")
# "密文: xxx" 锚定模式：中文题目高频写法，阈值可以更低（16 字符即收）
RE_CIPHER_KV = re.compile(
    r"(?:密文|ciphertext|cipher)\s*[=:：]?\s*([A-Za-z0-9+/=_\-]{16,})", re.I)
RE_USER = re.compile(
    r"(?:user(?:name)?|login|用户名)\s*[=:：]\s*([^\s，。；;\"'\\]{2,60})", re.I)
RE_PASS = re.compile(
    r"(?:pass(?:word)?|pwd|密码|口令)\s*[=:：]\s*([^\s，。；;\"'\\]{2,60})", re.I)
RE_FLAGISH = re.compile(r"\b([A-Za-z][A-Za-z0-9_]{1,20}\{[^{}\r\n]{3,180})\}")

# 已知 flag 前缀（与 common.STRONG_PREFIXES 同源，字符串版）
KNOWN_PREFIXES = [
    "flag", "f1ag", "fl4g", "ctf", "nssctf", "dasctf", "buuctf", "buuoj", "polarflag",
    "gwht", "moectf", "basectf", "syc", "d3ctf", "0xgame", "hgame", "iscc", "ciscn",
    "n1ctf", "sctf", "de1ctf", "corctf", "uiuctf", "ductf", "picoctf", "tjctf",
    "ctfshow", "xctf", "nctf", "key", "answer", "secret", "password", "token",
]

RE_MAX_TEXT = 2 * 1024 * 1024   # 单文件最多读 2MB 做参数提取


@dataclass
class TaskCard:
    """RAC 任务卡：流水线中间传递的"题目画像"。"""
    description: str = ""
    category: str = "unknown"       # crypto/misc/web/pwn/reverse/forensics/unknown
    confidence: float = 0.0
    scores: Dict[str, float] = field(default_factory=dict)
    params: Dict[str, object] = field(default_factory=dict)   # 提取到的参数（统一小写键）
    keywords: List[str] = field(default_factory=list)         # 命中的关键词（供脚本匹配）
    attachments: List[str] = field(default_factory=list)      # 附件绝对路径
    attachment_types: List[str] = field(default_factory=list) # 每个附件的 ftype
    direct_flags: List[str] = field(default_factory=list)     # 题目文本/附件中直接出现的 flag

    def as_dict(self):
        return {
            "category": self.category, "confidence": round(self.confidence, 3),
            "scores": {k: round(v, 2) for k, v in self.scores.items()},
            "params": {k: (str(v)[:300]) for k, v in self.params.items()},
            "keywords": self.keywords[:40],
            "attachments": self.attachments,
            "attachment_types": self.attachment_types,
            "direct_flags": self.direct_flags,
        }


def _try_int(raw: str):
    try:
        return int(raw, 0)
    except Exception:
        return None


def extract_params(text: str) -> Dict[str, object]:
    """从任意文本提取结构化参数（纯函数，可对描述/附件/解码结果反复调用）。"""
    params: Dict[str, object] = {}
    if not text:
        return params

    # 1) RSA 参数（同键后值覆盖前值；int 化失败放弃）
    for m in RE_RSA_PARAM.finditer(text):
        v = _try_int(m.group(2))
        if v is None:
            continue
        k = m.group(1).lower()
        params[k] = v

    # 2) host / port
    if m := RE_HOST_KV.search(text):
        params.setdefault("host", m.group(1))
    if m := RE_PORT_KV.search(text):
        try:
            params.setdefault("port", int(m.group(1)))
        except Exception:
            pass
    for pat in (RE_IP_PORT, RE_HOST_PORT):
        m = pat.search(text)
        if m:
            params.setdefault("host", m.group(1))
            try:
                params.setdefault("port", int(m.group(2)))
            except Exception:
                pass
            break
    if m := RE_NC.search(text):
        params.setdefault("host", m.group(1))
        try:
            params.setdefault("port", int(m.group(2)))
        except Exception:
            pass
    if "port" in params and "host" not in params:
        params.setdefault("host", "127.0.0.1")

    # 3) URL
    if m := RE_URL.search(text):
        params.setdefault("url", m.group(0).rstrip(".,;)"))

    # 4) 哈希（按长度特征，互斥识别）
    if m := RE_MD5.search(text):
        params.setdefault("md5", m.group(1).lower())
    if m := RE_SHA1.search(text):
        params.setdefault("sha1", m.group(1).lower())
    if m := RE_SHA256.search(text):
        params.setdefault("sha256", m.group(1).lower())

    # 5) 长密文串：hex 优先（更具体），"密文:"锚定次之，通用 Base64 兜底
    hexed = RE_HEXSTR.findall(text)
    if hexed:
        params.setdefault("ciphertext", max(hexed, key=len))
    if "ciphertext" not in params:
        for cand in RE_CIPHER_KV.findall(text):
            cand = cand.strip("=")
            if len(cand) >= 16:
                params.setdefault("ciphertext", cand)
                break
    if "ciphertext" not in params:
        for cand in RE_B64.findall(text):
            # 排除纯 hex（已被上面处理）与纯字母表串
            if re.fullmatch(r"[0-9a-fA-F]+", cand):
                continue
            if cand.lower() in ("abcdefghijklmnopqrstuvwxyz",):
                continue
            params.setdefault("ciphertext", cand)
            break

    # 6) 账号口令
    if m := RE_USER.search(text):
        params.setdefault("user", m.group(1))
    if m := RE_PASS.search(text):
        params.setdefault("pass", m.group(1))

    # 7) flag 前缀
    for m in RE_FLAGISH.finditer(text):
        prefix = m.group(1).lower()
        if any(prefix == p or prefix.startswith(p) for p in KNOWN_PREFIXES):
            params.setdefault("flag_prefix", prefix.split("{")[0])
            break

    # 8) RSA 确定性推导：给出 p/q 时自动补 n = p*q（题目常省略 n）
    if ("p" in params and "q" in params and "n" not in params
            and isinstance(params["p"], int) and isinstance(params["q"], int)):
        try:
            params["n"] = params["p"] * params["q"]
        except Exception:
            pass
    return params


def _keywords_of(text: str) -> List[str]:
    """从文本抓取可能是'术语'的关键词（供脚本简介匹配）：英文词 + 已知类别词。"""
    kws = set()
    for cat, kws_w in CATEGORY_KEYWORDS.items():
        for kw, _w in kws_w:
            if kw.lower() in text.lower():
                kws.add(kw.lower())
    # RSA 一类参数键本身也是线索
    for k in ("n", "e", "c", "dp", "dq"):
        if re.search(r"(?<![\w])" + k + r"\s*[=:：]", text, re.I):
            kws.add(k)
    return sorted(kws)


def classify(text: str, attachment_types: List[str] = None) -> Tuple[str, float, Dict[str, float]]:
    """题型分类：关键词评分 + 附件类型加权。返回 (category, confidence, scores)。"""
    scores: Dict[str, float] = {}
    low = (text or "").lower()
    for cat, kws_w in CATEGORY_KEYWORDS.items():
        s = 0.0
        for kw, w in kws_w:
            if kw.lower() in low:
                s += w
        scores[cat] = s

    # 附件类型加权
    for ft in (attachment_types or []):
        f = (ft or "").lower()
        if f.startswith("elf"):
            scores["pwn"] += 3; scores["reverse"] += 2
        elif f in ("pcap", "pcapng"):
            scores["forensics"] += 5
        elif f in ("png", "jpeg", "gif", "bmp", "webp", "tiff"):
            scores["misc"] += 4
        elif f in ("zip", "rar", "7z", "tar", "gzip", "bzip2", "xz"):
            scores["misc"] += 3
        elif f in ("wav", "mp3", "flac", "ogg", "m4a", "aac"):
            scores["misc"] += 4
        elif f in ("html", "json", "xml", "har"):
            scores["web"] += 3
        elif f in ("python-bytecode", "pyc"):
            scores["reverse"] += 5
        elif f in ("exe", "dll", "pe"):
            scores["reverse"] += 4
        elif f in ("docx", "xlsx", "pptx", "pdf"):
            scores["misc"] += 2
        elif f in ("evtx", "registry", "vmdk", "vhd", "e01"):
            scores["forensics"] += 5
        elif f in ("rsa-key", "pem", "certificate"):
            scores["crypto"] += 5

    best = max(scores, key=lambda k: scores[k]) if scores else "unknown"
    total = sum(scores.values())
    conf = (scores[best] / total) if total > 0 else 0.0
    if scores.get(best, 0) < 1:
        return "unknown", 0.0, scores
    return best, conf, scores


def _attachment_text(path: str) -> str:
    """轻量读取附件文本用于参数提取：只读文本类/小文件，不动二进制。"""
    try:
        if os.path.getsize(path) > RE_MAX_TEXT:
            return ""
        with open(path, "rb") as f:
            raw = f.read()
        from ..common import try_decode_text
        ok, _enc, text = try_decode_text(raw)
        return text if ok else ""
    except Exception:
        return ""


def recognize(description: str = "", attachments: List[str] = None,
              extra_texts: List[str] = None) -> TaskCard:
    """R 段入口：识别题目并产出任务卡。

    description   题目描述（可含参数、提示、连接信息）
    attachments   附件路径列表
    extra_texts   附件深度分析产出的补充文本（解码结果等），用于二次参数提取
    """
    card = TaskCard(description=description or "")
    texts = [description or ""]
    for p in (attachments or []):
        ap = os.path.abspath(p)
        if not os.path.isfile(ap):
            continue
        card.attachments.append(ap)
        ft = "unknown"
        try:
            from ..identifier import identify
            info = identify(ap)
            ft = info.ftype
            if info.category == "text":
                t = _attachment_text(ap)
                if t:
                    texts.append(t[:RE_MAX_TEXT])
        except Exception:
            ft = "unknown"
        card.attachment_types.append(ft)
        # 文本类之外的小附件也尝试直接解码读参数（如隐藏 txt / json）
        if ft == "unknown" and os.path.getsize(ap) <= RE_MAX_TEXT:
            t = _attachment_text(ap)
            if t:
                texts.append(t[:RE_MAX_TEXT])
    for t in (extra_texts or []):
        if t:
            texts.append(t[:RE_MAX_TEXT])

    big_text = "\n".join(texts)
    card.params = extract_params(big_text)
    card.keywords = _keywords_of(big_text)
    card.category, card.confidence, card.scores = classify(big_text, card.attachment_types)

    # 题目文本/附件中直接出现的 flag 直接收进任务卡
    from ..common import scan_flags_text
    card.direct_flags = scan_flags_text(big_text)
    return card
