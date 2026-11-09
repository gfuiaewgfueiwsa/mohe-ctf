# -*- coding: utf-8 -*-
"""通用工具：数据结构、flag 搜索、熵、strings、编码常量等。"""
import os
import re
import sys
import math
import json
import base64
import hashlib
import binascii
import logging
import warnings

# 抑制 scapy/cryptography 的运行时噪声警告（本工具只离线读包，不实时抓包）
logging.getLogger("scapy").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", message=".*Diffie-Hellman.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module=r".*scapy.*")
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Any

IS_FROZEN = bool(getattr(sys, "frozen", False))

if IS_FROZEN:
    # PyInstaller 打包后：工具与工作区放在 exe 同级目录，便于用户查看/工具中心下载
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def external_python():
    """返回可运行 .py 脚本 / pip 的外部 Python 解释器。
    打包后 sys.executable 是本 GUI exe，绝不能用它去 -m 或跑 .py。
    优先使用随包便携 Python（tools/runtime/python），保证干净电脑无 Python 也能运行
    sqlmap / volatility3 / binwalk 等 Python 工具。"""
    if not IS_FROZEN:
        return sys.executable
    # 1. 随包便携 Python 优先
    bundled = os.path.join(APP_DIR, "tools", "runtime", "python", "python.exe")
    if os.path.exists(bundled):
        return bundled
    # 2. 系统 PATH 回退
    import shutil
    for name in ("python", "python3", "py"):
        p = shutil.which(name)
        if p:
            if os.path.basename(p).lower().startswith("py.exe") or name == "py":
                return p  # py launcher，调用方需自行处理 -3
            return p
    return None
TOOLS_DIR = os.path.join(APP_DIR, "tools", "portable")
WORKSPACE = os.path.join(APP_DIR, "workspace")
# 所有导出物统一放在软件所在目录下，便于即开即用、随文件夹整体拷贝/卸载
REPORTS_DIR = os.path.join(APP_DIR, "reports")     # 分析报告（HTML/TXT）
EXPORTS_DIR = os.path.join(APP_DIR, "exports")     # 媒体转换/抽帧/音频/GIF 等导出
for _d in (TOOLS_DIR, WORKSPACE, REPORTS_DIR, EXPORTS_DIR):
    os.makedirs(_d, exist_ok=True)


def ensure_playwright_browsers() -> str:
    """修正 PyInstaller 冻结后的 Playwright 浏览器路径。

    Playwright 在 `sys.frozen` 时会强制 `PLAYWRIGHT_BROWSERS_PATH=0`，
    只找 `playwright/driver/package/.local-browsers`；随包不携带该目录时必然
    "Executable doesn't exist"，SPA 渲染被迫降级为 Chrome headless（无 XHR 采集）。
    这里在启动前指向随包浏览器目录或本机已安装的浏览器目录，返回生效路径。
    """
    if os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        return os.environ["PLAYWRIGHT_BROWSERS_PATH"]
    if not IS_FROZEN:
        return ""
    candidates = [
        os.path.join(APP_DIR, "tools", "runtime", "ms-playwright"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "ms-playwright"),
    ]
    for c in candidates:
        if c and os.path.isdir(c):
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = c
            return c
    return ""


def app_path(*parts) -> str:
    """返回软件所在目录下的路径（不自动建目录）。"""
    return os.path.join(APP_DIR, *parts)


def workspace_path(*parts) -> str:
    """返回 workspace 下的路径并确保父目录存在。"""
    p = os.path.join(WORKSPACE, *parts)
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    return p


def export_path(*parts) -> str:
    """返回 exports 下的路径并确保父目录存在。"""
    p = os.path.join(EXPORTS_DIR, *parts)
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    return p


def report_file(stem: str, ext: str = ".html") -> str:
    """在软件目录 reports\\ 下生成带时间戳的报告路径。"""
    import time
    safe = safe_name(stem)
    return os.path.join(REPORTS_DIR, f"{safe}_{time.strftime('%Y%m%d_%H%M%S')}{ext}")


# ----------------------------------------------------------------------------
# 统一运行产物目录
# ----------------------------------------------------------------------------
# 历史问题：dispatcher 用 `WORKSPACE/out_<文件名>_<abs(hash(path))%0xffff>` 作为
# 中间产物目录。`hash()` 受 PYTHONHASHSEED 随机化影响，同一文件每次运行都会
# 新建不同目录，长期使用后 workspace 根目录堆积数万个小目录（实测 41 万文件）。
# 这里改为「每进程一个运行根目录」，并做最近 N 次保留的滚动清理：
#   workspace/runs/<时间戳>_<pid>/
# 所有模块的 out_*/polar_* 产物都落在其下，清理时只删一个目录即可。
RUNS_DIR = os.path.join(WORKSPACE, "runs")
_RUN_DIR = None
_RUN_KEEP = 12          # 保留最近 12 次运行，满足排查需求又不无限增长


def prune_runs(keep: int = _RUN_KEEP) -> int:
    """删除过旧的运行目录，返回删除数量。失败静默（不影响主流程）。"""
    import shutil
    removed = 0
    try:
        names = [os.path.join(RUNS_DIR, n) for n in os.listdir(RUNS_DIR)]
        dirs = [p for p in names if os.path.isdir(p)]
        dirs.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        for old in dirs[max(1, keep):]:
            try:
                shutil.rmtree(old, ignore_errors=True)
                removed += 1
            except Exception:
                continue
    except Exception:
        return removed
    return removed


def new_run_dir(prefix: str = "run") -> str:
    """返回本进程共享的产物根目录（首次调用时创建并顺带清理旧运行）。"""
    global _RUN_DIR
    if _RUN_DIR and os.path.isdir(_RUN_DIR):
        return _RUN_DIR
    import time
    try:
        os.makedirs(RUNS_DIR, exist_ok=True)
        prune_runs()
    except Exception:
        pass
    stamp = time.strftime("%Y%m%d_%H%M%S")
    path = os.path.join(RUNS_DIR, "%s_%s_%d" % (safe_name(prefix), stamp, os.getpid()))
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        return WORKSPACE
    _RUN_DIR = path
    return path


# ----------------------------------------------------------------------------
# 后台子进程静默：打包为 windowed 程序后，调用 7z/exiftool/ffmpeg/python 等
# 控制台程序时默认会接连弹出黑窗。这里统一注入 CREATE_NO_WINDOW，
# 让所有后台工具调用静默执行；GUI 子系统程序（x64dbg/dnSpy/ffplay 等）不受影响，
# 仍会正常显示自己的窗口。确需弹出控制台的调用可显式传 CREATE_NEW_CONSOLE。
# ----------------------------------------------------------------------------
import subprocess as _sp

CREATE_NEW_CONSOLE = getattr(_sp, "CREATE_NEW_CONSOLE", 0x10)
CREATE_NO_WINDOW = getattr(_sp, "CREATE_NO_WINDOW", 0x08000000)


def _silence_subprocess():
    if not sys.platform.startswith("win"):
        return
    if getattr(_sp.Popen, "_ctf_silenced", False):
        return
    _orig_popen_init = _sp.Popen.__init__

    def _patched_init(self, *args, **kwargs):
        try:
            cf = kwargs.get("creationflags", 0) or 0
            # 调用方明确要求新控制台（如交互式 Kali）时不干预
            if not (cf & CREATE_NEW_CONSOLE):
                kwargs["creationflags"] = cf | CREATE_NO_WINDOW
        except Exception:
            pass
        return _orig_popen_init(self, *args, **kwargs)

    _sp.Popen.__init__ = _patched_init
    _sp.Popen._ctf_silenced = True


_silence_subprocess()

# ----------------------------------------------------------------------------
# 结果数据结构
# ----------------------------------------------------------------------------
@dataclass
class Finding:
    level: str          # info / ok / warn / flag / tool
    title: str
    detail: str = ""
    data: Any = None    # 附带数据（解码文本/字节/路径）

    def to_dict(self):
        d = asdict(self)
        if isinstance(d.get("data"), (bytes, bytearray)):
            d["data"] = f"<bytes len={len(d['data'])}>"
        return d


@dataclass
class Report:
    path: str
    findings: List[Finding] = field(default_factory=list)
    extracted: List[str] = field(default_factory=list)   # 提取出的新文件路径
    children: List["Report"] = field(default_factory=list)
    category: str = "unknown"
    ftype: str = "unknown"

    def add(self, level, title, detail="", data=None):
        # 同一文件报告内相同 flag 去重：原始内容强扫描与后续解码链/专项扫描
        # 经常命中同一 flag，重复上报会污染报告与 CLI 输出。
        if level == "flag":
            for f in self.findings:
                if f.level == "flag" and f.detail == detail:
                    return
        self.findings.append(Finding(level, title, detail, data))

    def add_item(self, finding: "Finding", flagdata=None):
        """添加 Finding 并自动登记提取文件、扫描 flag（新模块统一入口）。"""
        self.add(finding.level, finding.title, finding.detail, finding.data)
        if isinstance(finding.data, str) and os.path.isfile(finding.data):
            if os.path.isdir(finding.data):
                if finding.data not in self.extracted:
                    self.extracted.append(finding.data)
            elif finding.data not in self.extracted:
                self.extracted.append(finding.data)
        flags = getattr(finding, "flags", None) or (scan_flags(flagdata) if flagdata else None)
        if flags:
            for fl in flags:
                self.add("flag", "发现 flag", fl)

    def flags(self):
        out = []
        def walk(r):
            for f in r.findings:
                if f.level == "flag":
                    out.append((r.path, f))
            for c in r.children:
                walk(c)
        walk(self)
        return out

    def to_dict(self):
        return {
            "path": self.path, "category": self.category, "ftype": self.ftype,
            "findings": [f.to_dict() for f in self.findings],
            "extracted": self.extracted,
            "children": [c.to_dict() for c in self.children],
        }

# ----------------------------------------------------------------------------
# Flag 搜索
# ----------------------------------------------------------------------------
# 强模式：flag{} 变体 + 国内外常见比赛/平台/语义前缀（用于解码候选，避免 ROT/Atbash 结果误报）
STRONG_PREFIXES = [
    b"fl?ag", b"f1ag", b"fl4g", b"ctf", b"nssctf", b"dasctf", b"buuctf", b"buuoj",
    b"gwht", b"moectf", b"basectf", b"syc", b"d3ctf", b"0xgame", b"hgame", b"iscc",
    b"ciscn", b"n1ctf", b"n1book", b"sctf", b"rwctf", b"de1ctf", b"hxp", b"corctf", b"uiuctf",
    b"lacctf", b"ductf", b"picoctf", b"hsctf", b"tjctf", b"csictf", b"ctfshow",
    b"xctf", b"geekctf", b"catctf", b"venox", b"helloctf", b"mrctf", b"zjctf",
    b"dmctf", b"cnss", b"nctf", b"tip", b"key", b"answer", b"secret", b"password",
    b"passwd", b"token", b"flagctf", b"basectf", b"security",
]
FLAG_STRONG = (rb"(?i)(?:" + b"|".join(STRONG_PREFIXES) +
               rb")\{[^\r\n\x00]{1,200}?\}")
# flag=xxx / flag:xxx：要求值带花括号或至少 8 个 token 字符，
# 避免把 CSS/JS 里的 `flag:before`、`flag:hover` 等伪类当成 flag。
FLAG_KV = (rb"(?i)flag[=:][ ]?(?:\{[A-Za-z0-9_\-./+=@$%^&*!?]{3,199}\}"
           rb"|[A-Za-z0-9_\-]{8,120})")
# 弱模式：任意 前缀{...}，仅用于文件原始数据/雕刻/字符串扫描。
# 收紧：内容首字符须为字母数字、整体为 token 形态（排除 CSS/键值里常见的 '#',':',';' 与空白），
# 内容至少 4 个字符，显著降低在高熵二进制 / 样式表上的误报。
# 保留 `=`（base64 填充会用到），压缩 JS 的 `try{a=b}` 交给 looks_like_code_flag 剔除。
FLAG_WEAK = rb"[A-Za-z0-9_]{2,20}\{[A-Za-z0-9][A-Za-z0-9_\-./+=@$%^&*!?]{3,199}?\}"

SCAN_WINDOW = 4 * 1024 * 1024     # 大文件分窗扫描，避免弱正则在超长数据上回溯放大
SCAN_OVERLAP = 256                # 窗口重叠，防止 flag 跨窗截断

# 源码模板里的占位 flag（flag{??????}、YOUR_FLAG_HERE 等）不是真实答案，
# 命中后会把附件分析结果污染成「已解出」，必须在提取层统一丢弃。
_PLACEHOLDER_CHARS = re.compile(r"^[?*#._\-\sxX]+$")
_PLACEHOLDER_BODY = re.compile(
    r"(?i)^(?:(?:your[_-]?)?(?:flag|ctf|answer|secret|token|key|pass(?:word)?)"
    r"(?:[_-](?:is[_-])?(?:here|placeholder|redacted|xxx*))?"
    r"|todo|tbd|placeholder|redacted|changeme|example|none|null|undefined)$")

def is_placeholder_flag(value: str) -> bool:
    """判断提取值是否为模板占位符（不属于真实 flag）。"""
    if not value:
        return True
    m = re.match(r"(?is)^[A-Za-z0-9_]{2,20}\{(.*)\}$", value.strip())
    body = (m.group(1) if m else value).strip()
    if not body:
        return True
    return bool(_PLACEHOLDER_CHARS.fullmatch(body) or _PLACEHOLDER_BODY.fullmatch(body))


# 前端压缩代码里的 `try{n=document.activeElement!==e}`、`flag{Wt=null}` 形状上和
# flag 完全一致，弱/强正则都会命中，然后被当成候选提交出去（既浪费提交配额又污染报表）。
# 真实 flag 体内基本不会出现比较/赋值运算符、HTML 标签或 DOM API，故在此统一剔除；
# 唯一常见的 `=` 是 base64 尾部填充，所以只允许出现在结尾。
_CODE_BODY = re.compile(
    r"""(!==|!==|===|=>|&&|\|\||\bfunction\b|\bvar\b|\breturn\b|document\.|window\.|"""
    r"""getElementById|\.style\b|\.length\b|<\s*/?\s*[a-zA-Z]|/>|javascript:)""",
    re.I)


def looks_like_code_flag(value: str) -> bool:
    """判断 flag 形状命中是否是代码片段而非答案。"""
    if not value:
        return True
    m = re.match(r"(?is)^[A-Za-z0-9_.$]{2,24}\{(.*)\}$", value.strip())
    body = (m.group(1) if m else value).strip()
    if not body:
        return True
    if _CODE_BODY.search(body):
        return True
    if m:
        if "{" in body or "}" in body:
            return True
        if "=" in body.rstrip("="):      # 非尾部填充的等号 → 赋值语句
            return True
    return False

def scan_flags(data: bytes, strong_only: bool = False) -> List[str]:
    """在字节数据中搜索 flag，返回去重后的字符串列表。
    strong_only=True 时只认 flag{}/已知前缀（用于自身会产生变换结果的解码场景）。
    大文件按 4MB 窗口滑动扫描（窗口重叠 256 字节），覆盖全文件且控制正则回溯成本。"""
    if not data:
        return []
    found = []
    pats = [FLAG_STRONG, FLAG_KV]
    if not strong_only:
        pats.append(FLAG_WEAK)
    if len(data) <= SCAN_WINDOW:
        windows = [data]
    else:
        windows = []
        step = SCAN_WINDOW - SCAN_OVERLAP
        start = 0
        while start < len(data):
            windows.append(data[start:start + SCAN_WINDOW])
            if start + SCAN_WINDOW >= len(data):
                break
            start += step
    # flag 必为可打印文本：只在提取出的 ASCII / UTF-16LE 字符串上匹配，
    # 既覆盖明文 flag，又避免在高熵二进制（如 cubin 符号段）上灾难性回溯
    for chunk in windows:
        runs = re.findall(rb"[\x20-\x7e]{4,}", chunk)
        try:
            u16 = chunk.decode("utf-16-le", errors="ignore")
            runs.extend(m.group().encode("latin-1", "ignore")
                        for m in re.finditer(r"[\x20-\x7e]{4,}", u16))
        except Exception:
            pass
        target = b"\n".join(runs)
        for pat in pats:
            for m in re.finditer(pat, target):
                try:
                    s = m.group().decode("utf-8", errors="replace").strip()
                except Exception:
                    continue
                if is_placeholder_flag(s):
                    continue
                if looks_like_code_flag(s):
                    continue
                if s not in found:
                    found.append(s)
    return found


def scan_flags_text(text: str) -> List[str]:
    if not text:
        return []
    return scan_flags(text.encode("utf-8", errors="ignore"))

# ----------------------------------------------------------------------------
# 数学/字节工具
# ----------------------------------------------------------------------------()
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    cnt = [0] * 256
    for b in data:
        cnt[b] += 1
    n = len(data)
    e = 0.0
    for c in cnt:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e


def block_entropies(data: bytes, block: int = 256) -> List[float]:
    return [shannon_entropy(data[i:i + block]) for i in range(0, len(data), block)]


def extract_strings(data: bytes, min_len: int = 5) -> List[str]:
    """提取 ASCII 与 UTF-16LE 可打印字符串（C 层正则，大文件快速）。"""
    results = [m.group().decode("ascii")
               for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data)]
    # UTF-16LE
    try:
        txt = data.decode("utf-16-le", errors="ignore")
        for m in re.finditer(r"[\x20-\x7e]{%d,}" % min_len, txt):
            results.append(m.group())
    except Exception:
        pass
    return results


def file_hashes(path: str) -> dict:
    h = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    crc = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            for v in h.values():
                v.update(chunk)
            crc = binascii.crc32(chunk, crc)
    out = {k: v.hexdigest() for k, v in h.items()}
    out["crc32"] = "%08x" % (crc & 0xffffffff)
    return out


def try_decode_text(data: bytes):
    """判断字节数据是否像文本，返回 (is_text, encoding, text)。"""
    if len(data) > 2_000_000:
        sample = data[:2_000_000]
    else:
        sample = data
    for enc in ("utf-8", "gbk", "gb18030", "utf-16", "latin-1"):
        try:
            text = sample.decode(enc)
        except Exception:
            continue
        printable = sum(1 for ch in text if ch in "\r\n\t" or 32 <= ord(ch) < 0x3000 or ord(ch) >= 0x4e00)
        ratio = printable / max(1, len(text))
        if ratio > 0.92:
            full = data.decode(enc, errors="replace")
            return True, enc, full
    return False, None, None


def b64_try_decode(s: str) -> Optional[bytes]:
    """宽容的 base64 解码尝试。"""
    t = s.strip().strip('"').strip("'").replace("\n", "").replace("\r", "").replace(" ", "")
    # 去掉明显非字母表尾巴
    m = re.match(r"^[A-Za-z0-9+/=_-]+$", t)
    if not m or len(t) < 4:
        return None
    try:
        if "-" in t or "_" in t:
            pad = "=" * (-len(t) % 4)
            return base64.urlsafe_b64decode(t + pad)
        pad = t + "=" * (-len(t) % 4)
        return base64.b64decode(pad, validate=False)
    except Exception:
        return None


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f}{unit}" if unit != "B" else f"{n}B"
        n /= 1024.0


# ----------------------------------------------------------------------------
# 产物保存助手
# ----------------------------------------------------------------------------
_INVALID_FN = re.compile(r'[\\/:*?"<>|\r\n\t]+')


def safe_name(name: str) -> str:
    """把任意路径片段清洗成安全的单层文件名/目录名。"""
    name = _INVALID_FN.sub("_", str(name)).strip().strip(".")
    name = re.sub(r"\s+", " ", name)
    return name[:150] or "unnamed"


def save_text(path: str, text: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write(text if isinstance(text, str) else str(text))
    return path


def save_artifact(path: str, data: bytes) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return path


def strings(data: bytes, min_len: int = 5) -> List[str]:
    """extract_strings 的短别名。"""
    return extract_strings(data, min_len)
