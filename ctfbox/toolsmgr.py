# -*- coding: utf-8 -*-
"""工具适配层：检测本机工具、从官方源下载便携版、winget/WSL 引导。"""
import os
import io
import re
import sys
import shutil
import zipfile
import subprocess
import requests
from .common import TOOLS_DIR

# 便携工具相对目录下的可执行文件候选
PORTABLE_TOOLS = {
    "7z":       ["7z.exe", "7za.exe", "7zr.exe"],
    "upx":      ["upx.exe"],
    "die":      ["diec.exe", "DIE.exe", "die.exe"],
    "x64dbg":   ["x64dbg.exe", "x32dbg.exe", "release/x64/x64dbg.exe"],
    "radare2":  ["radare2.exe", "r2.exe", "bin/radare2.exe", "bin/r2.exe"],
    "exiftool": ["exiftool.exe", "exiftool(-k).exe"],
    "sqlmap":   ["sqlmap.py", "sqlmapproject-sqlmap-master/sqlmap.py"],
    "hashcat":  ["hashcat.exe"],
    "dnspy":    ["dnSpy.exe", "dnSpy/dnSpy.exe"],
    "ghidra":   ["ghidraRun.bat"],
    "steghide": ["steghide.exe"],
    "bkcrack":  ["bkcrack.exe"],
    "jadx":     ["bin/jadx.exe", "bin/jadx.bat", "jadx.exe", "jadx.bat"],
    "pycdc":    ["pycdc.exe"],
    "john":     ["run/john.exe", "john.exe"],
    "routerpassview": ["RouterPassView.exe"],
    # —— v2.1 新增便携工具 ——
    "ffmpeg":   ["ffmpeg.exe", "bin/ffmpeg.exe"],
    "ffprobe":  ["ffprobe.exe", "bin/ffprobe.exe"],
    "wabt":     ["wasm2wat.exe", "bin/wasm2wat.exe"],
    # MobaXterm Home 便携版可执行名带版本号（MobaXterm_Personal_<ver>.exe），
    # 固定名候选之外由 detect_one 的 glob 分支兜底
    "mobaxterm": ["MobaXterm_Personal.exe", "MobaXterm.exe"],
}
PATH_TOOLS = {
    "nmap":      ["nmap.exe"],
    "wireshark": ["tshark.exe", "wireshark.exe"],
    "gdb":       ["gdb.exe"],
    "java":      ["java.exe"],
    "git":       ["git.exe"],
    "node":      ["node.exe"],
    "ffmpeg":    ["ffmpeg.exe"],
    "ffprobe":   ["ffprobe.exe"],
}
COMMON_DIRS = {
    "nmap":      [r"C:\Program Files (x86)\Nmap", r"C:\Program Files\Nmap"],
    "wireshark": [r"C:\Program Files\Wireshark"],
    "exiftool":  [r"C:\Program Files\Exiftool", r"C:\Program Files (x86)\Exiftool"],
    "java":      [r"C:\Program Files\Microsoft\jdk-21*", r"C:\Program Files\Java\*"],
    "ghidra":    [r"C:\ghidra*", r"D:\ghidra*", r"C:\Program Files\ghidra*"],
    "gdb":       [r"D:\mingw64\bin"],
}

# 工具中心展示的元数据
TOOL_META = {
    "7z":       ("7-Zip", "压缩/解压/RAR/7z/加密压缩包爆破底座", "portable"),
    "upx":      ("UPX", "UPX 壳自动脱壳", "portable"),
    "die":      ("Detect It Easy", "专业查壳/编译器识别", "portable"),
    "x64dbg":   ("x64dbg", "Windows 动态调试器(开源, 替代 x64 OD)", "portable"),
    "radare2":  ("radare2", "开源逆向分析框架(命令行 IDA 平替)", "portable"),
    "exiftool": ("ExifTool", "元数据/EXIF 深度提取", "winget:OliverBetz.ExifTool"),
    "sqlmap":   ("sqlmap", "SQL 注入自动化(仅限授权靶场)", "portable"),
    "hashcat":  ("hashcat", "GPU/CPU 哈希爆破", "portable"),
    "dnspy":    ("dnSpy", ".NET 反编译/调试(开源)", "portable"),
    "ghidra":   ("Ghidra", "NSA 开源反编译器(IDA 平替, 约400MB, 自动配便携JRE21)", "portable"),
    "nmap":     ("Nmap", "端口/服务/漏洞扫描(系统级, winget)", "winget:Insecure.Nmap"),
    "wireshark":("Wireshark/tshark", "抓包与深度流量分析(系统级, winget)", "winget:WiresharkFoundation.Wireshark"),
    "java":     ("便携 JRE 21 (Temurin)", "Ghidra/jadx 等 Java 工具运行环境(主目录便携, 自动下载)", "runtime:jre"),
    "gdb":      ("GDB", "Linux/MinGW 动态调试 + pwndbg", "path"),
    "steghide": ("StegHide", "JPEG/WAV 隐写提取(需口令字典)", "guide:https://steghide.sourceforge.net/"),
    "bkcrack":  ("bkcrack", "ZIP 已知明文/明文校验攻击，恢复内部密钥后生成无密码压缩包", "portable"),
    "jadx":     ("jadx", "Android APK/DEX 反编译为 Java 源码(自带JRE)", "portable"),
    "ffmpeg":   ("FFmpeg", "音视频转码/抽帧/音轨，媒体中心播放与分析底座", "portable"),
    "wabt":     ("WABT", "WebAssembly 工具集(wasm2wat/wasm-decompile)", "portable"),
    "mobaxterm": ("MobaXterm Home", "SSH/串口/SFTP/FTP/X11/多标签终端，Xshell 免费平替(官方便携版)", "portable"),
    "node":     ("Node.js 便携版", "执行 AAencode/JSFuck/Jother 等 JS 编码(主目录便携)", "runtime:node"),
    "python":   ("便携 Python 3.11", "运行 sqlmap/volatility3/binwalk 等 Python 工具(主目录便携, 已预装取证模块)", "runtime:python"),
    "pycdc":    ("pycdc", "Python 字节码(.pyc)反编译器(Cheetah, 优于uncompyle6)", "guide:https://github.com/zrax/pycdc/releases"),
    "john":     ("John the Ripper", "通用哈希/压缩包口令爆破(jumbo版)", "guide:https://www.openwall.com/john/"),
    "routerpassview": ("RouterPassView", "路由器 config.bin/NVRAM 备份解析导出", "guide:https://www.nirsoft.net/utils/router_password_recovery.html"),
    "autopsy":  ("Autopsy", "图形化数字取证平台(需安装, 官网指引)", "guide:https://www.autopsy.com/download/"),
    "volatility3": ("Volatility 3", "内存取证框架(pip)", "pip:volatility3"),
    "binwalk":  ("binwalk", "固件/内嵌文件分析(pip)", "pip:binwalk"),
    "kali":     ("Kali Linux (WSL2)", "Kali 全套工具(apt 源, 含 foremost/zsteg/steghide/john 等; 无法文件夹便携)", "wsl"),
}

# ----------------------------------------------------------------------------
# 便携运行时（统一放在软件主目录 tools/runtime，换机无环境也能用）
# ----------------------------------------------------------------------------
RUNTIME_DIR = os.path.join(os.path.dirname(TOOLS_DIR), "runtime")
# 运行时安装后其 bin 目录的相对 glob（在 add_runtime_to_path / 检测时使用）
_RUNTIME_BIN_GLOBS = {
    "jre":    ["jre/bin", "jdk*/bin", "temurin*/bin"],
    "node":   ["node/node*", "node-v*", "node"],
    "ffmpeg": ["ffmpeg/bin", "ffmpeg*/bin", "ffmpeg/ffmpeg*/bin"],
    "python": ["python", "python/Scripts"],
}


def _runtime_bins():
    """返回当前已存在的所有运行时可执行目录（绝对路径）。"""
    import glob
    bins = []
    if not os.path.isdir(RUNTIME_DIR):
        return bins
    for rt, patterns in _RUNTIME_BIN_GLOBS.items():
        for pat in patterns:
            for d in glob.glob(os.path.join(RUNTIME_DIR, pat.replace("/", os.sep))):
                if os.path.isdir(d) and d not in bins:
                    bins.append(d)
    return bins


def add_runtime_to_path():
    """把已下载的便携运行时目录加入当前进程 PATH（离线、无网络，仅在存在时生效）。
    在模块导入时调用一次，使 shutil.which / 各子进程能找到便携 java/node/ffmpeg。"""
    for d in _runtime_bins():
        if d not in os.environ.get("PATH", ""):
            os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")
    # Ghidra 需要 JAVA_HOME
    if not os.environ.get("JAVA_HOME"):
        java = shutil.which("java")
        if java and os.path.basename(os.path.dirname(java)).lower() == "bin":
            jhome = os.path.dirname(os.path.dirname(java))
            if os.path.isdir(os.path.join(jhome, "bin")) and "runtime" in jhome.lower():
                os.environ["JAVA_HOME"] = jhome


add_runtime_to_path()

_cache = {}

def _walk_find(root, names):
    """按 names 的优先级顺序匹配（避免 os.walk 文件顺序导致选到 GUI 版）。"""
    allfiles = []
    for dirpath, _, files in os.walk(root):
        for fn in files:
            allfiles.append(os.path.join(dirpath, fn))
    for rel in names:
        target = rel.lower().split("/")[-1]
        for f in allfiles:
            if os.path.basename(f).lower() == target:
                return f
    return None

def detect_one(name: str):
    """返回可执行路径/标识，或 None。"""
    if name in _cache:
        return _cache[name]
    add_runtime_to_path()   # 运行时可能在本会话内刚下载好，刷新 PATH
    result = None
    # 1. 软件自带便携目录优先（自包含、版本可控，避免命中系统里的老旧版本，
    #    例如系统 PATH 中 2013 年的旧 ffmpeg 会缺少 -hide_banner 等参数）
    if name in PORTABLE_TOOLS:
        pdir = os.path.join(TOOLS_DIR, name)
        if os.path.isdir(pdir):
            for rel in PORTABLE_TOOLS[name]:
                cand = os.path.join(pdir, rel)
                if os.path.exists(cand):
                    result = cand
                    break
            if not result:
                result = _walk_find(pdir, PORTABLE_TOOLS[name])
    # ffprobe / ffplay 与便携 ffmpeg 同目录分发（BtbN GPL 包三件套齐全）
    if not result and name in ("ffprobe", "ffplay"):
        ff = detect_one("ffmpeg")
        if ff and "portable" in ff:
            cand = os.path.join(os.path.dirname(ff), name + ".exe")
            if os.path.exists(cand):
                result = cand
    # MobaXterm 便携版 exe 名带版本号（MobaXterm_Personal_26.5.exe），用 glob 兜底
    if not result and name == "mobaxterm":
        import glob as _glob
        pdir = os.path.join(TOOLS_DIR, "mobaxterm")
        hits = sorted(_glob.glob(os.path.join(pdir, "**", "MobaXterm_Personal_*.exe"),
                                 recursive=True))
        if not hits:
            hits = sorted(_glob.glob(os.path.join(pdir, "**", "MobaXterm*.exe"),
                                     recursive=True))
        if hits:
            result = hits[0]
    # 1b. PATH_TOOLS 里有些也随包便携分发（nmap、tshark 等），先在自带目录找，
    #     否则只有系统 PATH 命中才算可用，随包放了也等于没放。
    if not result and name in PATH_TOOLS:
        pdir = os.path.join(TOOLS_DIR, name)
        if os.path.isdir(pdir):
            result = _walk_find(pdir, PATH_TOOLS[name])
    # 2. PATH（便携运行时 bin 已在导入时前置，故随包 node/java 会优先于系统版本命中）
    if not result and name in PATH_TOOLS:
        for exe in PATH_TOOLS[name]:
            p = shutil.which(exe)
            if p:
                result = p
                break
    # 3. 常见安装目录
    if not result and name in COMMON_DIRS:
        import glob
        for pat in COMMON_DIRS[name]:
            for d in glob.glob(pat):
                exe = (PATH_TOOLS.get(name) or PORTABLE_TOOLS.get(name) or [name + ".exe"])[0]
                cand = os.path.join(d, exe)
                if os.path.exists(cand):
                    result = cand
                    break
            if result:
                break
    # 4. sqlmap 特殊：python 脚本
    if not result and name == "sqlmap":
        p = _walk_find(os.path.join(TOOLS_DIR, "sqlmap"), ["sqlmap.py"])
        result = p
    # 5. pip 包：先查随包便携 Python（离线也能用），再查系统 Python
    if not result and name in ("volatility3", "binwalk"):
        from .common import external_python
        mod = "volatility3" if name == "volatility3" else "binwalk"
        candidates = []
        bundled = os.path.join(RUNTIME_DIR, "python", "python.exe")
        if os.path.isfile(bundled):
            candidates.append(bundled)
        py = external_python()
        if py and py not in candidates:
            candidates.append(py)
        for candidate in candidates:
            try:
                r = subprocess.run([candidate, "-c", f"import {mod}"],
                                   capture_output=True, timeout=20)
                if r.returncode == 0:
                    result = f"pip:{name}"
                    break
            except Exception:
                continue
    # 6. WSL kali
    if name == "kali":
        try:
            r = subprocess.run(["wsl", "-l", "-q"], capture_output=True, timeout=15)
            txt = r.stdout.decode("utf-16-le", errors="ignore") + r.stdout.decode("utf-8", errors="ignore")
            if "kali" in txt.lower():
                result = "wsl:kali-linux"
        except Exception:
            pass
    _cache[name] = result
    return result

def detect_all():
    return {name: detect_one(name) for name in TOOL_META}

def get_tool(name: str):
    return detect_one(name)

def launch(name: str, extra_args=None, filepath=None):
    """非阻塞启动外部工具。"""
    p = detect_one(name)
    if not p:
        return False, "工具未安装"
    args = []
    if name == "sqlmap":
        from .common import external_python
        py = external_python()
        if not py:
            return False, "需要系统 Python 才能运行 sqlmap"
        args = [py, p] + (extra_args or [])
    elif name in ("ghidra",):
        args = ["cmd", "/c", p] + (extra_args or [])
    else:
        args = [p] + (extra_args or [])
    if filepath:
        args.append(filepath)
    try:
        env = dict(os.environ)
        rt = _runtime_bins()
        if rt:
            env["PATH"] = os.pathsep.join(rt) + os.pathsep + env.get("PATH", "")
        # Ghidra 需要 JAVA_HOME 指向便携 JRE
        if name == "ghidra" and not env.get("JAVA_HOME"):
            jre_root = _runtime_root("jre")
            if jre_root:
                env["JAVA_HOME"] = jre_root
        subprocess.Popen(args, cwd=os.path.dirname(p) if os.path.exists(p) else None, env=env)
        return True, " ".join(args)
    except Exception as e:
        return False, str(e)


def _runtime_root(rt: str):
    """返回某运行时的根目录（JAVA_HOME 用），找不到返回 None。"""
    import glob
    if not os.path.isdir(RUNTIME_DIR):
        return None
    if rt == "jre":
        for pat in ("jre", "jdk*", "temurin*"):
            hits = sorted(glob.glob(os.path.join(RUNTIME_DIR, pat)))
            for h in hits:
                if os.path.isfile(os.path.join(h, "bin", "java.exe")):
                    return h
    if rt == "node":
        for pat in ("node", "node*"):
            hits = sorted(glob.glob(os.path.join(RUNTIME_DIR, pat)))
            for h in hits:
                if os.path.isfile(os.path.join(h, "node.exe")):
                    return h
    if rt == "python":
        cand = os.path.join(RUNTIME_DIR, "python")
        if os.path.isfile(os.path.join(cand, "python.exe")):
            return cand
    return None

# ----------------------------------------------------------------------------
# 下载
# ----------------------------------------------------------------------------
def _gh_latest(repo):
    r = requests.get(f"https://api.github.com/repos/{repo}/releases/latest", timeout=30,
                     headers={"Accept": "application/vnd.github+json"})
    r.raise_for_status()
    return r.json()

# GitHub 下载加速镜像（直连失败时依次回退；仅用于官方 github.com release 资产）
GH_MIRRORS = [
    "",  # 官方直连优先
    "https://gh-proxy.com/",
    "https://ghfast.top/",
    "https://ghproxy.net/",
]

def _candidate_urls(url):
    urls = [url]
    if "://github.com/" in url or "://objects.githubusercontent.com" in url:
        for m in GH_MIRRORS[1:]:
            urls.append(m + url)
    return urls

def _download(url, dest, progress=None, log=print):
    last_err = None
    for i, u in enumerate(_candidate_urls(url)):
        for attempt in range(2):
            try:
                tag = "官方直连" if i == 0 else f"加速镜像{i}"
                log(f"  下载通道: {tag} (尝试 {attempt + 1})")
                with requests.get(u, stream=True, timeout=60) as r:
                    r.raise_for_status()
                    total = int(r.headers.get("Content-Length", 0))
                    done = 0
                    tmp = dest + ".part"
                    with open(tmp, "wb") as f:
                        for chunk in r.iter_content(1 << 16):
                            f.write(chunk)
                            done += len(chunk)
                            if progress and total:
                                progress(done, total)
                os.replace(tmp, dest)
                return dest
            except Exception as e:
                last_err = e
                continue
    raise last_err

def _extract(arc, dest, sevenz=None):
    if arc.endswith(".zip"):
        with zipfile.ZipFile(arc) as z:
            z.extractall(dest)
        return True
    if arc.endswith((".7z", ".tar.xz", ".tar.gz")):
        if sevenz and os.path.exists(sevenz):
            r = subprocess.run([sevenz, "x", arc, f"-o{dest}", "-y"],
                               capture_output=True, timeout=600)
            return r.returncode == 0
    return False

def install_portable(name: str, log=print, progress=None):
    """一键下载安装便携工具。返回 (bool, msg)。"""
    pdir = os.path.join(TOOLS_DIR, name)
    os.makedirs(pdir, exist_ok=True)
    tmp = os.path.join(TOOLS_DIR, "_dl")
    os.makedirs(tmp, exist_ok=True)
    try:
        if name == "7z":
            rel = _gh_latest("ip7z/7zip")
            assets = {a["name"]: a["browser_download_url"] for a in rel["assets"]}
            sevenzr = next((u for n, u in assets.items() if n == "7zr.exe"), None)
            sevenz_full = next((u for n, u in assets.items()
                                if re.fullmatch(r"7z\d+-extra\.7z", n)), None)
            if not sevenzr or not sevenz_full:
                return False, "未找到 7-Zip 官方资产"
            zr = os.path.join(pdir, "7zr.exe")
            _download(sevenzr, zr, progress)
            arc = os.path.join(tmp, "7zfull.7z")
            _download(sevenz_full, arc, progress)
            r = subprocess.run([zr, "x", arc, f"-o{pdir}", "-y"], capture_output=True, timeout=600)
            if r.returncode != 0:
                return False, "7z 自举解压失败"
            return True, zr
        if name == "upx":
            rel = _gh_latest("upx/upx")
            url = next((a["browser_download_url"] for a in rel["assets"]
                        if "win64.zip" in a["name"] and "debug" not in a["name"]), None)
            if not url:
                return False, "未找到 UPX win64 资产"
            arc = os.path.join(tmp, "upx.zip")
            _download(url, arc, progress)
            _extract(arc, pdir)
            return True, "ok"
        if name == "die":
            rel = _gh_latest("horsicq/DIE-engine")
            cand = None
            for a in rel["assets"]:
                n = a["name"].lower()
                if "win64" in n and ("portable" in n) and n.endswith((".zip", ".7z")):
                    cand = a
                    break
            if not cand:
                return False, "未找到 DIE win64 portable 资产"
            arc = os.path.join(tmp, "die." + cand["name"].rsplit(".", 1)[-1])
            _download(cand["browser_download_url"], arc, progress)
            sz = detect_one("7z")
            if not _extract(arc, pdir, sz):
                return False, "解压失败(7z 资产请先安装 7-Zip)"
            return True, "ok"
        if name == "x64dbg":
            rel = _gh_latest("x64dbg/x64dbg")
            url = next((a["browser_download_url"] for a in rel["assets"]
                        if a["name"].startswith("snapshot") and a["name"].endswith(".zip")), None)
            if not url:
                return False, "未找到 x64dbg snapshot 资产"
            arc = os.path.join(tmp, "x64dbg.zip")
            _download(url, arc, progress)
            _extract(arc, pdir)
            return True, "ok"
        if name == "radare2":
            rel = _gh_latest("radareorg/radare2")
            # 完整 Windows 发行版 radare2-x.y.z-w64.zip（含 bin/radare2.exe 等全套），
            # 排除 r2blob-*-w64.zip（单文件静态 blob）与 -w64-arm64.zip
            url = next((a["browser_download_url"] for a in rel["assets"]
                        if re.fullmatch(r"radare2-[\d.]+-w64\.zip", a["name"])), None)
            if not url:
                return False, "未找到 radare2 w64 完整发行版资产"
            arc = os.path.join(tmp, "r2.zip")
            _download(url, arc, progress)
            _extract(arc, pdir)
            return True, "ok"
        if name == "exiftool":
            arc = os.path.join(tmp, "exiftool.zip")
            # 首选 oliverbetz.de 自包含便携版（exiftool.org 官方收录镜像，
            # ExifTool.exe + exiftool_files 内嵌 Perl 运行时，无需系统安装 Perl）；
            # SourceForge 在部分网络连接超时时作为回退。
            urls = []
            try:
                op = requests.get("https://oliverbetz.de/pages/Artikel/ExifTool-for-Windows",
                                  timeout=30).text
                mo = re.search(r'(/cms/files/Artikel/ExifTool-for-Windows/exiftool-[\d.]+_64\.zip)', op)
                if mo:
                    urls.append("https://oliverbetz.de" + mo.group(1))
            except Exception as e:
                log(f"  oliver 镜像页解析失败: {e}")
            try:
                page = requests.get("https://exiftool.org/", timeout=30).text
                ms = re.search(r"exiftool-(\d[\d.]*)_64\.zip", page)
                if ms:
                    sf = ms.group(0)
                    urls += [
                        f"https://master.dl.sourceforge.net/project/exiftool/{sf}?viasf=1",
                        f"https://downloads.sourceforge.net/project/exiftool/{sf}",
                        f"https://altushost-swe.dl.sourceforge.net/project/exiftool/{sf}",
                    ]
            except Exception:
                pass
            if not urls:
                return False, "未能解析 exiftool 任何下载地址"
            last = None
            for u in urls:
                try:
                    log(f"  尝试: {u}")
                    with requests.get(u, stream=True, timeout=90, allow_redirects=True) as r:
                        r.raise_for_status()
                        with open(arc + ".part", "wb") as f:
                            for chunk in r.iter_content(1 << 16):
                                f.write(chunk)
                    if os.path.getsize(arc + ".part") > 1_000_000:
                        os.replace(arc + ".part", arc)
                        break
                except Exception as e:
                    last = e
                    continue
            if not os.path.exists(arc):
                return False, f"exiftool 全部下载源失败: {last}"
            _extract(arc, pdir)
            # 标准化命名（ExifTool.exe / exiftool(-k).exe -> exiftool.exe，
            # exiftool_files 目录保留在旁边供自包含运行时读取）
            for fn in os.listdir(pdir):
                if fn.lower().startswith("exiftool") and fn.lower().endswith(".exe"):
                    src = os.path.join(pdir, fn)
                    dst = os.path.join(pdir, "exiftool.exe")
                    # Windows 文件系统大小写不敏感：ExifTool.exe 与 exiftool.exe 是同一文件，
                    # os.path.exists/detect 已能按小写匹配命中，无需再复制
                    if os.path.abspath(src).lower() != os.path.abspath(dst).lower():
                        shutil.copy(src, dst)
                    break
            return True, "ok"
        if name == "sqlmap":
            arc = os.path.join(tmp, "sqlmap.zip")
            _download("https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip",
                      arc, progress)
            _extract(arc, pdir)
            return True, "ok"
        if name == "hashcat":
            rel = _gh_latest("hashcat/hashcat")
            a = next((x for x in rel["assets"] if x["name"].endswith(".7z")), None)
            if not a:
                return False, "未找到 hashcat 资产"
            arc = os.path.join(tmp, "hashcat.7z")
            _download(a["browser_download_url"], arc, progress)
            sz = detect_one("7z")
            if not sz or not _extract(arc, pdir, sz):
                return False, "解压失败(需先安装 7-Zip)"
            return True, "ok"
        if name == "dnspy":
            rel = _gh_latest("dnSpyEx/dnSpy")
            a = next((x for x in rel["assets"] if "net-win64.zip" in x["name"]), None)
            if not a:
                return False, "未找到 dnSpy win64 资产"
            arc = os.path.join(tmp, "dnspy.zip")
            _download(a["browser_download_url"], arc, progress)
            _extract(arc, pdir)
            return True, "ok"
        if name == "bkcrack":
            rel = _gh_latest("kimci86/bkcrack")
            a = next((x for x in rel["assets"]
                      if "win" in x["name"].lower() and x["name"].endswith(".zip")), None)
            if not a:
                return False, "未找到 bkcrack Windows 资产"
            arc = os.path.join(tmp, "bkcrack.zip")
            _download(a["browser_download_url"], arc, progress)
            _extract(arc, pdir)
            return True, "ok"
        if name == "jadx":
            rel = _gh_latest("skylot/jadx")
            ver = rel["tag_name"].lstrip("v")
            # 用标准发行包 jadx-<ver>.zip（含 bin/jadx.bat 命令行与 bin/jadx-gui.bat），
            # 配合软件内置便携 JRE21 运行；with-jre 的 GUI 包只有原生 GUI exe、没有 CLI。
            a = next((x for x in rel["assets"] if x["name"] == f"jadx-{ver}.zip"), None)
            if not a:
                a = next((x for x in rel["assets"]
                          if x["name"].endswith(".zip")
                          and "gui" not in x["name"].lower()
                          and "jre" not in x["name"].lower()), None)
            if not a:
                return False, "未找到 jadx 标准(CLI+GUI) zip 资产"
            arc = os.path.join(tmp, "jadx.zip")
            _download(a["browser_download_url"], arc, progress)
            _extract(arc, pdir)
            return True, "ok"
        if name == "ffmpeg":
            rel = _gh_latest("BtbN/FFmpeg-Builds")
            a = next((x for x in rel["assets"]
                      if x["name"] == "ffmpeg-master-latest-win64-gpl.zip"), None)
            if not a:
                a = next((x for x in rel["assets"]
                          if "win64-gpl.zip" in x["name"] and "shared" not in x["name"]), None)
            if not a:
                return False, "未找到 FFmpeg win64-gpl 资产"
            arc = os.path.join(tmp, "ffmpeg.zip")
            _download(a["browser_download_url"], arc, progress, log)
            _extract(arc, pdir)
            return True, "ok"
        if name == "wabt":
            rel = _gh_latest("WebAssembly/wabt")
            wins = [x for x in rel["assets"]
                    if "windows" in x["name"].lower()
                    and x["name"].lower().endswith((".tar.gz", ".zip"))]
            # 优先 x64 桌面版（排除 arm64/特殊构建）
            wins.sort(key=lambda x: 0 if ("x64" in x["name"].lower()
                                          and "arm" not in x["name"].lower()) else 1)
            a = wins[0] if wins else None
            if not a:
                return False, "未找到 wabt windows 资产"
            lname = a["name"].lower()
            if lname.endswith(".tar.gz"):
                arc = os.path.join(tmp, "wabt.tar.gz")
            else:
                arc = os.path.join(tmp, "wabt.zip")
            _download(a["browser_download_url"], arc, progress, log)
            if arc.endswith(".tar.gz"):
                import tarfile
                with tarfile.open(arc, "r:gz") as tf:
                    tf.extractall(pdir)
            else:
                _extract(arc, pdir)
            return True, "ok"
        if name == "ghidra":
            # Ghidra 约 400MB；自动确保便携 JRE21
            if not detect_one("java"):
                log("[*] Ghidra 需要 Java，先下载便携 JRE 21 …")
                okj, msgj = install_runtime("jre", log=log, progress=progress)
                if not okj:
                    return False, "Ghidra 便携 JRE 下载失败: " + msgj
            rel = _gh_latest("NationalSecurityAgency/ghidra")
            a = next((x for x in rel["assets"]
                      if x["name"].startswith("ghidra_") and x["name"].endswith(".zip")
                      and "PUBLIC" in x["name"].upper()), None)
            if not a:
                return False, "未找到 Ghidra PUBLIC zip 资产"
            arc = os.path.join(tmp, "ghidra.zip")
            _download(a["browser_download_url"], arc, progress, log)
            _extract(arc, pdir)
            return True, "ok（已配便携 JRE）"
        if name == "mobaxterm":
            # MobaXterm Home（免费）便携版，官方下载页的直链目录 hash 随版本变化，动态解析取最新
            page = requests.get(
                "https://mobaxterm.mobatek.net/download-home-edition.html",
                timeout=40, headers={"User-Agent": "Mozilla/5.0"}).text
            links = re.findall(r'https?://download\.mobatek\.net/\d+/MobaXterm_Portable_v[\d.]+\.zip',
                               page)

            def _mver(u):
                mm = re.search(r'_v([\d.]+)\.zip', u)
                return tuple(int(x) for x in mm.group(1).split(".")) if mm else (0,)

            links = sorted(set(links), key=_mver)
            if not links:
                return False, "未能从官网解析 MobaXterm 便携版地址"
            arc = os.path.join(tmp, "mobaxterm.zip")
            _download(links[-1], arc, progress, log)
            _extract(arc, pdir)
            return True, "ok（MobaXterm Home 便携版）"
        if name == "steghide":
            return False, "请从 SourceForge 官方页下载 steghide win32 构建"
        return False, f"未知工具 {name}"
    except requests.RequestException as e:
        return False, f"网络错误: {e}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    finally:
        _cache.clear()

def winget_install(pkg_id: str):
    try:
        r = subprocess.run(["winget", "install", "--id", pkg_id, "-e",
                            "--accept-package-agreements", "--accept-source-agreements"],
                           capture_output=True, timeout=1800)
        return r.returncode == 0, (r.stdout + r.stderr).decode("utf-8", "replace")[-3000:]
    except Exception as e:
        return False, str(e)

def pip_install(pkg: str):
    from .common import external_python
    py = external_python()
    if not py:
        return False, "打包环境未检测到系统 Python，请先安装 Python 3 或使用源码版"
    try:
        r = subprocess.run([py, "-m", "pip", "install", pkg],
                           capture_output=True, timeout=900)
        return r.returncode == 0, (r.stdout + r.stderr).decode("utf-8", "replace")[-3000:]
    except Exception as e:
        return False, str(e)

def wsl_install_kali(log=print):
    try:
        r = subprocess.run(["wsl", "--install", "-d", "kali-linux"],
                           capture_output=True, timeout=1800)
        ok = r.returncode == 0
        return ok, (r.stdout + r.stderr).decode("utf-8", "replace")[-3000:]
    except Exception as e:
        return False, str(e)

def wsl_kali_setup_tools(log=print):
    """在 Kali 中安装 CTF 常用套件（root 执行）。"""
    cmd = ("export DEBIAN_FRONTEND=noninteractive && apt update && "
           "apt install -y foremost scalpel steghide stegseek zsteg john hashcat "
           "testdisk volatility3 binwalk radare2 gdb pwndbg nmap sqlmap nikto gobuster "
           "wireshark tcpdump netcat-traditional socat exploitdb "
           "python3-pwntools ruby ruby-dev && gem install zsteg")
    try:
        r = subprocess.run(["wsl", "-d", "kali-linux", "-u", "root", "--", "bash", "-c", cmd],
                           capture_output=True, timeout=3600)
        return r.returncode == 0, (r.stdout + r.stderr).decode("utf-8", "replace")[-4000:]
    except Exception as e:
        return False, str(e)


# ----------------------------------------------------------------------------
# 便携运行时：JRE21 / Node / FFmpeg 统一下载到软件主目录 tools/runtime
# ----------------------------------------------------------------------------
def install_runtime(rt, log=print, progress=None, force=False):
    """下载并配置便携运行时（解压即用，不写系统、不需要管理员）。返回 (bool, msg)。
    force=True 时只认软件目录内的便携副本，不因系统 PATH 已存在而跳过（用于离线分发预置）。"""
    os.makedirs(RUNTIME_DIR, exist_ok=True)
    tmp = os.path.join(TOOLS_DIR, "_dl")
    os.makedirs(tmp, exist_ok=True)
    try:
        if rt == "jre":
            local = _runtime_root("jre")
            if local or (not force and shutil.which("java")):
                return True, "已存在便携 Java，跳过" if local else "系统已存在 Java，跳过（如需随包分发请用强制预置）"
            url = ("https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jre/"
                   "hotspot/normal/eclipse?project=jdk")
            arc = os.path.join(tmp, "temurin-jre21.zip")
            _download(url, arc, progress, log)
            with zipfile.ZipFile(arc) as z:
                z.extractall(RUNTIME_DIR)
            add_runtime_to_path()
            return True, "便携 JRE 21 已安装到 tools/runtime"
        if rt == "node":
            local = _runtime_root("node")
            if local or (not force and shutil.which("node")):
                return True, "已存在便携 Node，跳过" if local else "系统已存在 Node，跳过（如需随包分发请用强制预置）"
            idx = requests.get("https://nodejs.org/dist/index.json", timeout=30).json()
            ver = None
            for x in idx:
                if x.get("lts") and x["version"].startswith("v22"):
                    ver = x["version"]; break
            if not ver:
                ver = idx[0]["version"]
            url = f"https://nodejs.org/dist/{ver}/node-{ver}-win-x64.zip"
            arc = os.path.join(tmp, "node.zip")
            _download(url, arc, progress, log)
            with zipfile.ZipFile(arc) as z:
                z.extractall(RUNTIME_DIR)
            add_runtime_to_path()
            return True, f"便携 Node {ver} 已安装到 tools/runtime"
        if rt == "python":
            local = _runtime_root("python")
            if local and not force:
                return True, "已存在便携 Python，跳过"
            # astral/python-build-standalone：可重定位、免安装的官方 CPython 构建。
            # 选 3.11：binwalk v2.3.4（CTF 常用、纯 Python）依赖 3.12 已移除的 imp 模块；
            # volatility3 在 3.11 同样有官方 wheel。
            rel = _gh_latest("indygreg/python-build-standalone")
            asset = next((a for a in rel["assets"]
                          if re.fullmatch(r"cpython-3\.11[\d.]*\+\d+-x86_64-pc-windows-msvc-install_only\.tar\.gz",
                                          a["name"])), None)
            if not asset:
                asset = next((a for a in rel["assets"]
                              if "cpython-3.11" in a["name"]
                              and "x86_64-pc-windows-msvc-install_only.tar.gz" in a["name"]), None)
            if not asset:
                return False, "未找到 python-build-standalone(3.11) Windows 资产"
            arc = os.path.join(tmp, "python-standalone.tar.gz")
            _download(asset["browser_download_url"], arc, progress, log)
            pydir = os.path.join(RUNTIME_DIR, "python")
            if os.path.isdir(pydir):
                shutil.rmtree(pydir, ignore_errors=True)
            import tarfile
            with tarfile.open(arc, "r:gz") as tf:
                tf.extractall(RUNTIME_DIR)   # 解出 RUNTIME_DIR/python
            py = os.path.join(pydir, "python.exe")
            if not os.path.exists(py):
                return False, "便携 Python 解压后未找到 python.exe"
            add_runtime_to_path()

            def _pip(args, timeout=1800):
                return subprocess.run([py, "-m", "pip", "install", "--disable-pip-version-check", *args],
                                      capture_output=True, timeout=timeout)
            log("[*] 便携 Python 预装 volatility3 / binwalk（首次需联网下载 wheel）…")
            subprocess.run([py, "-m", "pip", "install", "--upgrade",
                            "--disable-pip-version-check", "pip"],
                           capture_output=True, timeout=600)
            r1 = _pip(["volatility3"])
            # PyPI 上的 binwalk 2.1.0 是空占位包；改装官方 v2.3.4 源码（含 binwalk.core，纯 Python）
            r2 = _pip(["https://github.com/ReFirmLabs/binwalk/archive/refs/tags/v2.3.4.zip"])
            ok_vol = subprocess.run([py, "-c", "import volatility3"],
                                    capture_output=True, timeout=60).returncode == 0
            ok_bw = subprocess.run([py, "-c", "import binwalk, binwalk.core"],
                                   capture_output=True, timeout=60).returncode == 0
            if not ok_bw:  # 兜底：直接把纯 Python 包目录复制进 site-packages
                try:
                    import zipfile as _zf
                    bz = os.path.join(tmp, "binwalk-2.3.4.zip")
                    if not os.path.exists(bz):
                        _download("https://github.com/ReFirmLabs/binwalk/archive/refs/tags/v2.3.4.zip",
                                  bz, progress, log)
                    ex = os.path.join(tmp, "binwalk-src")
                    shutil.rmtree(ex, ignore_errors=True)
                    os.makedirs(ex, exist_ok=True)
                    with _zf.ZipFile(bz) as z:
                        z.extractall(ex)
                    site = os.path.join(pydir, "Lib", "site-packages")
                    dst = os.path.join(site, "binwalk")
                    shutil.rmtree(dst, ignore_errors=True)
                    shutil.copytree(os.path.join(ex, "binwalk-2.3.4", "src", "binwalk"), dst)
                    ok_bw = subprocess.run([py, "-c", "import binwalk, binwalk.core"],
                                           capture_output=True, timeout=60).returncode == 0
                except Exception as e:
                    log(f"  binwalk 兜底安装失败: {e}")
            # Windows 兼容补丁：binwalk v2.3.4 的 extractor 无条件 import pwd（Unix 专属），
            # 会在加载模块时崩溃。改为可选导入，并在无 pwd 时跳过 runas 逻辑。
            try:
                ext_py = os.path.join(pydir, "Lib", "site-packages", "binwalk",
                                      "modules", "extractor.py")
                if os.path.exists(ext_py):
                    with open(ext_py, "r", encoding="utf-8") as f:
                        src = f.read()
                    if "import pwd\n" in src and "except ImportError:\n    pwd = None" not in src:
                        src = src.replace("import pwd\n",
                                          "try:\n    import pwd  # Unix-only\n"
                                          "except ImportError:\n    pwd = None\n", 1)
                    src = src.replace("        if self.enabled is True:\n",
                                      "        if self.enabled is True and pwd is not None:\n", 1)
                    with open(ext_py, "w", encoding="utf-8") as f:
                        f.write(src)
                    log("  已应用 binwalk Windows 兼容补丁")
            except Exception as e:
                log(f"  binwalk 补丁异常: {e}")
            # 用模块级导入（会加载 extractor）复验，而不只是 import binwalk.core
            ok_bw = subprocess.run([py, "-c", "import binwalk.modules; print('modules ok')"],
                                   capture_output=True, timeout=60,
                                   stdin=subprocess.DEVNULL).returncode == 0
            if not ok_vol:
                return False, "便携 Python 就绪，但 volatility3 安装失败: " + \
                    (r1.stdout + r1.stderr).decode("utf-8", "replace")[-300:]
            msg = "便携 Python 3.11 已安装并预装 volatility3" + ("+binwalk" if ok_bw else "（binwalk 未成功，可用内置雕刻替代）")
            return True, msg
        if rt == "ffmpeg":
            if _local_portable_present("ffmpeg") or (not force and detect_one("ffmpeg")):
                return True, "FFmpeg 已就绪，跳过"
            return install_portable("ffmpeg", log=log, progress=progress)
        return False, f"未知运行时 {rt}"
    except requests.RequestException as e:
        return False, f"网络错误: {e}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    finally:
        _cache.clear()


def bootstrap_runtimes(log=print, progress=None, want=("jre", "node", "ffmpeg"), force=False):
    """首次启动/一键体检：确保所有便携运行时就绪。force=True 用于离线分发预置。"""
    result = {}
    for rt in want:
        log(f"[*] 检查运行时 {rt} …")
        ok, msg = install_runtime(rt, log=log, progress=progress, force=force)
        result[rt] = (ok, msg)
        log(("[+] " if ok else "[!] ") + f"{rt}: {msg}")
    add_runtime_to_path()
    return result


# ----------------------------------------------------------------------------
# 批量预置：把所有可再发行的开源便携工具一次性下载到 tools/portable
# （用户无需在接口里逐个选择；失败的项目会记录并继续）
# ----------------------------------------------------------------------------
BULK_PORTABLE = ["7z", "upx", "die", "ffmpeg", "sqlmap", "bkcrack", "radare2",
                 "x64dbg", "dnspy", "hashcat", "exiftool", "jadx", "wabt", "ghidra"]
BULK_RUNTIMES = ["jre", "node", "ffmpeg"]


def _local_portable_present(name):
    """仅判断软件目录 tools/portable/<name> 内是否已存在该工具（不看系统 PATH）。"""
    pdir = os.path.join(TOOLS_DIR, name)
    if not os.path.isdir(pdir) or not os.listdir(pdir):
        return False
    rels = PORTABLE_TOOLS.get(name, [])
    for rel in rels:
        if os.path.exists(os.path.join(pdir, rel)):
            return True
    if rels and _walk_find(pdir, rels):
        return True
    # 无候选清单时，目录内存在任意 .exe/.bat/.py 即视为已解压
    for dirpath, _, files in os.walk(pdir):
        if any(f.lower().endswith((".exe", ".bat", ".py")) for f in files):
            return True
    return False


def install_bulk(log=print, progress=None, names=None, skip_present=True, force=False):
    names = names or BULK_PORTABLE
    report = {}
    for name in names:
        try:
            present = _local_portable_present(name) if force else bool(detect_one(name))
            if skip_present and present:
                log(f"[=] {name} 已存在，跳过")
                report[name] = (True, "已存在")
                continue
            log(f"[*] 批量预置下载 {name} …")
            ok, msg = install_portable(name, log=log, progress=progress)
        except Exception as e:
            ok, msg = False, f"{type(e).__name__}: {e}"
        report[name] = (ok, msg)
        log(("[+] " if ok else "[!] ") + f"{name}: {msg}")
        _cache.clear()
    return report


def predownload_all(log=print, progress=None):
    """一键：先运行时后工具，全部强制预置到软件目录（供离线分发，不依赖系统 PATH）。"""
    log("========== 第 1 步：便携运行时 ==========")
    rt = bootstrap_runtimes(log=log, progress=progress, force=True,
                            want=("jre", "node", "python", "ffmpeg"))
    log("========== 第 2 步：开源便携工具 ==========")
    tk = install_bulk(log=log, progress=progress, force=True)
    return {"runtime": rt, "tools": tk}
