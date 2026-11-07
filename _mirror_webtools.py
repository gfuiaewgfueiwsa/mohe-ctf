# -*- coding: utf-8 -*-
"""离线网页工具镜像脚本（由 魔盒-ctf「网页导航 → 重新镜像离线网页」按钮调用）。

功能：把 CyberChef、兽音/熊曰/佛论禅、零宽字符、QRazyBox 等纯前端工具
镜像到 tools/portable/webtools/，断网可用，并生成 manifest.json。

特性：
  * 仅用标准库（便携 Python 3.11+ 可直接跑）；
  * 同站递归抓取静态资源（html/css/js/img/svg/woff...），深度与数量封顶；
  * CyberChef 走 GitHub Releases 官方自包含 HTML 压缩包；
  * 每个站点先下载到临时暂存目录，全部成功后才替换旧镜像，失败保留旧版；
  * 重复运行即增量刷新。

用法：
  python _mirror_webtools.py            # 镜像全部
  python _mirror_webtools.py CyberChef  # 只镜像指定 key
"""
import io
import os
import re
import sys
import json
import shutil
import zipfile
import urllib.parse
import urllib.request
from html.parser import HTMLParser

# ---------------------------------------------------------------------------
# 路径：开发态=工程根/tools/portable/webtools；冻结态=exe 同级 tools/portable/...
# ---------------------------------------------------------------------------
if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(APP_DIR, "tools", "portable", "webtools")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
MAX_FILES = 600          # 单站文件数上限
MAX_BYTES = 300 * 1024 * 1024
TIMEOUT = 25

STATIC_JOBS = [
    # key, 入口URL, 保存入口文件名, 递归深度
    ("zero-width", "https://yuanfux.github.io/zero-width-web/", "index.html", 3),
    ("qrazybox", "https://merri.cx/qrazybox/", "index.html", 3),
    ("pcmoe_roar", "https://hi.pcmoe.net/roar.html", "roar.html", 2),
    ("pcmoe_bear", "https://hi.pcmoe.net/bear.html", "bear.html", 2),
    ("pcmoe_buddha", "https://hi.pcmoe.net/buddha.html", "buddha.html", 2),
]
ENTRY = {k: f for k, _, f, _ in STATIC_JOBS}

ASSET_RE = re.compile(
    r"(?:src|href)\s*=\s*['\"]([^'\"]+)['\"]", re.I)
CSS_URL_RE = re.compile(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)", re.I)


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        for name, val in attrs:
            if name in ("src", "href") and val:
                self.links.append(val)
            if name == "content":
                # <meta http-equiv="refresh" content="0;url=...">
                pass


def _fetch(url, binary=False):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        data = r.read()
        ctype = r.headers.get("Content-Type", "")
    return data, ctype


def _safe_rel_path(url, base_url):
    """把同站 URL 映射成本地相对路径（目录形式用 index.html）。"""
    p = urllib.parse.urlparse(url)
    rel = urllib.parse.unquote(p.path.lstrip("/"))
    if not rel:
        rel = "index.html"
    elif rel.endswith("/"):
        rel += "index.html"
    if "." not in os.path.basename(rel):
        rel = os.path.join(rel, "index.html")
    # 防路径穿越
    rel = rel.replace("\\", "/")
    parts = [x for x in rel.split("/") if x not in ("", ".", "..")]
    return "/".join(parts)


def mirror_static(key, start_url, entry_name, depth, log=print):
    """同站静态递归镜像，返回入口本地绝对路径。"""
    dest = os.path.join(WEB_DIR, key)
    stage = dest + ".new"
    if os.path.isdir(stage):
        shutil.rmtree(stage, ignore_errors=True)
    os.makedirs(stage, exist_ok=True)

    base = urllib.parse.urlparse(start_url)
    base_host = base.netloc
    start_save = entry_name
    queue = [(start_url, start_save, 0)]
    seen = set()
    nfiles = 0
    nbytes = 0

    while queue:
        url, rel, d = queue.pop(0)
        if url in seen or nfiles >= MAX_FILES or nbytes >= MAX_BYTES:
            continue
        seen.add(url)
        try:
            data, ctype = _fetch(url)
        except Exception as e:
            log(f"  [-] 跳过 {url}: {e}")
            continue
        local = os.path.join(stage, *rel.split("/"))
        os.makedirs(os.path.dirname(local), exist_ok=True)
        with open(local, "wb") as f:
            f.write(data)
        nfiles += 1
        nbytes += len(data)
        is_html = b"<html" in data[:2000].lower() or rel.endswith((".html", ".htm"))
        is_css = "css" in ctype or rel.endswith(".css")
        text = data.decode("utf-8", "replace")
        links = []
        if is_html:
            p = _LinkParser()
            p.feed(text)
            links = p.links
            # 内联样式中的 url() 顺带扫描
            links += CSS_URL_RE.findall(text)
        elif is_css:
            links = CSS_URL_RE.findall(text)
        if d >= depth:
            continue
        for raw in links:
            raw = raw.strip()
            if not raw or raw.startswith(("#", "data:", "javascript:", "mailto:")):
                continue
            u = urllib.parse.urljoin(url, raw.split("#")[0])
            # 对含空格/特殊字符的 URL 做百分号编码（如 "problem (1).png"）
            pu = urllib.parse.urlparse(u)
            u = urllib.parse.urlunparse((
                pu.scheme, pu.netloc,
                urllib.parse.quote(pu.path, safe="/%:@"),
                pu.params,
                urllib.parse.quote(pu.query, safe="=&?/%:"),
                pu.fragment))
            pu = urllib.parse.urlparse(u)
            if pu.scheme not in ("http", "https") or pu.netloc != base_host:
                continue
            r2 = _safe_rel_path(u, start_url)
            if r2 and u not in seen:
                queue.append((u, r2, d + 1))
    # 确保入口文件存在（部分站点入口名与路径不一致时兜底重命名）
    entry_local = os.path.join(stage, entry_name)
    if not os.path.exists(entry_local):
        guess = os.path.join(stage, _safe_rel_path(start_url, start_url))
        if os.path.exists(guess) and guess != entry_local:
            shutil.copy2(guess, entry_local)
    if not os.path.exists(entry_local):
        raise RuntimeError(f"{key}: 镜像完成但入口 {entry_name} 缺失")
    # 成功后替换旧目录
    if os.path.isdir(dest):
        shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    os.replace(stage, dest)
    log(f"  [+] {key}: {nfiles} 文件 / {nbytes // 1024} KB")
    return os.path.join(dest, entry_name)


def mirror_cyberchef(log=print):
    """从 GitHub Releases 下载官方自包含 CyberChef HTML（zip 包）。"""
    import tempfile
    api = "https://api.github.com/repos/gchq/CyberChef/releases/latest"
    try:
        data, _ = _fetch(api)
        rel = json.loads(data.decode("utf-8", "replace"))
    except Exception as e:
        raise RuntimeError(f"获取 CyberChef release 失败: {e}")
    # 官方资产名形如 CyberChef_<commit-hash>.zip（约 80MB，自包含 HTML）
    asset = None
    for a in rel.get("assets", []):
        if re.match(r"CyberChef_.+\.zip$", a.get("name", "")):
            asset = a
            break
    if not asset:
        raise RuntimeError("CyberChef release 未找到 zip 资产")
    log(f"  [*] 下载 {asset['name']} ({asset['size'] // 1024 // 1024} MB)…")
    data, _ = _fetch(asset["browser_download_url"])
    dest = os.path.join(WEB_DIR, "CyberChef")
    stage = dest + ".new"
    if os.path.isdir(stage):
        shutil.rmtree(stage, ignore_errors=True)
    os.makedirs(stage, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        z.extractall(stage)
    htmls = []
    for root, _, files in os.walk(stage):
        for fn in files:
            if fn.lower().endswith((".html", ".htm")):
                htmls.append(os.path.join(root, fn))
    if not htmls:
        raise RuntimeError("CyberChef zip 内未找到 HTML")
    # 主 HTML 复制一份固定名，manifest 好引用
    main_html = max(htmls, key=lambda p: os.path.getsize(p))
    fixed = os.path.join(stage, "CyberChef_latest.html")
    if os.path.abspath(main_html) != os.path.abspath(fixed):
        shutil.copy2(main_html, fixed)
    if os.path.isdir(dest):
        shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    os.replace(stage, dest)
    log(f"  [+] CyberChef: {os.path.basename(main_html)}")
    return os.path.join(dest, "CyberChef_latest.html")


def write_manifest(paths, log=print):
    """合并旧 manifest（保留本次未刷新且仍存在的条目）后写回。"""
    mp = os.path.join(WEB_DIR, "manifest.json")
    old = {}
    if os.path.exists(mp):
        try:
            old = json.load(open(mp, encoding="utf-8")).get("offline", {})
        except Exception:
            old = {}
    merged = dict(old)
    for k, p in paths.items():
        if p and os.path.exists(p):
            # 存相对路径（相对 webtools 目录），整个软件文件夹拷走/改名后仍可用
            merged[k] = os.path.relpath(p, WEB_DIR).replace("\\", "/")
    # 清掉失效条目（兼容旧版绝对路径 manifest）
    def _exists(v):
        return os.path.exists(v) or os.path.exists(os.path.join(WEB_DIR, v))
    merged = {k: v for k, v in merged.items() if _exists(v)}
    os.makedirs(WEB_DIR, exist_ok=True)
    json.dump({"version": 1, "offline": merged},
              open(mp, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    log(f"[+] manifest 已更新: {mp}（{len(merged)} 个离线工具）")


def main(argv):
    only = set(argv)
    os.makedirs(WEB_DIR, exist_ok=True)
    paths = {}
    if not only or "CyberChef" in only:
        print("[*] 镜像 CyberChef（GitHub 官方 release）…")
        try:
            paths["CyberChef"] = mirror_cyberchef()
        except Exception as e:
            print(f"[-] CyberChef 镜像失败，保留旧版: {e}")
    for key, url, entry, depth in STATIC_JOBS:
        if only and key not in only:
            continue
        print(f"[*] 镜像 {key}: {url}")
        try:
            paths[key] = mirror_static(key, url, entry, depth)
        except Exception as e:
            print(f"[-] {key} 镜像失败，保留旧版: {e}")
    write_manifest(paths)
    print("[*] 全部结束，可在软件「网页导航」页点击离线打开验证。")


if __name__ == "__main__":
    main(sys.argv[1:])
