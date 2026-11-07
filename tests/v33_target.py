# -*- coding: utf-8 -*-
"""v3.3.0 本地自建漏洞靶站（仅测试用，绑定 127.0.0.1 随机端口）。

这不是外部靶场样本，而是项目内自建仿真目标，用于验证：
  SQLi 报错、命令注入回显、SSTI、LFI、上传解析、弱口令、CSRF 表单、
  XSS 反射、JWT 弱密钥、IDOR、SSRF file://、XXE、PHP/Pickle 反序列化回显、
  Cookie 弱属性、7z/RAR5 归档链路。

实现只模拟必要的响应，不提供真实 PHP/Java 运行时：
  - 上传的 PHP 仅识别固定 ``<?php echo '...'; ?>`` 模式并回显标记；
  - 反序列化仅解析测试 payload 中的 ``echo`` 标记，不执行系统命令；
  - 所有服务只监听回环地址，随测试进程退出。
"""
import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
          "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")
WININI = "[fonts]\nfor 16-bit app support\n[extensions]\n"
JWT_KEY = b"secret"
JWT_CLAIMS = {"user": "guest", "role": "user", "sub": "1"}


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def make_jwt(claims=None) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    claims = claims or JWT_CLAIMS
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(claims, separators=(",", ":")).encode())
    sig = hmac.new(JWT_KEY, (h + "." + p).encode(), hashlib.sha256).digest()
    return h + "." + p + "." + b64url(sig)


def verify_jwt(token: str) -> dict:
    try:
        h, p, s = token.split(".")
        sign = hmac.new(JWT_KEY, (h + "." + p).encode(), hashlib.sha256).digest()
        if b64url(sign) != s:
            return {}
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p.encode()).decode())
    except Exception:
        return {}


HOME_TEMPLATE = """<!doctype html><html><head><title>Mohe Local CTF v3.3</title></head>
<body><h1>Mohe Local CTF Target</h1>
<script>var jwt = "{token}";</script>
<ul>
<li><a href="/sqli?id=1">item 1</a></li>
<li><a href="/ping?host=127.0.0.1">ping</a></li>
<li><a href="/ssti?name=mohe">hello</a></li>
<li><a href="/lfi?file=about.txt">about</a></li>
<li><a href="/xss?q=hi">search</a></li>
<li><a href="/user?id=1">profile</a></li>
<li><a href="/fetch?url=http://127.0.0.1:{port}/">fetch</a></li>
</ul>
<form action="/login" method="post">
  <input name="username" value="guest"><input name="password" type="password">
  <input type="submit" value="login">
</form>
<form action="/upload" method="post" enctype="multipart/form-data">
  <input type="file" name="file"><input type="submit" value="upload">
</form>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "MoheV33Target/1.0"
    sys_version = ""

    # ---- 基础 -----------------------------------------------------------
    def log_message(self, *args):
        pass

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def _send(self, code: int, body, ctype: str = "text/html; charset=utf-8",
              extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # 故意缺少 HttpOnly/Secure/SameSite，用于 Cookie 审计
        self.send_header("Set-Cookie", "sessionid=mohe-v33-test; Path=/")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _home(self) -> str:
        return HOME_TEMPLATE.format(token=make_jwt(), port=self.port)

    # ---- GET ------------------------------------------------------------
    def do_GET(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query, keep_blank_values=True)

        def q(name, default=""):
            return (qs.get(name) or [default])[0]

        if path == "/":
            # 模拟 PHP/Pickle 反序列化的固定标记回显
            for name in ("data", "payload", "ser", "object", "session", "info", "token"):
                value = q(name, "")
                if not value:
                    continue
                marker = self._deser_marker(value)
                if marker:
                    self._send(200, "DESER-OK " + marker)
                    return
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                claims = verify_jwt(auth[7:])
                if claims and claims.get("role") == "admin":
                    self._send(200, "<html>admin dashboard flag{jwt_local}</html>")
                    return
            self._send(200, self._home())
            return

        if path == "/sqli":
            row = q("id", "1")
            con = sqlite3.connect(":memory:")
            try:
                con.execute("CREATE TABLE items (id INTEGER, name TEXT)")
                con.executemany("INSERT INTO items VALUES (?,?)",
                                [(1, "alpha"), (2, "beta")])
                rows = con.execute("SELECT name FROM items WHERE id = %s" % row).fetchall()
                self._send(200, "<html>items: %s</html>" % ", ".join(r[0] for r in rows))
            except Exception as exc:
                self._send(500, "sqlite3.OperationalError: %s" % exc)
            finally:
                con.close()
            return

        if path == "/sqli-time":
            # 仅用于测试时间盲注取数：解析 IF(ASCII(SUBSTR((select database()),N,1))>M,...)
            payload = q("id", "1")
            m = re.search(
                r"IF\(\((?:ASCII|UNICODE)\(SUBSTR\(\((.*?)\),(\d+),1\)\)>(\d+)\),"
                r"SLEEP\(([\d.]+)\),0\)", payload, re.I)
            const = re.search(r"IF\(\((1=1|1=2)\),SLEEP\(([\d.]+)\),0\)", payload)
            if m:
                expr, pos, mid, secs = m.group(1), int(m.group(2)), int(m.group(3)), float(m.group(4))
                value = "mohectf" if "database()" in expr.lower() else "8.0.0"
                ch = value[pos - 1] if 0 < pos <= len(value) else "\x00"
                if ord(ch) > mid:
                    time.sleep(min(secs, 2.0))
                self._send(200, "ok")
                return
            if const:
                if const.group(1) == "1=1":
                    time.sleep(min(float(const.group(2)), 2.0))
                self._send(200, "ok")
                return
            self._send(200, "ok")
            return

        if path == "/ping":
            host = q("host", "127.0.0.1")
            if "$((9137+1))" in host and "echo" in host:
                self._send(200, "PING output: MOHE9138")
            elif re.search(r"cat\s+/flag", host):
                self._send(200, "flag{cmdi_local}")
            else:
                self._send(200, "PING %s: 64 bytes from 127.0.0.1" % host)
            return

        if path == "/ssti":
            name = q("name", "")
            rendered = re.sub(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}",
                              lambda m: str(int(m.group(1)) * int(m.group(2))), name)
            rendered = re.sub(r"\$\{\s*(\d+)\s*\*\s*(\d+)\s*\}",
                              lambda m: str(int(m.group(1)) * int(m.group(2))), rendered)
            self._send(200, "<html>hello %s</html>" % rendered)
            return

        if path == "/lfi":
            target = q("file", "")
            low = target.lower()
            if "passwd" in low:
                self._send(200, PASSWD, "text/plain")
            elif "win.ini" in low:
                self._send(200, WININI, "text/plain")
            elif "flag" in low:
                self._send(200, "flag{lfi_local}", "text/plain")
            elif "php://filter" in low:
                self._send(200, base64.b64encode(b"<?php echo 'mohe'; ?>").decode())
            elif "environ" in low:
                self._send(200, "PATH=/usr/bin\nHTTP_USER_AGENT=mohe", "text/plain")
            else:
                self._send(200, "about page: local CTF target")
            return

        if path == "/xss":
            value = q("q", "")
            self._send(200, "<html><body>results for %s</body></html>" % value)
            return

        if path == "/user":
            value = q("id", "1")
            if value == "2":
                self._send(200, "flag{idor_local}")
            else:
                self._send(200, "<html>user %s profile</html>" % value)
            return

        if path == "/fetch":
            url = q("url", "")
            low = url.lower()
            if "passwd" in low:
                self._send(200, PASSWD, "text/plain")
            elif "win.ini" in low:
                self._send(200, WININI, "text/plain")
            elif "127.0.0.1" in low or "localhost" in low or "[::1]" in low:
                if "flag" in low:
                    self._send(200, "fetch: not found")
                else:
                    self._send(200, self._home())
            elif "169.254" in low or "100.100" in low or "dict://" in low or "gopher://" in low:
                self._send(502, "connection refused")
            else:
                self._send(200, "fetch result: " + url)
            return

        if path == "/uploads" or path.startswith("/uploads/"):
            name = path.rsplit("/", 1)[-1] or "index.txt"
            self._serve_upload(name)
            return

        if path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin\n", "text/plain")
            return

        self._send(404, "not found")

    # ---- POST -----------------------------------------------------------
    def do_POST(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        ctype = self.headers.get("Content-Type", "")
        if path == "/upload":
            self._handle_upload(body, ctype)
            return
        if path == "/login":
            if "xml" in ctype:
                text = body.decode("utf-8", "replace")
                low = text.lower()
                if "passwd" in low:
                    self._send(200, PASSWD, "text/plain")
                elif "win.ini" in low:
                    self._send(200, WININI, "text/plain")
                else:
                    self._send(200, "<html>xml ok</html>")
                return
            form = parse_qs(body.decode("utf-8", "replace"))
            user = (form.get("username") or [""])[0]
            pwd = (form.get("password") or [""])[0]
            if user == "admin" and pwd == "admin":
                self._send(302, "redirecting", extra={"Location": "/dashboard"})
            else:
                self._send(200, "<html>login failed: invalid credentials</html>")
            return
        if path == "/xml":
            text = body.decode("utf-8", "replace").lower()
            if "passwd" in text:
                self._send(200, PASSWD, "text/plain")
            elif "win.ini" in text:
                self._send(200, WININI, "text/plain")
            else:
                self._send(200, "<xml>ok</xml>")
            return
        self._send(404, "not found")

    # ---- 上传/反序列化仿真 -------------------------------------------------
    def _handle_upload(self, body: bytes, ctype: str):
        match = re.search(r"boundary=([^;]+)", ctype)
        if not match:
            self._send(400, "no boundary")
            return
        boundary = match.group(1).strip().encode()
        filename, data = "", b""
        for part in body.split(b"--" + boundary):
            if b'filename="' not in part:
                continue
            head, _, payload = part.partition(b"\r\n\r\n")
            fm = re.search(rb'filename="([^"]*)"', head)
            if fm:
                filename = fm.group(1).decode("utf-8", "replace")
                data = payload
                if data.endswith(b"\r\n"):
                    data = data[:-2]
                break
        if not filename:
            self._send(400, "no file")
            return
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.basename(filename))
        upload_dir = self.server.upload_dir
        os.makedirs(upload_dir, exist_ok=True)
        with open(os.path.join(upload_dir, safe), "wb") as fp:
            fp.write(data)
        self._send(200, '<html>upload ok: <a href="/uploads/%s">%s</a></html>'
                   % (safe, safe))

    def _serve_upload(self, name: str):
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.basename(name))
        path = os.path.join(self.server.upload_dir, safe)
        if not os.path.isfile(path):
            self._send(404, "not found")
            return
        with open(path, "rb") as fp:
            data = fp.read()
        text = data.decode("utf-8", "replace")
        # 仅模拟固定 PHP 回显：<?php echo 'MARKER'; ?>
        match = re.search(r"<\?php\s+echo\s+'([^']*)'\s*;\s*\?>", text)
        if match:
            self._send(200, match.group(1), "text/html")
            return
        # 仅模拟只读取 flag 的验证脚本
        if safe.lower().startswith("read") and "file_get_contents" in text:
            self._send(200, "flag{upload_rce_local}", "text/plain")
            return
        self._send(200, data, "application/octet-stream")

    @staticmethod
    def _deser_marker(value: str) -> str:
        # PHP 序列化：从 cmd/command 属性里取 echo 标记
        if re.search(r'O:\d+:"', value):
            match = re.search(r's:\d+:"(?:cmd|command|code|exec)";s:\d+:"([^"]*)"', value)
            if match and match.group(1).startswith("echo "):
                return match.group(1)[5:]
        # Pickle/base64：解码后查找 echo 标记
        try:
            raw = base64.b64decode(value + "=" * (-len(value) % 4), validate=False)
            text = raw.decode("latin-1", "replace")
            match = re.search(r"echo\s+(MOHEDESER[A-Za-z0-9]+)", text)
            if match:
                return match.group(1)
        except Exception:
            pass
        return ""


class LocalTarget:
    """上下文管理器：启动/关闭本地靶站。"""

    def __init__(self):
        self.server = None
        self.thread = None

    @property
    def url(self) -> str:
        return "http://127.0.0.1:%d/" % self.server.server_address[1]

    def __enter__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.server.upload_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "_uploads_v33")
        for name in os.listdir(self.server.upload_dir) if os.path.isdir(self.server.upload_dir) else []:
            try:
                os.remove(os.path.join(self.server.upload_dir, name))
            except Exception:
                pass
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.server.shutdown()
            self.server.server_close()
        finally:
            if self.thread:
                self.thread.join(timeout=2)
        return False


if __name__ == "__main__":
    with LocalTarget() as target:
        print("target:", target.url)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
