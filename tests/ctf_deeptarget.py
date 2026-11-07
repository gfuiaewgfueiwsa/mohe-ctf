# -*- coding: utf-8 -*-
"""深度 Web 测试本机靶站（仅监听 127.0.0.1，供 tests/test_webattack.py 使用）。

用法：
    python ctf_deeptarget.py <port> <request_log>

进程由测试拉起，结束时被 terminate。只做本地回环，不对外暴露。
覆盖：反射型 XSS、SQL 报错/布尔、LFI、SSTI、命令注入、文件上传后可执行、定向 flag。
"""
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote, urlsplit

FLAG = "flag{deep_hunt_9137}"
UPLOAD_MARK = "CTFBOXUPLOAD9137"

LOG_PATH = ""
LOCK = threading.Lock()
UPLOADS = {}

HOME = """<html><head><title>Deep Hunt 靶站</title></head><body>
<h1>Deep Hunt 靶站</h1>
<form action="/login" method="post">
<input type="text" name="username"><input type="password" name="password">
<input type="submit" value="登录"></form>
<form action="/upload" method="post" enctype="multipart/form-data">
<input type="file" name="file"><input type="submit" value="上传"></form>
</body></html>"""

LOGIN_PAGE = """<html><head><title>Login</title></head><body>
<form action="/login" method="post">
<input type="text" name="username"><input type="password" name="password">
<input type="submit" value="登录"></form></body></html>"""

TRUE_PAGE = """<html><head><title>Login</title></head><body><h2>登录成功</h2><p>欢迎回来</p></body></html>"""
FALSE_PAGE = """<html><head><title>Login</title></head><body><h2>用户名或密码错误</h2></body></html>"""
SQLERR_PAGE = ("""<html><head><title>Login</title></head><body><h2>Query failed</h2>
<p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</p>
</body></html>""")
NEUTRAL_PAGE = """<html><head><title>Login</title></head><body><p>记录为空</p></body></html>"""
PASSWD_PAGE = """<html><body><pre>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin</pre></body></html>"""
FLAG_PAGE = """<html><body><p>%s</p></body></html>""" % FLAG
CMDI_PAGE = """<html><body><pre>CTFBOX9138</pre></body></html>"""

REFLECT_HEAD = """<html><head><title>Login</title></head><body><div id="out">"""
REFLECT_TAIL = """</div></body></html>"""


def _page(body):
    return body.encode("utf-8")


def ssti_page(value):
    mo = re.search(r"(\d+)\s*\*\s*(\d+)", value)
    if mo:
        return _page("<html><body><p>%d</p></body></html>" % (int(mo.group(1)) * int(mo.group(2))))
    return _page(LOGIN_PAGE)


def classify(value):
    """按注入 payload 的特征返回对应漏洞响应。"""
    low = value.lower()
    if "and 1=1" in low:
        return _page(TRUE_PAGE)
    if "and 1=2" in low:
        return _page(FALSE_PAGE)
    if "ascii(substr" in low:
        # 布尔盲注取数：条件不成立，二分收敛到不可打印字符后自动放弃
        return _page(FALSE_PAGE)
    if "union" in low:
        return _page(NEUTRAL_PAGE)
    if "sleep(" in low or "pg_sleep" in low:
        return _page(LOGIN_PAGE)
    if "cat /flag" in low or "cat$ifs/flag" in low or "cat /flag.txt" in low:
        return _page(FLAG_PAGE)
    if "$((9137+1))" in low or "ctfbox9138" in low:
        return _page(CMDI_PAGE)
    if "file://" in low:
        return _page(FLAG_PAGE)
    if "etc/passwd" in low or "proc/self/environ" in low or "win.ini" in low:
        return _page(PASSWD_PAGE)
    if "{{" in value or "${" in value or "<%=" in value or "#{" in value:
        return ssti_page(value)
    if "<script" in low or "<img" in low or "<svg" in low or "javascript:" in low or "<body" in low:
        return _page(REFLECT_HEAD + value + REFLECT_TAIL)
    if "'" in value or '"' in value:
        return _page(SQLERR_PAGE)
    return _page(LOGIN_PAGE)


def parse_multipart(body, ctype):
    """最小 multipart 解析：返回 (普通字段, 文件字段)。"""
    mo = re.search(r"boundary=([^;]+)", ctype or "")
    if not mo:
        return {}, {}
    boundary = mo.group(1).strip().strip('"')
    fields, files = {}, {}
    for part in body.split(("--" + boundary).encode("utf-8")):
        part = part.lstrip(b"\r\n")
        if not part or part.startswith(b"--"):
            continue
        if b"\r\n\r\n" not in part:
            continue
        head, _, content = part.partition(b"\r\n\r\n")
        if content.endswith(b"\r\n"):
            content = content[:-2]
        headers = head.decode("utf-8", "replace")
        name_m = re.search(r'name="([^"]*)"', headers)
        if not name_m:
            continue
        name = name_m.group(1)
        file_m = re.search(r'filename="([^"]*)"', headers)
        if file_m:
            ct_m = re.search(r"Content-Type:\s*([^\r\n]+)", headers, re.I)
            files[name] = (file_m.group(1), content, ct_m.group(1).strip() if ct_m else "")
        else:
            fields[name] = content.decode("utf-8", "replace")
    return fields, files


def run_php(content):
    """模拟服务端解析 PHP：只回显固定标记 / 取 flag 脚本的结果。"""
    if b"scandir" in content:
        return FLAG.encode("utf-8")
    if b"<?php" in content and UPLOAD_MARK.encode("utf-8") in content:
        return UPLOAD_MARK.encode("utf-8")
    return content


class Handler(BaseHTTPRequestHandler):
    server_version = "DeepTarget/1.0"

    def log_message(self, fmt, *args):
        pass

    def _record(self, body=b""):
        ctype = self.headers.get("Content-Type", "")
        with LOCK:
            with open(LOG_PATH, "a", encoding="utf-8") as fp:
                fp.write("%s %s %s\n" % (self.command, self.path, self.request_version))
                if ctype:
                    fp.write("Content-Type: %s\n" % ctype)
                if body:
                    fp.write(body.decode("utf-8", "replace") + "\n")

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self):
        path = urlsplit(self.path).path
        self._record()
        if path == "/" or path == "":
            return self._send(200, HOME)
        if path == "/login":
            return self._send(200, LOGIN_PAGE)
        if path.startswith("/uploads/"):
            name = unquote(path[len("/uploads/"):])
            entry = UPLOADS.get(name)
            if entry is None:
                for key, val in UPLOADS.items():
                    if key.strip() == name.strip():
                        entry = val
                        break
            if entry is None:
                return self._send(404, "<html><body><p>404</p></body></html>")
            content, ctype = entry
            # 只有「PHP 内容 + application/x-php + .php 后缀」才被服务端解析执行；
            # 其余形态（图片马、双扩展名、大写、尾点、尾空格、双写）一律按原样存储返回，
            # 这样上传矩阵里只会有 1 种形态被判定可执行，取 flag 脚本也只补 1 次。
            if ctype == "application/x-php" and name.endswith(".php") \
                    and not content.startswith(b"\x89PNG"):
                return self._send(200, run_php(content))
            return self._send(200, content)
        return self._send(404, "<html><body><p>404</p></body></html>")

    def do_POST(self):
        body = self._read_body()
        path = urlsplit(self.path).path
        self._record(body)
        if path == "/login":
            fields = {}
            ctype = self.headers.get("Content-Type", "")
            if "multipart/form-data" in ctype:
                fields, _ = parse_multipart(body, ctype)
            else:
                from urllib.parse import parse_qsl
                fields = dict(parse_qsl(body.decode("utf-8", "replace")))
            if fields.get("username") == "admin" and fields.get("password") == "admin":
                return self._send(200, TRUE_PAGE)
            combined = "%s %s" % (fields.get("username", ""), fields.get("password", ""))
            return self._send(200, classify(combined))
        if path == "/upload":
            ctype = self.headers.get("Content-Type", "")
            _, files = parse_multipart(body, ctype)
            if not files:
                return self._send(400, "<html><body><p>no file</p></body></html>")
            filename, content, ctype = next(iter(files.values()))
            name = filename.strip()
            UPLOADS[name] = (content, ctype)
            link = "/uploads/" + quote(name, safe="")
            return self._send(200, '<html><body><p>上传成功</p><img src="%s"></body></html>' % link)
        return self._send(404, "<html><body><p>404</p></body></html>")


def main():
    global LOG_PATH
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18081
    LOG_PATH = sys.argv[2] if len(sys.argv) > 2 else ""
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
