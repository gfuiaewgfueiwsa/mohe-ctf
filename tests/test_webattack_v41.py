# -*- coding: utf-8 -*-
"""v4.1 web 增强回归：302 入口跟随 + 隐藏参数发现 + nginx off-by-slash + 源码审计链。

只打 127.0.0.1 自建靶站。三个独立小场景：
  A: / 302 到 /?p=hello，p 参数 include 拼接 .php，php://filter 读 flag 源码注释。
  B: 静态首页引用 img/img.gif，/img../ 列上级目录，/img../flag 给 flag。
  C: 路由重写把所有备份名都回同一张首页（soft-404 批量误报），真 www.zip 里
     index.php 把 $_GET['ip'] 拼进 shell_exec 且过滤空格/;/|，需换行+IFS 绕过。
"""
import io
import os
import re
import sys
import threading
import zipfile
from html import escape as html_escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote, urlsplit, parse_qs

SRC = r"D:\工具合集软件\_源码_v2.4"
sys.path.insert(0, SRC)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from ctfbox import webattack  # noqa: E402
from ctfbox.autopilot import consent as _consent  # noqa: E402

FLAG_A = "n1book{afr_1_regression}"
FLAG_B = "flag{nginx_alias_regression}"
FLAG_C = "flag{source_audit_regression}"
FLAG_D = "flag{blind_param_regression}"
FLAG_E = "flag{ds_store_script_regression}"
PORT = 18099
URL = "http://127.0.0.1:%d/" % PORT
_consent.grant_session(_consent.FEATURE_WEB_EXPLOIT, URL)

MODE = ["A"]

HOME_C = ("<html><head><title>NN-007 路由器</title></head><body>"
          "<h1>路由器诊断面板</h1><p>" + "设备状态正常。" * 80 + "</p></body></html>")
PING_SRC = ("<?php\n$ip = $_GET['ip'];\n"
            "if (preg_match('/ |;|\\|/', $ip)) { die('bad ip'); }\n"
            "echo '<pre>'.shell_exec('ping -c 2 '.$ip).'</pre>';\n")


def _zip_c():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.php", PING_SRC)
    return buf.getvalue()


def _fake_shell(ip, flag=FLAG_C):
    """模拟 ping 拼接后的 shell：换行分隔命令，$IFS/${IFS} 当空格，算术求值。"""
    if " " in ip or ";" in ip or "|" in ip:
        return "bad ip"
    parts = ip.split("\n")
    if len(parts) < 2:
        return "ping %s ok" % parts[0]
    cmd = parts[1].replace("${IFS}", " ").replace("$IFS", " ").strip()
    if cmd.startswith("echo "):
        return cmd[5:].replace("CTFBOX$((9137+1))", "CTFBOX9138")
    if cmd in ("cat /flag", "cat</flag", "tac</flag", "head</flag"):
        return flag
    return ""


HOME_D = ("<html><head><title>NN-007 路由器</title></head><body>"
          "<h1>路由器诊断</h1><p>" + "系统运行正常，uptime 32 days。" * 60 + "</p></body></html>")
PING_PHP = ("<?php\n$ip = $_GET['ip'];\n"
            "if (preg_match('/ |;|\\|/', $ip)) { die('bad ip'); }\n"
            "echo shell_exec('ping -c 2 '.$ip);\n")
def _ds_store(entries):
    """按真实 macOS .DS_Store 的样子拼：names 块里是「长度前缀 + UTF-16BE 名字」。

    早先这个 fixture 是纯 ASCII，所以 ds_store_names 只按 ASCII 连续串匹配也能过，
    到了现场（真文件）就只捞出 Bud1/DSDB 两个结构标签，看起来像「解析成功但没内容」。
    """
    blob = bytearray(b"Bud1" + b"\x00" * 24)
    for name in entries:
        blob += bytes([len(name)]) + name.encode("utf-16-be") + b"\x00" * 6
    blob += b"DSDB" + b"\x00" * 8
    return bytes(blob)


DS_STORE = _ds_store(["cmd.php", "index.php", "ping"])

FLAG_G = "flag{spa_js_entry_regression}"
SPA_HOME = ('<html><head><title>Tree Hole</title></head><body><div id="app"></div>'
            '<script src="/static/js/app.js"></script></body></html>')
APP_JS = ('var BASE="/api";\n'
          'function ping(ip){ return fetch("/api/ping?ip="+encodeURIComponent(ip)); }\n'
          'function login(u,p){ return axios.post("/api/login", {data:{username:u,password:p}}); }\n')


def _ping_page(flag):
    return ("<html><body><pre>%s</pre></body></html>" % flag)


FLAG_H = "flag{post_ssti_regression}"
HOME_H = ("<html><head><title>tpl</title></head><body>"
          "<p>用法：向 / POST name=你的名字</p></body></html>")

FLAG_I = "flag{robots_disallow_regression}"
HOME_I = ("<html><head><title>nothing here</title></head><body>"
          "<p>欢迎访问，本站没有任何可交互入口。</p></body></html>")

FLAG_J = "flag{src_param_regression}"
# 现场原型：[BJDCTF2020]ZJCTF，不过如此。首页是 highlight_file 的真实输出：
# 每段代码各自套一个 <span style="color: …">，`$_GET` 和 `["text"]` 之间隔着标签，
# 整页又过了 htmlspecialchars（&lt;?php / &quot; / &nbsp;）。
# 表单 0 个、带参链接 0 条——入口名肉眼看得见，不做「先去标签再解实体」就一个也抽不出来。
_JS_ = '<span style="color: #0000BB">'
_JT_ = '<span style="color: #007700">'
_JQ_ = '<span style="color: #DD0000">'
HOME_J = ("<html><head><title>easy source</title></head><body><code>" + _JS_ +
          "&lt;?php&lt;br&nbsp;/&gt;error_reporting" + _JT_ + "(&nbsp;0&nbsp;);&lt;br&nbsp;/&gt;"
          + _JS_ + "$text&nbsp;=&nbsp;" + _JT_ + "$_GET" + _JT_ + "[" + _JQ_ +
          "&quot;text&quot;" + _JT_ + "];&lt;br&nbsp;/&gt;" + _JS_ +
          "$source_file&nbsp;=&nbsp;" + _JT_ + "$_GET" + _JT_ + "[" + _JQ_ +
          "&quot;source_file&quot;" + _JT_ + "];&lt;br&nbsp;/&gt;" + _JS_ +
          "if&nbsp;(isset($source_file))&nbsp;{&nbsp;" + _JT_ + "include" + _JS_ +
          "($source_file);" + _JT_ + "&nbsp;}&nbsp;" + _JS_ + "?&gt;&lt;br&nbsp;/&gt;" +
          "</code></body></html>")


FLAG_K = "flag{php_gate_chain_regression}"
# 现场原型：ZJCTF 的完整形状——text 必须先「读到」那句字面量，file 才会被 include。
# 单发探 text 或单发探 file 响应都一模一样（闸门没过就回同一张页），
# 所以这条只能靠「data:// 顶闸门 + 同一发带上读文件参数」打通，逐参数矩阵永远打不开。
HOME_K = ("<html><head><title>gate</title></head><body><code>" + _JS_ +
          "&lt;?php&nbsp;&nbsp;error_reporting" + _JT_ + "(&nbsp;0&nbsp;);" + _JS_ +
          "$text&nbsp;=&nbsp;" + _JT_ + "$_GET" + _JT_ + "[" + _JQ_ + "&quot;text&quot;" + _JT_
          + "];" + _JS_ + "$file&nbsp;=&nbsp;" + _JT_ + "$_GET" + _JT_ + "[" + _JQ_
          + "&quot;file&quot;" + _JT_ + "];" + _JS_ + "if&nbsp;(isset($text)&nbsp;&amp;&amp;" +
          _JT_ + "file_get_contents" + _JS_ + "($text&nbsp;,&nbsp;" + _JQ_ + "'r'" + _JS_ +
          ")" + _JT_ + "===&nbsp;" + _JQ_ + "&quot;I have a dream&quot;" + _JT_ + "){&nbsp;" +
          _JS_ + "if(!preg_match" + _JT_ + "(&quot;/config/i&quot;,$file))&nbsp;{" + _JS_ +
          "include&nbsp;($file);" + _JT_ + "&nbsp;}&nbsp;}" + _JS_ + "?&gt;" +
          "</code></body></html>")


FLAG_L = "flag{lfi_wrapper_code_exec_regression}"
# 现场原型：ZJCTF 那一题的完整链路。除了 K 的闸门还多两道墙——
# 1) 下一个文件名只写在注释里（`include($file); //next.php`），不带引号；
# 2) file 参数里出现 flag 就 die，顺着文件名读 flag 走不通，
#    flag 只在"机器"上一个随机名的文件里，必须让代码执行去 cat 它。
HOME_L = ("<html><head><title>exec</title></head><body><code>" + _JS_ +
          "&lt;?php&nbsp;&nbsp;error_reporting" + _JT_ + "(&nbsp;0&nbsp;);" + _JS_ +
          "$text&nbsp;=&nbsp;" + _JT_ + "$_GET" + _JT_ + "[" + _JQ_ + "&quot;text&quot;" + _JT_
          + "];" + _JS_ + "$file&nbsp;=&nbsp;" + _JT_ + "$_GET" + _JT_ + "[" + _JQ_
          + "&quot;file&quot;" + _JT_ + "];" + _JS_ + "if&nbsp;(file_get_contents" + _JT_ +
          "($text&nbsp;,&nbsp;" + _JQ_ + "'r'" + _JS_ + ")" + _JT_ + "===&nbsp;" + _JQ_ +
          "&quot;I have a dream&quot;" + _JT_ + "){&nbsp;" + _JS_ + "if(preg_match" + _JT_ +
          "(&quot;/flag/&quot;,$file))&nbsp;{" + _JS_ + "die(&quot;Not now!&quot;);" + _JT_ +
          " }" + _JS_ + "include&nbsp;($file);" + _JT_ + " //next.php" + _JS_ +
          " }" + _JT_ + "else&nbsp;{&nbsp;highlight_file(__FILE__);&nbsp;}" + _JS_ +
          "?&gt;</code></body></html>")

IDX_L = ("<?php\n$text = $_GET[\"text\"];\n$file = $_GET[\"file\"];\n"
         "if(preg_match(\"/flag/\",$file)){die(\"Not now!\");}\n"
         "include($file); //next.php\n?>")
NEXT_L = ("<?php\nerror_reporting(0);\n"
          "// flag 只在随机名文件里，参数带 flag 会被拦掉\n$f='/flag_8823';\n?>")


def _l_exec(code):
    """最小 PHP 执行模拟：算术求值才算跑过代码，命令按这台 mock 的文件布局回答。"""
    code = code or ""
    if "<?php" not in code:
        return ""
    if "9137+1" in code:
        return "CTFBOX9138"
    if "system" not in code:
        return ""
    if "flag_8823" in code:
        return FLAG_L
    if "ls -la" in code:
        return "index.php  next.php  flag_8823"
    if "-name" in code:
        return FLAG_L
    return "cat: No such file or directory"


def _l_gate(q):
    """闸门只认 data:// 顶开的 'I have a dream'，没过闸一律回首页。"""
    t = q.get("text", [""])[0]
    val = t[len("data://text/plain,"):] if t.startswith("data://text/plain,") else t
    return val == "I have a dream"


FLAG_M = "flag{php_pcre_e_regression}"
# 现场原型：同一道题的第二阶段。allow_url_include=Off，data:// 与 php://input 全部进不去，
# 唯一能执行代码的是 next.php 里的 preg_replace /e —— 执行点在「参数名当模式、参数值放 ${…}」上。
NEXT_M = ("<?php\nfunction complex($re, $str) {\n"
          "    return preg_replace('/(' . $re . ')/ei', 'strtolower(\"\\\\1\")', $str);\n}\n"
          "foreach($_GET as $re => $str) { echo complex($re, $str). \"\\n\"; }\n"
          "function getFlag(){ @eval($_GET['cmd']); }\n?>")
E_KEYS = (r"\S+", r"[^,]*", r"[^\s,]*")


def _m_pcre_e(q):
    """模拟那台机器：只有 /e 这条路能跑代码；参数名里的点会先被 PHP 换成下划线。"""
    out = []
    for k, vals in q.items():
        name = k.replace(".", "_")   # PHP 对 query 参数名的固定改写，带点的模式因此匹配不上
        v = vals[0]
        if name in E_KEYS and v.startswith("${") and v.endswith("}"):
            expr = v[2:-1]
            if expr == "phpinfo()":
                out.append("PHP Version 5.6.40 www-data memory usage")
                continue
            if expr == "getFlag()":
                cmd = q.get("cmd", [""])[0]
                if "file_get_contents('/flag')" in cmd:
                    out.append(FLAG_M)
                elif "scandir" in cmd:
                    out.append("Array ( [0] => . [1] => .. [2] => bin [3] => flag )")
                elif "glob" in cmd:
                    out.append('array(1) { [0]=> string(5) "/flag" }')
                else:
                    out.append("")
                continue
        out.append(v)                 # 没被执行就原样回显，回显不能算执行证据
    return " ".join(out)


def _fake_jinja(value, flag):
    """最小 Jinja 味模拟：只认 {{a*b}} 和 popen('cat /flag')，其余原样回显。"""
    mo = re.search(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}", value)
    if mo:
        return "<html><body>hi %d</body></html>" % (int(mo.group(1)) * int(mo.group(2)))
    if "cat /flag" in value:
        return "<html><body>%s</body></html>" % flag
    return "<html><body>hi %s</body></html>" % value


HOME_N = ('<html><head><title>Converter</title></head><body>'
          '<form action="/api/new" method="post" enctype="multipart/form-data">'
          '<input type="file" name="upload_file"><input type="submit"></form></body></html>')

# 场景 O：现场 N1BOOK「文件上传」的形状。
# 页面把源码打在屏幕上（能抽出 GET file），有上传表单；上传 2xx 但文件被改名，
# 按原名猜的 8 个路径一个都访问不到；只有把落盘路径交给 ?file= 包含才会执行。
# 「上传」与「LFI」各自都跑完却没把前者输出喂给后者，就是旧引擎的缺口。
FLAG_O = "flag{upload_lfi_chain_regression}"
HOME_O = ("<html><head><title>upload</title></head><body>"
          "<code>&lt;?php $f = $_GET[&quot;file&quot;]; include($f); ?&gt;</code>"
          '<form action="/upload.php" method="post" enctype="multipart/form-data">'
          '<input type="file" name="upfile"><input type="submit"></form></body></html>')
UPLOADED = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        path = urlsplit(self.path).path
        n = int(self.headers.get("Content-Length") or 0)
        raw_bytes = self.rfile.read(n) if n else b""
        raw = raw_bytes.decode("utf-8", "ignore")
        body = parse_qs(raw, keep_blank_values=True)
        if MODE[0] == "O":
            # 极简 multipart 解析：只要 filename 和载荷正文，够跑通联动即可
            mo = re.search(rb'filename="([^"]+)"', raw_bytes)
            if mo:
                fname = mo.group(1).decode("utf-8", "ignore")
                parts = raw_bytes.split(b"\r\n\r\n", 1)
                content = parts[1].split(b"\r\n--", 1)[0] if len(parts) > 1 else b""
                UPLOADED[fname] = content
            return self._send(200, "<html><body>upload ok</body></html>")
        if MODE[0] == "N":
            # 服务端对每种载荷都回 400：文件根本没落盘，引擎不该再去猜 8 个路径。
            # 现场「unsecure converter」就是这样，旧代码 9 种载荷白烧 100 多个请求。
            return self._send(400, "<html><body>invalid file type</body></html>")
        if MODE[0] == "L":
            # php://input 的内容只来自原始 POST body，表单编码的题拿不到这条路
            q = parse_qs(urlsplit(self.path).query)
            if not _l_gate(q) or q.get("file", [""])[0] != "php://input":
                return self._send(200, HOME_L)
            return self._send(200, "<html><body>%s</body></html>" % _l_exec(raw))
        if MODE[0] == "H":
            # 只吃 POST 的模板渲染题：HTML 上没有表单，入口只能靠 POST 盲探
            if path == "/" and body.get("name"):
                return self._send(200, _fake_jinja(body["name"][0], FLAG_H))
            return self._send(200, HOME_H)
        if MODE[0] != "G":
            return self._send(501, "<html><body>Unsupported method</body></html>")
        if path == "/api/login":
            if body.get("username") == ["admin"] and body.get("password") == ["123456"]:
                return self._send(200, "<html><body>登录成功</body></html>")
            return self._send(200, "<html><body>账号或密码错误</body></html>")
        return self._send(404, "<html><body>404</body></html>")

    def do_GET(self):
        path = urlsplit(self.path).path
        q = parse_qs(urlsplit(self.path).query)
        if MODE[0] == "O":
            if "__probe_" in path:
                return self._send(404, "not found")
            if path.startswith("/uploads/"):
                # 文件确实落盘了，但目录不可直接访问（改名/重写），猜路径全部落空
                return self._send(404, "not found")
            if "file" in q:
                key = q["file"][0].lstrip("./").rsplit("/", 1)[-1]
                data = UPLOADED.get(key)
                if data is None:
                    return self._send(200, HOME_O)
                text = data.decode("utf-8", "ignore")
                if "scandir" in text:
                    return self._send(200, "<html><body>%s</body></html>" % FLAG_O)
                if "CTFBOXUPLOAD9137" in text:
                    return self._send(200, "<html><body>CTFBOXUPLOAD9137</body></html>")
                return self._send(200, "<html><body>raw source</body></html>")
            return self._send(200, HOME_O)
        if MODE[0] == "N":
            if "__probe_" in path:
                return self._send(404, "not found")
            return self._send(200, HOME_N)
        if MODE[0] == "A":
            if "p" not in q:
                return self._send(302, "", {"Location": "/?p=hello"})
            p = q["p"][0]
            if p == "hello":
                return self._send(200, "hello world!")
            if p.startswith("php://filter") and p.endswith("resource=flag"):
                import base64
                src = "<?php\ndie('no no no');\n//%s\n" % FLAG_A
                return self._send(200, base64.b64encode(src.encode()).decode())
            return self._send(200, "")
        if MODE[0] == "C":
            if path == "/www.zip":
                return self._send(200, _zip_c(),
                                  {"Content-Type": "application/zip"})
            # 首页对任何参数都无反应：只有泄露源码指向的 index.php 才吃 ip，
            # 这样命令注入只能靠「源码审计→定向利用」这条链找到。
            if path == "/index.php":
                if "ip" in q:
                    return self._send(200, "<html><body><pre>%s</pre></body></html>"
                                      % _fake_shell(q["ip"][0]))
                return self._send(200, HOME_C)
            # 探针路径给 404（基线探不到），其余一律重写成首页：批量 soft-404
            if "__probe_" in path:
                return self._send(404, "not found")
            return self._send(200, HOME_C)
        if MODE[0] == "D":
            # 长首页、无表单无链接：入口只藏在 ?ip= 里，必须靠盲探参数名发现
            if "__probe_" in path:
                return self._send(404, "not found")
            if "ip" in q:
                return self._send(200, "<html><body><pre>%s</pre></body></html>"
                                  % _fake_shell(q["ip"][0], FLAG_D))
            return self._send(200, HOME_D)
        if MODE[0] == "E":
            # 首页什么都不接受；真实入口是 .DS_Store 里泄露的 cmd.php
            if "__probe_" in path:
                return self._send(404, "not found")
            if path == "/.DS_Store":
                return self._send(200, DS_STORE)
            if path == "/cmd.php":
                if "ip" in q:
                    return self._send(200, "<html><body><pre>%s</pre></body></html>"
                                      % _fake_shell(q["ip"][0], FLAG_E))
                return self._send(200, "<html><body>用法：请通过 ip 参数指定目标</body></html>")
            return self._send(200, HOME_D)
        if MODE[0] == "F":
            # 纯回显页（afr_3 那类）：把 n1code 原样打印，既不执行 SQL 也不报错。
            # 引擎不能因为 payload 里带着 9137/CBX 就认定 UNION 可用。
            if "__probe_" in path:
                return self._send(404, "not found")
            if path in ("/", "/search"):
                val = q.get("n1code", [""])[0]
                if not val:
                    return self._send(200,
                                      '<html><head><title>article</title></head><body>'
                                      '<a href="/?n1code=1">next</a>'
                                      '<p>Hello :</p></body></html>',
                                      {"Set-Cookie": "session=eyJuMWNvZGUiOm51bGx9.abc.def"})
                return self._send(200,
                                  '<html><head><title>article</title></head><body>'
                                  '<script>n1code="%s"</script><p>Hello : %s</p></body></html>'
                                  % (html_escape(val), html_escape(val)),
                                  {"Set-Cookie": "session=eyJuMWNvZGUiOm51bGx9.abc.def"})
            return self._send(404, "<html><body>404</body></html>")
            return self._send(404, "<html><body>404</body></html>")
        if MODE[0] == "G":
            # SPA：HTML 既无表单也无链接，真实接口只写在 app.js 的 fetch 调用里
            if "__probe_" in path:
                return self._send(404, "not found")
            if path == "/static/js/app.js":
                return self._send(200, APP_JS, {"Content-Type": "application/javascript"})
            if path == "/api/ping":
                if "ip" in q:
                    return self._send(200, "<html><body><pre>%s</pre></body></html>"
                                      % _fake_shell(q["ip"][0], FLAG_G))
                return self._send(200, "<html><body>用法：请通过 ip 参数指定目标</body></html>")
            if path == "/api/login":
                return self._send(405, "<html><body>method not allowed</body></html>")
            return self._send(200, SPA_HOME)
        if MODE[0] == "H":
            # GET 侧对任何参数都回同一张页：入口只能靠 POST 盲探发现
            if "__probe_" in path:
                return self._send(404, "not found")
            return self._send(200, HOME_H)
        if MODE[0] == "I":
            # 页面本身零入口，唯一线索是 robots.txt 的 Disallow 路径（真实提示面）
            if path == "/robots.txt":
                return self._send(200, "User-agent: *\nDisallow: /static/secretkey.txt\n")
            if path == "/static/secretkey.txt":
                return self._send(200, "the key is %s\n" % FLAG_I)
            if "__probe_" in path:
                return self._send(404, "not found")
            return self._send(200, HOME_I)
        if MODE[0] == "J":
            # flag 只挂在 source_file 上，而这个名字不在任何参数字典里：
            # 没有「从页面源码抽入口名」这一步，本轮连入口都找不到。
            if "source_file" in q:
                v = q["source_file"][0]
                if "resource=flag" in v.replace(" ", ""):
                    import base64
                    src = "<?php\n$flag = '%s';\n?>" % FLAG_J
                    return self._send(200, base64.b64encode(src.encode()).decode())
                return self._send(200, "")
            if "text" in q:
                return self._send(200, "<html><body>need: I have a dream</body></html>")
            if "__probe_" in path:
                return self._send(404, "not found")
            return self._send(200, HOME_J)
        if MODE[0] == "K":
            import base64
            t = q.get("text", [""])[0]
            f = q.get("file", [""])[0].replace(" ", "")
            val = t[len("data://text/plain,"):] if t.startswith("data://text/plain,") else t
            # 闸门没过就一律回同一张页：任何「单参数」探测都看不出 file 是入口
            if val != "I have a dream":
                return self._send(200, HOME_K)
            if "resource=flag_here" in f:
                return self._send(200, base64.b64encode(
                    ("<?php\n$flag = '%s';\n?>" % FLAG_K).encode()).decode())
            if "resource=index" in f:
                # 源码里没有 flag，但写着下一个文件叫什么——逼引擎做「读源码→顺着读」这一步
                return self._send(200, base64.b64encode(
                    ("<?php\n// flag 不在这页，写在 flag_here.php 里\ninclude 'flag_here.php';\n?>")
                    .encode()).decode())
            return self._send(200, HOME_K)
        if MODE[0] == "L":
            import base64
            if not _l_gate(q):
                return self._send(200, HOME_L)
            f = q.get("file", [""])[0]
            # 对参数做关键词检查：这就是逼着走"代码藏进 base64 / POST body"那一步
            if "flag" in f.lower():
                return self._send(200, "<html><body>Not now!</body></html>")
            if "resource=index" in f:
                return self._send(200, base64.b64encode(IDX_L.encode()).decode())
            if "resource=next" in f:
                return self._send(200, base64.b64encode(NEXT_L.encode()).decode())
            if f.startswith("data://text/plain;base64,"):
                b = f.split(";base64,", 1)[1]
                code = base64.b64decode(b + "=" * (-len(b) % 4)).decode("utf-8", "ignore")
                return self._send(200, "<html><body>%s</body></html>" % _l_exec(code))
            return self._send(200, HOME_L)
        if MODE[0] == "M":
            import base64
            if not _l_gate(q):
                return self._send(200, HOME_L)
            f = q.get("file", [""])[0]
            if "flag" in f.lower():
                return self._send(200, "<html><body>Not now!</body></html>")
            if "resource=index" in f:
                return self._send(200, base64.b64encode(IDX_L.encode()).decode())
            if "resource=next" in f:
                return self._send(200, base64.b64encode(NEXT_M.encode()).decode())
            # 只有裸文件名 next.php 被 include 时代码才会跑；data:// 与 php://input
            # 在这里一律回首页，模拟 allow_url_include=Off 的那台机器。
            if f == "next.php":
                return self._send(200, "<html><body>%s</body></html>" % _m_pcre_e(q))
            return self._send(200, HOME_L)
        # 场景 B：静态页 + off-by-slash
        if path == "/":
            return self._send(200, '<html><head><title>u1s1</title></head>'
                                   '<body>HELLO!<img src="img/img.gif"></body></html>')
        if path == "/img/img.gif":
            return self._send(200, "GIF89a-fake")
        if path == "/img../":
            return self._send(200, '<html><head><title>Index of /img../</title></head>'
                                   '<body><h1>Index of /img../</h1><a href="../">../</a>'
                                   '<a href="flag">flag</a></body></html>')
        if path == "/img../flag":
            return self._send(200, FLAG_B)
        return self._send(404, "<html><body>404</body></html>")


def run_case(mode, expect_flag, expect_kind):
    MODE[0] = mode
    logs = []
    r = webattack.campaign(URL, log=logs.append, max_requests=500, max_seconds=200)
    flags = [f["value"] for f in r.get("flags") or []]
    kinds = [f["type"] for f in r.get("findings") or []]
    ok = expect_flag in flags
    print(("PASS" if ok else "FAIL"), "场景", mode, "flags=", flags, "findings=", kinds)
    if expect_kind:
        ok2 = expect_kind in kinds
        print(("PASS" if ok2 else "FAIL"), "场景", mode, "发现类型", expect_kind)
        ok = ok and ok2
    return ok


def run_negative(mode, bad_kinds):
    """纯回显靶站：不允许报任何"注入成功"类结论，也不许编造 flag。"""
    MODE[0] = mode
    logs = []
    r = webattack.campaign(URL, log=logs.append, max_requests=500, max_seconds=200)
    kinds = [f["type"] for f in r.get("findings") or []]
    flags = [f["value"] for f in r.get("flags") or []]
    hits = [k for k in kinds if k in bad_kinds]
    ok = not hits and not flags
    print(("PASS" if ok else "FAIL"), "场景", mode, "误报=", hits or "无",
          "findings=", kinds, "flags=", flags)
    return ok


def run_budget(mode, expect_kinds, max_requests, banned_logs=()):
    """被服务端明确拒绝的载荷必须尽快收手：结论要对，请求数也要省。

    banned_logs 查的是引擎自己打的判断句——「候选路径均未回显标记」意味着它还在
    为一个个根本没落盘的文件猜路径，那是纯粹的预算浪费，比总数更早暴露问题。
    """
    MODE[0] = mode
    logs = []
    r = webattack.campaign(URL, log=logs.append, max_requests=500, max_seconds=200)
    kinds = [f["type"] for f in r.get("findings") or []]
    used = r.get("requests") or 0
    ok_kind = all(k in kinds for k in expect_kinds)
    ok_budget = used <= max_requests
    banned = [b for b in banned_logs if any(b in line for line in logs)]
    print(("PASS" if ok_kind else "FAIL"), "场景", mode, "期望结论", expect_kinds,
          "实得=", sorted(set(kinds)))
    print(("PASS" if ok_budget else "FAIL"), "场景", mode, "请求数", used, "≤ %d" % max_requests)
    print(("PASS" if not banned else "FAIL"), "场景", mode, "不该出现的浪费=", banned or "无")
    return ok_kind and ok_budget and not banned


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        ok_a = run_case("A", FLAG_A, "lfi-source")
        ok_b = run_case("B", FLAG_B, "nginx-alias")
        ok_c = run_case("C", FLAG_C, "source-audit")
        ok_d = run_case("D", FLAG_D, "cmdi")
        ok_e = run_case("E", FLAG_E, "cmdi")
        ok_f = run_negative("F", ("sqli-union", "sqli-filter", "sqli-boolean",
                                  "sqli-time", "sqli-error", "flag-read"))
        ok_g = run_case("G", FLAG_G, "cmdi")
        ok_h = run_case("H", FLAG_H, "ssti")
        ok_i = run_case("I", FLAG_I, "robots-leak")
        ok_j = run_case("J", FLAG_J, "flag-read")
        ok_k = run_case("K", FLAG_K, "flag-read")
        ok_l = run_case("L", FLAG_L, "lfi-rce")
        ok_m = run_case("M", FLAG_M, "php-pcre-e")
        ok_n = run_budget("N", ("upload-rejected",), 260,
                          banned_logs=("个候选路径均未回显标记",))
        ok_o = run_case("O", FLAG_O, "upload-lfi-exec")
    finally:
        srv.shutdown()
    oks = (ok_a, ok_b, ok_c, ok_d, ok_e, ok_f, ok_g, ok_h, ok_i, ok_j, ok_k, ok_l, ok_m,
           ok_n, ok_o)
    print("RESULT:", "ALL PASS" if all(oks) else "FAIL")
    return 0 if all(oks) else 1


if __name__ == "__main__":
    raise SystemExit(main())