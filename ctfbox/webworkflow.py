# -*- coding: utf-8 -*-
"""Local tool discovery and a bounded, single-origin CTF workflow.

No installers, shell commands, crawling, or automatic exploitation. Local tools
are user-trusted programs, not sandboxed or claimed to be bundled. GUI launch is
explicit; all automated subprocesses belong to process_runner.
"""
import base64
import binascii
import glob
import html
import http.client
from datetime import datetime, timezone
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit
import uuid
import webbrowser

from .common import TOOLS_DIR, WORKSPACE, REPORTS_DIR, external_python
from . import toolsmgr, webnav
from .webtools import DIR_WORDS
from .process_runner import run_command, TaskCancelled, TaskTimeout


TOOLS = {
    "burp": dict(name="Burp Suite Community", category="HTTP", mode="gui",
                 description="仅手动打开本地界面；请限定 CTF 主机范围后拦截请求、使用重放器。社区版没有自动扫描器。",
                 candidates=["BurpSuiteCommunity.exe", "burpsuite_community*.jar"]),
    "devtools": dict(name="Browser DevTools", category="HTTP", mode="manual",
                     description="浏览器内置功能：在 CTF 页面按 F12，手动查看网络、存储和控制台；无需独立程序。",
                     candidates=[]),
    "hackbar": dict(name="HackBar", category="HTTP", mode="manual",
                    description="需自行安装浏览器扩展，在其面板中手动构造已授权的 CTF 请求；不自动运行。",
                    candidates=[]),
    "sqlmap": dict(name="SQLMap", category="Detection", mode="cli",
                   description="可选的单 URL SQL 注入自动检测，使用固定低影响参数；不枚举、导出数据库或执行命令。替换自定义版本后需确认兼容性。",
                   candidates=["sqlmap.py", "sqlmap-master/sqlmap.py", "sqlmapproject-sqlmap-master/sqlmap.py", "sqlmap.exe", "sqlmap"]),
    "dirsearch": dict(name="dirsearch", category="Directories", mode="cli",
                      description="可选的同源目录自动检测：固定小词表、单线程、每秒最多 2 次请求，隔离配置，不递归、不跟随重定向；自定义版本需确认参数兼容。",
                      candidates=["dirsearch.py", "dirsearch-master/dirsearch.py", "dirsearch.exe", "dirsearch"]),
    "ffuf": dict(name="ffuf", category="Directories", mode="cli",
                 description="可选的同源目录自动检测：固定小词表、单线程、每秒最多 2 次请求，不递归、不跟随重定向，保存独立 JSON；自定义版本需确认参数兼容。",
                 candidates=["ffuf.exe", "ffuf"]),
    "xsstrike": dict(name="XSStrike", category="Detection", mode="cli",
                     description="仅供手动限定范围检测。原版命令行无法强制禁止重定向，因此自动流程始终跳过；内置 xss 步骤仅检测反射线索，不调用 XSStrike。",
                     candidates=["xsstrike.py", "XSStrike/xsstrike.py", "XSStrike-master/xsstrike.py"]),
    "jwt_tool": dict(name="JWT_Tool", category="Tokens", mode="manual",
                     description="仅手动使用，需提供令牌及明确的测试上下文，不能仅凭 URL 自动运行；内置 JWT 解码完全离线且不验证签名。",
                     candidates=["jwt_tool.py", "jwt_tool/jwt_tool.py"]),
    "ssrfmap": dict(name="SSRFmap", category="Context required", mode="manual",
                    description="仅手动使用，需提供已捕获的请求、指定参数及已授权的回连上下文；不根据单个 URL 自动运行。",
                    candidates=["ssrfmap.py", "SSRFmap/ssrfmap.py"]),
    "cyberchef": dict(name="CyberChef", category="Offline analysis", mode="html",
                      description="打开已有的本地离线 HTML，手动编排分析配方；不会自动转到在线版或下载。",
                      candidates=["index.html", "CyberChef.html", "CyberChef*.html"]),
    "githack": dict(name="GitHack", category="Context required", mode="manual",
                   description="仅手动使用，需确认 CTF 的 .git 暴露并指定输出目录；自动 source 步骤只检查 HEAD 线索，不拉取源码或执行。",
                   candidates=["GitHack.py", "GitHack/GitHack.py", "githack.py"]),
    "antsword": dict(name="AntSword", category="Context required", mode="gui",
                     description="仅打开本地界面。已获授权的 CTF 网站管理脚本、协议和密码须手动配置，不会从 URL 推断或自动连接。",
                     candidates=["AntSword.exe", "antSword.exe", "antsword.exe"]),
    "file": dict(name="file", category="Local files", mode="cli",
                 description="仅手动识别本地文件类型；需提供本地样本，不接受 URL 自动任务。",
                 candidates=["file.exe", "bin/file.exe", "file"]),
    "binwalk": dict(name="binwalk", category="Local files", mode="cli",
                    description="仅手动检查本地固件或文件特征；需提供本地样本，不自动提取或安装软件包。",
                    candidates=["binwalk.exe", "binwalk.py", "binwalk"]),
    "strings": dict(name="strings", category="Local files", mode="cli",
                    description="仅手动提取本地文件中的字符串；需提供本地样本，不接受 URL 自动任务。",
                    candidates=["strings.exe", "strings64.exe", "bin/strings.exe", "strings"]),
    "exiftool": dict(name="ExifTool", category="Local files", mode="cli",
                     description="仅手动检查本地文件元数据；需提供本地样本，不接受 URL 自动任务。",
                     candidates=["exiftool.exe", "exiftool(-k).exe", "exiftool"]),
}

ALLOWED_STEPS = ("http", "dirs", "sqlmap", "xsstrike", "dirsearch", "ffuf", "source", "xss",
                 "auto", "deep")
MAX_RESPONSE_BYTES = 64 * 1024
MAX_JWT_BYTES = 8192
MAX_JWT_CHARS = 32768
_CONFIG_LIMIT = 64 * 1024
_PATH_LOCK = threading.RLock()
_SHELL_NAMES = {"cmd", "powershell", "pwsh", "bash", "sh", "zsh", "csh", "wscript", "cscript"}


def _meta(key):
    if key not in TOOLS:
        raise ValueError("Unknown web tool: %r" % (key,))
    return TOOLS[key]


def _config_path():
    return os.path.join(WORKSPACE, "web_tool_paths.json")


def _load_paths():
    try:
        with open(_config_path(), "r", encoding="utf-8") as handle:
            text = handle.read(_CONFIG_LIMIT + 1)
    except FileNotFoundError:
        return {}
    if len(text) > _CONFIG_LIMIT:
        raise ValueError("web_tool_paths.json exceeds the size limit")
    data = json.loads(text)
    if not isinstance(data, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                         for k, v in data.items()):
        raise ValueError("web_tool_paths.json must map tool keys to file paths")
    return data


def _file_kind(path):
    suffix = Path(path).suffix.lower()
    if Path(path).stem.lower() in _SHELL_NAMES:
        raise ValueError("Command interpreters are not tool entry points")
    if suffix in (".py", ".jar", ".exe", ".html", ".htm"):
        return suffix[1:]
    # POSIX binaries (including python3.11) or extensionless Python entry points.
    if suffix not in (".bat", ".cmd", ".ps1", ".sh", ".vbs", ".js") and os.access(path, os.X_OK):
        with open(path, "rb") as handle:
            prefix = handle.read(128)
        if prefix.startswith(b"#!") and re.search(rb"\bpython(?:[23](?:\.\d+)?)?\b", prefix.split(b"\n", 1)[0]):
            return "py"
        if prefix.startswith((b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe")):
            return "binary"
    raise ValueError("Select a .py, .jar, .exe, local HTML, or native executable; shell/batch scripts are not supported")


def _validate_path(key, path):
    meta = _meta(key)
    if not meta["candidates"]:
        raise ValueError(meta["description"])
    path = os.fsdecode(os.fspath(path))
    if not path or any(unicodedata.category(c) == "Cc" for c in path):
        raise ValueError("Invalid tool path")
    if path.startswith(("\\\\", "//")) or "://" in path:
        raise ValueError("Select a local file, not a network location")
    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(path):
        raise FileNotFoundError("Tool file does not exist: " + path)
    kind = _file_kind(path)
    if key == "cyberchef" and kind not in ("html", "htm"):
        raise ValueError("CyberChef requires an offline HTML entry point")
    if key != "cyberchef" and kind in ("html", "htm"):
        raise ValueError("HTML entry points are only supported for CyberChef")
    if kind == "jar" and key != "burp":
        raise ValueError("JAR entry points are only supported for Burp Community")
    return path


def configure_tool(key, path):
    """Validate and atomically persist a selected local file; return its absolute path.

    Raises ValueError/OSError on invalid input or persistence failure. No program
    is executed and a malformed existing configuration is never overwritten.
    """
    path = _validate_path(key, path)
    with _PATH_LOCK:
        paths = _load_paths()
        paths[key] = path
        text = json.dumps(paths, ensure_ascii=False, indent=2)
        if len(text) > _CONFIG_LIMIT:
            raise ValueError("Tool path configuration exceeds the size limit")
        os.makedirs(WORKSPACE, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=WORKSPACE,
                                             prefix="web_tool_paths_", suffix=".tmp", delete=False) as handle:
                temporary = handle.name
                handle.write(text + "\n")
            os.replace(temporary, _config_path())
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)
    return path


def _discover(key):
    meta = _meta(key)
    if not meta["candidates"]:
        return None, "manual"
    selected = _load_paths().get(key)
    if selected is not None:
        # A stale explicit choice must not silently launch a different program.
        return _validate_path(key, selected), "configured"
    if key == "cyberchef":
        offline = webnav.offline_path("CyberChef")
        if offline:
            return _validate_path(key, offline), "offline mirror"
    if key == "binwalk":
        python = external_python()
        if python and os.path.isfile(python):
            entry = os.path.join(os.path.dirname(python), "Scripts", "binwalk")
            if os.path.isfile(entry):
                return _validate_path(key, entry), "portable runtime"
    # Only file-discovery tables; package detection does not imply a CLI entry.
    if any(key in table for table in (toolsmgr.PORTABLE_TOOLS, toolsmgr.PATH_TOOLS,
                                      toolsmgr.COMMON_DIRS)):
        try:
            detected = toolsmgr.detect_one(key)
            if detected:
                return _validate_path(key, detected), "toolsmgr"
        except (KeyError, ValueError, OSError):
            pass
    for candidate in meta["candidates"]:
        for root in (os.path.join(TOOLS_DIR, key), TOOLS_DIR):
            for path in glob.iglob(os.path.join(root, candidate)):
                try:
                    return _validate_path(key, path), "local"
                except (ValueError, OSError):
                    continue
        if "/" not in candidate and not glob.has_magic(candidate):
            path = shutil.which(candidate)
            if path:
                try:
                    return _validate_path(key, path), "PATH"
                except (ValueError, OSError):
                    continue
    return None, "missing"


def _runtime(path, label):
    if not path:
        raise FileNotFoundError(label + " runtime not found; configure/install it separately")
    resolved = shutil.which(path) if not os.path.isfile(path) else path
    if not resolved or not os.path.isfile(resolved):
        raise FileNotFoundError(label + " runtime is not a local file")
    resolved = os.path.abspath(resolved)
    if _file_kind(resolved) not in ("exe", "binary"):
        raise ValueError(label + " runtime must be a native executable, not a shell script")
    if getattr(sys, "frozen", False) and os.path.normcase(os.path.realpath(resolved)) == os.path.normcase(os.path.realpath(sys.executable)):
        raise ValueError("The frozen GUI executable cannot be used as a tool runtime")
    return resolved


def _command_for(path):
    kind = _file_kind(path)
    if kind == "py":
        python = _runtime(external_python(), "External Python")
        return [python] + (["-3"] if Path(python).stem.lower() == "py" else []) + [path]
    if kind == "jar":
        java = _runtime(shutil.which("java") or toolsmgr.detect_one("java"), "Java")
        return [java, "-jar", path]
    return [path]


def get_tool_command(key):
    """Return a base argv, without user arguments or a shell.

    Browser features return []; missing tools/runtimes raise ValueError/OSError.
    An HTML entry returns [absolute_html_path], for a browser rather than Popen.
    Finding an entry/runtime does not validate third-party packages or versions.
    """
    path, _ = _discover(key)
    if not _meta(key)["candidates"]:
        return []
    if not path:
        raise FileNotFoundError(_meta(key)["name"] + " not found; browse to its local entry point")
    return _command_for(path)


def tool_status():
    """Return key -> metadata plus path, source, available, ready, command, detail.

    available means an entry file exists; ready means its launcher is resolvable,
    not that its dependencies work. Manual browser features have neither flag.
    Discovery never installs tools or invokes a CLI to test its dependencies.
    """
    result = {}
    for key, meta in TOOLS.items():
        item = dict(meta, path=None, source="missing", available=False,
                    ready=False, command=[], detail=meta["description"])
        try:
            path, source = _discover(key)
            item.update(path=path, source=source, available=bool(path))
            if path:
                item["command"] = _command_for(path)
                item["ready"] = True
                item["detail"] += " 已找到本地入口和运行时；不代表依赖、版本或旗标已验证。"
            elif meta["candidates"]:
                item["detail"] += " 未找到，请选择本地入口；配置操作不会自动下载工具。"
        except (OSError, ValueError) as exc:
            item["detail"] += " " + str(exc)
        result[key] = item
    return result


def launch_tool(key, log=print):
    """Return (success, detail). Only explicitly selected GUI/HTML tools launch.

    CLI/context-only entries log their base argv and actionable manual guidance,
    without starting an invisible interactive process. GUI processes are left
    under the user's control, not treated as timed workflow subprocesses.
    """
    meta = _meta(key)
    try:
        command = get_tool_command(key)
        if meta["mode"] == "html":
            if not webbrowser.open(Path(command[0]).as_uri()):
                raise OSError("The browser did not accept the offline HTML page")
            detail = "Opened offline page: " + command[0]
        elif meta["mode"] == "gui":
            subprocess.Popen(command, shell=False, cwd=os.path.dirname(command[-1]),
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            detail = "Opened " + meta["name"] + ". " + meta["description"]
        else:
            detail = meta["description"]
            if command:
                detail += "\n手动入口就绪（本次未执行）。先切换至工具目录：" + os.path.dirname(command[-1])
                detail += "\nWindows CMD 基础命令：\n" + subprocess.list2cmdline(command)
                detail += "\n请先查看工具帮助，并提供所需的 CTF 请求、令牌或本地文件；SSRFmap 必须明确指定参数与模块，不要使用默认全模块运行。"
        log(detail)
        return True, detail
    except (OSError, ValueError, webbrowser.Error) as exc:
        detail = meta["name"] + ": " + str(exc)
        log(detail)
        return False, detail


def _decode_segment(segment, allow_empty=False):
    if not segment and allow_empty:
        return b""
    if not segment or len(segment) > (MAX_JWT_BYTES * 4 + 2) // 3:
        raise ValueError("JWT segment is empty or exceeds the size limit")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", segment) or len(segment) % 4 == 1:
        raise ValueError("JWT requires unpadded base64url segments")
    try:
        decoded = base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Invalid JWT base64url") from exc
    if len(decoded) > MAX_JWT_BYTES or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != segment:
        raise ValueError("Oversized or non-canonical JWT base64url")
    return decoded


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JWT JSON key: " + key)
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("Non-finite JWT JSON constant: " + value)


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Non-finite JWT JSON number")
    return number


def decode_jwt(token):
    """Strict bounded offline compact-JWT decoding, NEVER signature verification.

    Returns header/payload objects, the encoded signature and an explicit warning.
    Rejects malformed/oversized base64url, non-object JSON and duplicate keys.
    """
    if not isinstance(token, str) or len(token) > MAX_JWT_CHARS:
        raise ValueError("JWT must be a bounded compact string")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have exactly three compact segments")
    objects = []
    try:
        for part in parts[:2]:
            value = json.loads(_decode_segment(part).decode("utf-8"),
                               object_pairs_hook=_unique_object, parse_constant=_invalid_constant,
                               parse_float=_finite_float)
            if not isinstance(value, dict):
                raise ValueError("JWT header and payload must be JSON objects")
            objects.append(value)
        _decode_segment(parts[2], allow_empty=True)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid JWT JSON") from exc
    return {"header": objects[0], "payload": objects[1], "signature": parts[2],
            "signature_verified": False,
            "warning": "Decoded only. Signature, algorithm, issuer, audience and expiry have NOT been verified; do not trust these claims."}


jwt_decode = decode_jwt


def validate_url(url):
    """Validate one HTTP(S) host; preserve path/query, reject ambiguous authorities."""
    if not isinstance(url, str) or not url or len(url) > 8192:
        raise ValueError("Provide one HTTP(S) CTF URL, at most 8192 characters")
    if any(c.isspace() or unicodedata.category(c) == "Cc" for c in url) or "\\" in url or "#" in url:
        raise ValueError("URL whitespace, control characters, backslashes and fragments are not allowed")
    if re.search(r"%(?![0-9a-fA-F]{2})", url) or any(unicodedata.category(c) == "Cc" for c in unquote(url)):
        raise ValueError("URL contains invalid escapes or encoded control characters")
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in ("http", "https") or not parts.netloc or not parts.hostname:
            raise ValueError("A single HTTP(S) host is required")
        if parts.username is not None or parts.password is not None or any(c in parts.netloc for c in "@%,*"):
            raise ValueError("Credentials and multiple/ambiguous hosts are not allowed")
        port = parts.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Invalid URL port")
        if parts.netloc.endswith(":"):
            raise ValueError("Empty URL port")
        host = parts.hostname
        try:
            address = ipaddress.ip_address(host)
            host = "[" + str(address) + "]" if address.version == 6 else str(address)
        except ValueError:
            host = host.encode("idna").decode("ascii").lower()
            if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                         for label in host.rstrip(".").split(".")):
                raise ValueError("Invalid URL hostname")
        authority = host + (":" + str(port) if port is not None else "")
        # Reject text after a closing IPv6 bracket that urlsplit otherwise ignores.
        if parts.netloc.startswith("[") and not re.fullmatch(r"\[[^\]]+\](?::[0-9]+)?", parts.netloc):
            raise ValueError("Invalid IPv6 authority")
        return urlunsplit((parts.scheme.lower(), authority,
                           quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~"),
                           quote(parts.query, safe="/%?:@!$&'()*+,;=-._~"), ""))
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Invalid CTF URL: " + str(exc)) from exc


def _check_control(cancel_event, deadline):
    if cancel_event is not None and cancel_event.is_set():
        raise TaskCancelled("Workflow cancelled")
    if time.monotonic() >= deadline:
        raise TaskTimeout("Workflow step timeout")


def _http_get(url, cancel_event, deadline, capture=False):
    """One direct GET; no proxy, cookies, auth, redirects or decompression.

    Opt-in capture adds request metadata, redacted response headers, bounded raw
    body bytes and milliseconds. The default summary and transport are unchanged.

    A watchdog bounds even trickled headers/bodies and interrupts an open socket.
    OS DNS resolution may finish in the daemon worker after cancellation; the
    guarded connection prevents a subsequent HTTP request on that connection.
    """
    _check_control(cancel_event, deadline)
    parts = urlsplit(url)
    stopped, done = threading.Event(), threading.Event()
    outcome = {}
    request_headers = []
    base = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection

    class Connection(base):
        def putheader(self, header, *values):
            super().putheader(header, *values)
            if capture:
                request_headers.append({"name": header, "value": ", ".join(map(str, values))})

        def connect(self):
            super().connect()
            if stopped.is_set():
                self.close()
                raise TaskCancelled("HTTP request stopped before sending")

    connection = Connection(parts.hostname, parts.port, timeout=min(5.0, max(0.001, deadline - time.monotonic())))

    def work():
        response = None
        try:
            if stopped.is_set():
                return
            target = urlunsplit(("", "", parts.path or "/", parts.query, ""))
            started_utc = datetime.now(timezone.utc).isoformat()
            started_at = time.monotonic()
            connection.request("GET", target, headers={"User-Agent": "魔盒-CTF-CTFWorkflow/1.0",
                                                       "Accept-Encoding": "identity", "Connection": "close"})
            # getresponse() detaches connection.sock for Connection: close.
            # Keep the transport so cancellation can still interrupt body reads.
            outcome["transport"] = connection.sock
            response = connection.getresponse()
            headers_at = time.monotonic()
            data = bytearray()
            while not stopped.is_set() and len(data) <= MAX_RESPONSE_BYTES:
                chunk = response.read1(min(8192, MAX_RESPONSE_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if stopped.is_set():
                return
            text = bytes(data[:MAX_RESPONSE_BYTES]).decode("utf-8", "replace")
            title = re.search(r"<title\b[^>]*>(.*?)</title>", text, re.I | re.S)
            outcome["value"] = {
                "url": url, "status_code": response.status,
                "bytes_read": min(len(data), MAX_RESPONSE_BYTES),
                "truncated": len(data) > MAX_RESPONSE_BYTES,
                "title": " ".join(title.group(1).split())[:200] if title else "",
                "redirect_followed": False,
                "location": (response.getheader("Location") or "")[:2048],
            }
            if capture:
                finished_at = time.monotonic()
                outcome["value"].update(
                    request={"method": "GET", "url": url, "httpVersion": "HTTP/1.1",
                             "headers": request_headers, "cookies": [],
                             "queryString": [{"name": k, "value": v} for k, v in
                                             parse_qsl(parts.query, keep_blank_values=True)],
                             "headersSize": -1, "bodySize": 0},
                    response_headers=[{"name": k, "value": "[REDACTED]" if k.lower() == "set-cookie" else v}
                                      for k, v in response.getheaders()],
                    body=bytes(data[:MAX_RESPONSE_BYTES]),
                    status_text=response.reason or "",
                    http_version={10: "HTTP/1.0", 11: "HTTP/1.1"}.get(response.version, "HTTP/1.0"),
                    mime_type=response.getheader("Content-Type") or "application/octet-stream",
                    started_utc=started_utc,
                    elapsed_ms=(finished_at - started_at) * 1000,
                    timings={"blocked": -1, "dns": -1, "connect": -1, "ssl": -1,
                             "send": 0, "wait": (headers_at - started_at) * 1000,
                             "receive": (finished_at - headers_at) * 1000,
                             "comment": "连接、发送与等待响应头合并计入 wait；未单独测量 DNS/TLS。"})
        except Exception as exc:
            outcome["error"] = exc
        finally:
            if response is not None:
                response.close()
            connection.close()
            done.set()

    threading.Thread(target=work, name="ctf-http-request", daemon=True).start()
    try:
        while not done.wait(min(0.05, max(0.001, deadline - time.monotonic()))):
            _check_control(cancel_event, deadline)
        _check_control(cancel_event, deadline)
        if "error" in outcome:
            raise outcome["error"]
        return outcome["value"]
    finally:
        stopped.set()
        # shutdown unblocks a concurrent read; close() alone need not unblock it.
        sock = connection.sock or outcome.get("transport")
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        # Only the worker closes HTTPResponse/its buffered file. A concurrent
        # connection.close() can wait on the reader lock until socket timeout
        # (notably on Windows), blocking cancellation despite the watchdog.


def _http_detail(item):
    detail = "HTTP {status_code}; read {bytes_read} bytes; title={title!r}".format(**item)
    if item["truncated"]:
        detail += "; response truncated at %d bytes" % MAX_RESPONSE_BYTES
    if item["location"]:
        detail += "; redirect NOT followed; Location=" + repr(item["location"])
    return detail


_HAR_WARNING = ("本地敏感数据警告：HAR 仅记录本步骤的一次请求，不是系统抓包。"
                "Set-Cookie 已隐藏，但 URL、查询参数、其他响应头和正文仍可能含令牌或个人信息；请勿公开分享。")


def _save_har(item, run_id):
    """HAR 1.2 with one entry; never copy the body into workflow/UI details."""
    content = {"size": len(item["body"]), "mimeType": item["mime_type"],
               "text": base64.b64encode(item["body"]).decode("ascii"), "encoding": "base64"}
    if item["truncated"]:
        content["comment"] = "仅保留前 %d 字节，正文已截断；size 为捕获长度。" % MAX_RESPONSE_BYTES
    entry = {"startedDateTime": item["started_utc"], "time": item["elapsed_ms"],
             "request": item["request"],
             "response": {"status": item["status_code"], "statusText": item["status_text"],
                          "httpVersion": item["http_version"], "headers": item["response_headers"],
                          "cookies": [], "content": content,
                          "redirectURL": next((h["value"] for h in item["response_headers"]
                                               if h["name"].lower() == "location"), ""),
                          "headersSize": -1,
                          "bodySize": -1 if item["truncated"] else len(item["body"])},
             "cache": {}, "timings": item["timings"], "comment": _HAR_WARNING}
    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = os.path.abspath(os.path.join(REPORTS_DIR, "web_workflow_" + run_id + ".har"))
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"log": {"version": "1.2", "creator": {"name": "魔盒-CTF", "version": "1.0"},
                           "entries": [entry], "comment": _HAR_WARNING}},
                  handle, ensure_ascii=False, indent=2)
    return path


def _wait_request(last_start, cancel_event, deadline):
    """Cancellable start-to-start rate limit (at most two requests per second)."""
    if last_start is not None:
        until = last_start + 0.5
        while time.monotonic() < until:
            _check_control(cancel_event, deadline)
            delay = min(0.05, until - time.monotonic())
            if delay > 0:
                if cancel_event is not None:
                    cancel_event.wait(delay)
                else:
                    time.sleep(delay)
    _check_control(cancel_event, deadline)


def _source(url, log, cancel_event, deadline):
    parts = urlsplit(url)
    target = urlunsplit((parts.scheme, parts.netloc, "/.git/HEAD", "", ""))
    started_at = time.monotonic()
    item = _http_get(target, cancel_event, deadline, capture=True)
    note = "仅检测 .git/HEAD 暴露线索，不拉取源码、不执行文件；无重定向。"
    body = item["body"].strip()
    if (item["status_code"] != 200 or item["truncated"] or not re.fullmatch(
            rb"(?:ref: refs/heads/[A-Za-z0-9_./-]+|[0-9a-fA-F]{40})", body)):
        return "ok", "未发现有效的 .git/HEAD 线索。" + note
    _wait_request(started_at, cancel_event, deadline)
    control_url = urlunsplit((parts.scheme, parts.netloc,
                             "/.ctf_not_found_" + uuid.uuid4().hex, "", ""))
    control = _http_get(control_url, cancel_event, deadline, capture=True)
    if control["truncated"] or body == control["body"].strip():
        return "ok", "未报告暴露：随机不存在路径的对照正文相同（soft404）或对照已截断。" + note
    log("[source] 已对照随机不存在路径；未进一步访问 Git 文件。")
    return "ok", "发现 .git/HEAD 暴露线索：" + target + "；仍需人工确认。" + note


def _xss(url, log, cancel_event, deadline):
    parts = urlsplit(url)
    # Preserve every other raw query component, including duplicates and blanks.
    query = parts.query.split("&")
    indexes = [i for i, part in enumerate(query) if part.split("=", 1)[0]][:5]
    note = "内置反射线索检测（不是 XSStrike），不是已确认 XSS；未执行脚本，需人工检查上下文。"
    if not indexes:
        return "skipped", "无 URL 查询参数，跳过。" + note
    observations, last_start = [], None
    for index in indexes:
        _wait_request(last_start, cancel_event, deadline)
        marker = "ctf_" + uuid.uuid4().hex
        payload = marker + "'\"<>"
        changed = list(query)
        name = query[index].split("=", 1)[0]
        changed[index] = name + "=" + quote(payload, safe="")
        target = urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(changed), ""))
        last_start = time.monotonic()
        item = _http_get(target, cancel_event, deadline, capture=True)
        text = item["body"].decode("utf-8", "replace")
        if payload in text:
            reflection = "未转义反射"
        elif payload in html.unescape(unquote(text)):
            reflection = "已编码反射（未见完整未转义标记）"
        elif marker in text:
            reflection = "部分标记反射（未见完整未转义标记）"
        else:
            reflection = "未发现反射（限已读取正文）"
        observation = {"parameter_index": index + 1, "parameter": unquote(name),
                       "marker": marker, "reflection": reflection,
                       "status_code": item["status_code"], "truncated": item["truncated"]}
        observations.append(observation)
        log("[xss] 参数 #%d %s：%s；不是已确认 XSS。" % (index + 1, unquote(name), reflection))
    return "ok", note + " 每次仅替换一个值，最多 5 个参数、每秒最多 2 次请求，同源且不跟随重定向。" + json.dumps(
        observations, ensure_ascii=False)


def _directory_words():
    words = []
    for word in DIR_WORDS:
        if (isinstance(word, str) and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", word)
                and not any(part in (".", "..") for part in word.split("/")) and word not in words):
            words.append(word)
            if len(words) == 80:
                break
    return words


# Empty exclude-subdirs can become an empty prefix upstream and suppress every scan.
_DIRSEARCH_CONFIG = """[general]
threads = 1
async = False
subdirs = /
exclude-subdirs = ../
recursive = False
deep-recursive = False
force-recursive = False
max-recursion-depth = 0
[dictionary]
default-extensions =
prefixes =
suffixes =
[request]
follow-redirects = False
[connection]
timeout = 5
max-retries = 0
[advanced]
crawl = False
"""


def _directory_tool(step, url, log, cancel_event, deadline, run_id):
    _check_control(cancel_event, deadline)
    try:
        command = get_tool_command(step)
        if not command:
            raise FileNotFoundError("未找到命令入口")
    except (OSError, ValueError) as exc:
        _check_control(cancel_event, deadline)
        return "skipped", "工具或运行时不可用：" + str(exc)
    _check_control(cancel_event, deadline)
    words = _directory_words()
    if not words:
        return "skipped", "固定目录词表过滤后为空。"
    parts = urlsplit(url)
    origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
    os.makedirs(WORKSPACE, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ctf_dirs_", dir=WORKSPACE) as temporary:
        wordlist = os.path.abspath(os.path.join(temporary, "words.txt"))
        with open(wordlist, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(words) + "\n")
        # ffuf's default ffufrc is per-user (Go os.UserConfigDir); keep it empty.
        # Preserve PATH/SystemRoot and runtimes, but do not inherit user scan options.
        env = os.environ.copy()
        for key in list(env):
            if key.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "dirsearch_config"):
                env.pop(key)
        env["NO_PROXY"] = "*"
        for key in ("HOME", "USERPROFILE", "XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA"):
            env[key] = os.path.abspath(temporary)
        if step == "dirsearch":
            config = os.path.abspath(os.path.join(temporary, "dirsearch.ini"))
            with open(config, "w", encoding="utf-8") as handle:
                handle.write(_DIRSEARCH_CONFIG)
            args = command + ["-u", origin, "-w", wordlist, "-t", "1", "--max-rate=2",
                              "--timeout=5", "--retries=0", "--no-color", "--quiet",
                              "--skip-on-status=429", "--config=" + config]
            output_note = "结果见工具日志。"
        else:
            os.makedirs(REPORTS_DIR, exist_ok=True)
            output = os.path.abspath(os.path.join(REPORTS_DIR, "web_workflow_" + run_id + "_ffuf.json"))
            args = command + ["-u", origin + "/FUZZ", "-w", wordlist, "-t", "1", "-rate", "2",
                              "-timeout", "5", "-noninteractive", "-of", "json", "-o", output]
            output_note = "工具 JSON 输出路径：" + output + "。"
        log("[%s] 固定 %d 词、单线程、每秒最多 2 次请求；不递归、不跟随重定向。"
            "自定义工具版本若不兼容，不自动降级重试。" % (step, len(words)))
        _check_control(cancel_event, deadline)
        remaining = deadline - time.monotonic()
        if step == "ffuf":
            # ffuf requires integer seconds; the outer deadline also covers <1s.
            args += ["-maxtime", str(max(1, math.floor(remaining)))]
        completed = run_command(args, log=log, cancel_event=cancel_event,
                                timeout=max(0.001, remaining),
                                cwd=os.path.dirname(os.path.abspath(command[-1])), env=env)
        _check_control(cancel_event, deadline)
    detail = "%s 退出码 %s；%s " % (step, completed.returncode, output_note)
    detail += "ok 仅代表执行成功，不代表没有漏洞或已确认漏洞；需人工分析结果（可能有 soft404）。"
    return ("ok" if completed.returncode == 0 else "error"), detail


def _dirs(url, log, cancel_event, deadline):
    parts = urlsplit(url)
    # Do not propagate page parameters to unrelated directory paths.
    words = list(dict.fromkeys(DIR_WORDS))[:80]
    observations, errors = [], 0
    last_start = None
    for word in words:
        _check_control(cancel_event, deadline)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", word) or ".." in word.split("/"):
            continue
        if last_start is not None:
            wait_until = last_start + 0.5
            while time.monotonic() < wait_until:
                _check_control(cancel_event, deadline)
                delay = min(0.05, wait_until - time.monotonic())
                if delay > 0:
                    if cancel_event is not None:
                        cancel_event.wait(delay)
                    else:
                        time.sleep(delay)
        _check_control(cancel_event, deadline)
        candidate = urlunsplit((parts.scheme, parts.netloc, "/" + word, "", ""))
        last_start = time.monotonic()
        try:
            item = _http_get(candidate, cancel_event, deadline)
            observations.append({"url": candidate, "status_code": item["status_code"]})
            log("[dirs] " + candidate + " " + _http_detail(item))
        except (TaskCancelled, TaskTimeout):
            raise
        except (OSError, http.client.HTTPException) as exc:
            errors += 1
            log("[dirs] " + candidate + ": " + str(exc))
    detail = "Fixed wordlist, <=2 requests/s; no redirects/crawling. Responses are not proof of exposed resources (soft 404s possible). "
    detail += json.dumps({"responses": observations, "request_errors": errors}, ensure_ascii=False)
    return ("error" if errors else "ok"), detail


def _tool_step(step, url, log, cancel_event, deadline, run_id):
    _check_control(cancel_event, deadline)
    if not urlsplit(url).query or not any(part.split("=", 1)[0] for part in urlsplit(url).query.split("&")):
        return "skipped", "No URL query parameters; detection requires an explicit parameterized CTF request."
    try:
        command = get_tool_command(step)
    except (OSError, ValueError) as exc:
        _check_control(cancel_event, deadline)
        return "skipped", "Tool/runtime unavailable: " + str(exc)
    _check_control(cancel_event, deadline)
    if step == "xsstrike":
        return "skipped", ("XSStrike found, but its stock CLI has no enforceable no-redirect option. "
                           "Use manual scoped detection; automatic crawl/fuzzer/blind modes are disabled.")
    output = os.path.abspath(os.path.join(WORKSPACE, "web_workflow_" + run_id, "sqlmap"))
    os.makedirs(output, exist_ok=True)
    args = command + ["-u", url, "--batch", "--level=1", "--risk=1", "--threads=1",
                      "--timeout=5", "--retries=0", "--delay=0.5", "--ignore-redirects",
                      "--ignore-proxy", "--technique=BEU", "--output-dir=" + output]
    _check_control(cancel_event, deadline)
    log("[sqlmap] Detection only; no enumeration/dump/OS shell. Output: " + output)
    completed = run_command(args, log=log, cancel_event=cancel_event,
                            timeout=max(0.001, deadline - time.monotonic()),
                            cwd=os.path.dirname(command[-1]))
    _check_control(cancel_event, deadline)
    detail = "SQLMap exit code %s; output: %s. " % (completed.returncode, output)
    detail += "Review tool output manually; exit 0 is NOT proof of a vulnerability."
    return ("ok" if completed.returncode == 0 else "error"), detail


def _auto(url, log, cancel_event, deadline):
    """一键只读取证链：指纹 → robots → 敏感文件 → 目录 → 参数弱点 → flag 汇总。"""
    from . import webauto
    _check_control(cancel_event, deadline)
    remaining = max(1.0, deadline - time.monotonic())
    result = webauto.auto_solve(url, log=log, max_seconds=remaining,
                                cancel_event=cancel_event)
    _check_control(cancel_event, deadline)
    status = "ok" if not result.get("stopped") else "error"
    flags = result.get("flags") or []
    # 只在拿到 flag 时落盘报告；没拿到就没有可交付的结果，不产生报告文件
    path = webauto.save_report(result) if flags else ""
    detail = result.get("summary", "") + "\n请求数：%s%s" % (
        result.get("requests"), ("；报告：" + path) if path else "")
    return status, detail, flags


def _deep(url, log, cancel_event, deadline):
    """深度全自动：页面分析 → 参数全 payload 矩阵 → 上传测试 → 定向取 flag，
    再按已命中的类型接着跑外部工具（有注入线索跑 sqlmap，没命中就扩目录词表）。

    引擎内部自带请求预算与同源校验；这里只把剩余时间传进去，并在结束后落盘报告。
    """
    from . import webattack
    run_id = time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]
    _check_control(cancel_event, deadline)
    left = max(4.0, deadline - time.monotonic())
    result = webattack.campaign(url, log=log, max_seconds=min(left, 240.0),
                                cancel_event=cancel_event)
    _check_control(cancel_event, deadline)
    flags = result.get("flags") or []
    status = "ok" if not result.get("stopped") else "error"
    # 只在拿到 flag 时落盘报告：没拿到就不写文件，界面日志仍给出摘要与请求数
    if flags:
        report = webattack.render(result)
        path = webattack.save_report(result)
        detail = (report[-4000:] if len(report) > 4000 else report) + "\n请求数：%s；JSON 报告：%s" % (
            result.get("requests"), path)
    else:
        detail = ("未拿到 flag。请求数：%s；发现 %d 条。"
                  % (result.get("requests"), len(result.get("findings") or [])))
    # ---- 外部工具接力：只在还有时间、工具可用、且还没拿到 flag 时才跑 ----
    types = {f["type"] for f in result.get("findings") or []}
    follow = []
    if flags:
        detail += "\n已拿到 flag，跳过外部工具接力。"
        return status, detail, flags
    try:
        if ("sqli-error" in types or "sqli-boolean" in types or "sqli-time" in types) \
                and deadline - time.monotonic() > 45:
            deep_url = next((f["url"] for f in result["findings"] if f["type"].startswith("sqli")), url)
            log("[deep] 注入线索已成立，接力 sqlmap：" + deep_url)
            st, dt = _tool_step("sqlmap", deep_url, log, cancel_event,
                                min(deadline - 5, time.monotonic() + 75), run_id)
            follow.append("sqlmap：%s ｜ %s" % (st, dt.split("\n")[0]))
        if deadline - time.monotonic() > 50:
            log("[deep] 接力目录词表（dirsearch 可用则用，否则内置词表已在 auto 步骤里）")
            st, dt = _dirs(url, log, cancel_event, min(deadline - 5, time.monotonic() + 60))
            follow.append("目录探测：%s ｜ %s" % (st, dt.split("\n")[0]))
    except TaskTimeout as exc:
        follow.append("外部工具超时：" + str(exc))
    except Exception as exc:
        follow.append("外部工具失败：%s: %s" % (type(exc).__name__, exc))
    if follow:
        detail += "\n\n== 外部工具接力 ==" + "\n" + "\n".join("- " + item for item in follow)
    return status, detail, flags


def run_workflow(url, steps, log=print, cancel_event=None, step_timeout=180):
    """Run selected steps in caller order；只在拿到 flag 时汇总 JSON 报告到 REPORTS_DIR。

    Returns [{step, status, detail}], statuses: ok/skipped/error/timeout/cancelled.
    Invalid URL/steps/timeout raise ValueError before any requests. Failures and
    timeouts do not prevent independent later steps; cancellation prevents every
    remaining step. Each step has a fresh deadline, including tool discovery.
    XSStrike skips even when found: no safe redirect control in its stock CLI.
    http saves a single-request HAR; dirs/source/xss are bounded built-ins.
    dirsearch/ffuf/sqlmap are optional local CLIs; other tools remain manual.
    """
    url = validate_url(url)
    if not isinstance(steps, (list, tuple)) or len(steps) > len(ALLOWED_STEPS):
        raise ValueError("steps must be an ordered list/tuple of allowed steps")
    if any(not isinstance(step, str) or step not in ALLOWED_STEPS for step in steps) or len(set(steps)) != len(steps):
        raise ValueError("Choose each step at most once from: " + ", ".join(ALLOWED_STEPS))
    if isinstance(step_timeout, bool):
        raise ValueError("step_timeout must be a finite positive number")
    try:
        step_timeout = float(step_timeout)
    except (TypeError, ValueError) as exc:
        raise ValueError("step_timeout must be a finite positive number") from exc
    if not math.isfinite(step_timeout) or step_timeout <= 0:
        raise ValueError("step_timeout must be a finite positive number")
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    run_id = time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex
    results, cancelled = [], False
    got_flags = []
    log("[workflow] CTF-only single-origin sequence; use only your authorized challenge. No crawling or redirects.")
    for step in steps:
        deadline = time.monotonic() + step_timeout
        flags = []
        try:
            if cancelled:
                raise TaskCancelled("Not started: workflow cancelled")
            _check_control(cancel_event, deadline)
            log("[workflow] Starting " + step)
            if step == "http":
                item = _http_get(url, cancel_event, deadline, capture=True)
                _check_control(cancel_event, deadline)
                har_path = _save_har(item, run_id)
                status, detail = "ok", _http_detail(item) + "\nHAR 文件：" + har_path + "\n" + _HAR_WARNING
            elif step == "dirs":
                status, detail = _dirs(url, log, cancel_event, deadline)
            elif step == "source":
                status, detail = _source(url, log, cancel_event, deadline)
            elif step == "xss":
                status, detail = _xss(url, log, cancel_event, deadline)
            elif step == "auto":
                status, detail, flags = _auto(url, log, cancel_event, deadline)
            elif step == "deep":
                status, detail, flags = _deep(url, log, cancel_event, deadline)
            elif step in ("dirsearch", "ffuf"):
                status, detail = _directory_tool(step, url, log, cancel_event, deadline, run_id)
            else:
                status, detail = _tool_step(step, url, log, cancel_event, deadline, run_id)
            _check_control(cancel_event, deadline)
        except TaskCancelled as exc:
            status, detail, cancelled = "cancelled", str(exc), True
        except TaskTimeout as exc:
            status, detail = "timeout", str(exc)
        except Exception as exc:
            status, detail = "error", "%s: %s" % (type(exc).__name__, exc)
        got_flags.extend(flags)
        results.append({"step": step, "status": status, "detail": detail})
        log("[workflow] %s: %s — %s" % (step, status, detail))
    # 只在真正拿到 flag 的那一步落盘汇总报告；没拿到就不产生报告文件
    if got_flags:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        report_path = os.path.abspath(os.path.join(REPORTS_DIR, "web_workflow_" + run_id + ".json"))
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump({"url": url, "started_utc": started,
                       "scope": "CTF-only; single origin; no redirects/crawling",
                       "flags": got_flags, "results": results}, handle, ensure_ascii=False, indent=2)
        log("[workflow] 拿到 flag，已生成 JSON 报告：" + report_path)
    else:
        log("[workflow] 未拿到 flag，不生成报告文件")
    return results
