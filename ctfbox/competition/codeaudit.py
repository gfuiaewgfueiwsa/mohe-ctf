# -*- coding: utf-8 -*-
"""代码审计：PHP / Java / Python 危险函数、可控输入汇聚点、反序列化入口、SQL 拼接。

启发式：按行匹配 source→sink，并跟踪同文件简单赋值传播；结论需人工复核。
"""
import os
import re

from . import util

LANG_EXTS = {
    ".php": "php", ".phtml": "php", ".php3": "php", ".php4": "php",
    ".php5": "php", ".inc": "php",
    ".java": "java", ".jsp": "java", ".jspx": "java",
    ".py": "python", ".pyw": "python",
}

SOURCE_RE = {
    "php": re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|"
                      r"php://input|getallheaders\s*\(", re.I),
    "java": re.compile(r"\b(?:getParameter|getHeader|getInputStream|getReader|"
                       r"getQueryString|getCookies|getPathInfo)\s*\(|"
                       r"@(?:RequestParam|PathVariable|RequestBody|RequestHeader)\b"),
    "python": re.compile(r"\brequest\.(?:args|form|values|json|data|files|get_json)\b|"
                         r"\binput\s*\(|\bsys\.argv\b|\bos\.environ\b|\bsys\.stdin\b"),
}

TAINT_ASSIGN = {
    "php": re.compile(r"(\$[A-Za-z_]\w*)\s*=\s*(.+)$"),
    "java": re.compile(r"^\s*(?:[\w$.<>\[\],]+\s+)+(\w+)\s*=\s*(.+)$"),
    "python": re.compile(r"^(\s*)([A-Za-z_]\w*)\s*=\s*(.+)$"),
}

RULES = [
    # ---- PHP ----
    {"id": "php-eval", "lang": "php", "sev": "high",
     "re": re.compile(r"\beval\s*\("), "title": "eval 代码执行"},
    {"id": "php-assert", "lang": "php", "sev": "high",
     "re": re.compile(r"\bassert\s*\("), "title": "assert 代码执行"},
    {"id": "php-cmd", "lang": "php", "sev": "high",
     "re": re.compile(r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\("),
     "title": "系统命令执行函数"},
    {"id": "php-backtick", "lang": "php", "sev": "high",
     "re": re.compile(r"`[^`\r\n]*\$[^`\r\n]*`"), "title": "反引号命令执行"},
    {"id": "php-include", "lang": "php", "sev": "high",
     "re": re.compile(r"\b(?:include|include_once|require|require_once)\s*\(?\s*\$"),
     "title": "变量文件包含"},
    {"id": "php-unserialize", "lang": "php", "sev": "high",
     "re": re.compile(r"\bunserialize\s*\("), "title": "PHP 反序列化入口"},
    {"id": "php-phar", "lang": "php", "sev": "medium",
     "re": re.compile(r"phar://", re.I), "title": "phar:// 反序列化触发点"},
    {"id": "php-magic", "lang": "php", "sev": "info",
     "re": re.compile(r"function\s+__(?:wakeup|destruct|toString|call|invoke|"
                      r"get|set)\s*\("), "title": "PHP 魔术方法（POP gadget 候选）"},
    {"id": "php-sql", "lang": "php", "sev": "medium",
     "re": re.compile(r"\b(?:mysqli_query|mysql_query|pg_query|sqlite_query)\s*\("),
     "title": "SQL 查询函数"},
    {"id": "php-pdo", "lang": "php", "sev": "medium",
     "re": re.compile(r"->(?:query|exec)\s*\("), "title": "PDO/DB 查询调用"},
    {"id": "php-file", "lang": "php", "sev": "medium",
     "re": re.compile(r"\b(?:file_get_contents|file_put_contents|fopen|readfile|"
                      r"unlink|copy|rename|move_uploaded_file|file_exists)\s*\("),
     "title": "文件读写/操作函数"},
    {"id": "php-curl", "lang": "php", "sev": "medium",
     "re": re.compile(r"\bcurl_exec\s*\("), "title": "curl 发起请求（SSRF 候选）"},
    {"id": "php-xxe", "lang": "php", "sev": "medium",
     "re": re.compile(r"\b(?:simplexml_load_string|simplexml_load_file|DOMDocument|"
                      r"loadXML)\b"), "title": "XML 解析（XXE 候选）"},
    {"id": "php-upload", "lang": "php", "sev": "medium",
     "re": re.compile(r"\$_FILES|move_uploaded_file\s*\("), "title": "文件上传处理"},
    {"id": "php-header", "lang": "php", "sev": "low",
     "re": re.compile(r"\bheader\s*\(\s*[^)]*\$"), "title": "header 可变量（响应头注入）"},
    {"id": "php-echo", "lang": "php", "sev": "low",
     "re": re.compile(r"\b(?:echo|print|printf|vprintf)\b[^;\r\n]*\$"),
     "title": "输出变量（XSS 候选）"},
    {"id": "php-preg-e", "lang": "php", "sev": "high",
     "re": re.compile(r"preg_replace\s*\([^;]*?/[a-z]*e[a-z]*['\"]"),
     "title": "preg_replace /e 代码执行"},
    {"id": "php-extract", "lang": "php", "sev": "medium",
     "re": re.compile(r"\b(?:extract|parse_str)\s*\("), "title": "变量覆盖"},
    # ---- Java ----
    {"id": "java-cmd", "lang": "java", "sev": "high",
     "re": re.compile(r"Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder\b"),
     "title": "Java 命令执行"},
    {"id": "java-deser", "lang": "java", "sev": "high",
     "re": re.compile(r"\breadObject\s*\(|new\s+ObjectInputStream\b"),
     "title": "Java 反序列化入口"},
    {"id": "java-xmldecoder", "lang": "java", "sev": "high",
     "re": re.compile(r"\bXMLDecoder\b"), "title": "XMLDecoder 反序列化"},
    {"id": "java-xstream", "lang": "java", "sev": "medium",
     "re": re.compile(r"\.fromXML\s*\(|new\s+XStream\b"), "title": "XStream 反序列化"},
    {"id": "java-snakeyaml", "lang": "java", "sev": "medium",
     "re": re.compile(r"new\s+Yaml\s*\(|\.loadAs\s*\("), "title": "SnakeYAML 反序列化"},
    {"id": "java-jndi", "lang": "java", "sev": "high",
     "re": re.compile(r"\bInitialContext\b|\.lookup\s*\(|\$\{jndi:"),
     "title": "JNDI lookup（Log4Shell/注入）"},
    {"id": "java-scriptengine", "lang": "java", "sev": "medium",
     "re": re.compile(r"ScriptEngine\w*|\.eval\s*\("), "title": "脚本引擎 eval"},
    {"id": "java-sql", "lang": "java", "sev": "medium",
     "re": re.compile(r"\b(?:createStatement|prepareStatement|executeQuery|"
                      r"executeUpdate|execute)\s*\("), "title": "JDBC SQL 调用"},
    {"id": "java-xxe", "lang": "java", "sev": "medium",
     "re": re.compile(r"DocumentBuilderFactory|SAXParserFactory|SAXReader|"
                      r"XMLInputFactory|Unmarshaller"), "title": "XML 解析（XXE 候选）"},
    {"id": "java-ssrf", "lang": "java", "sev": "medium",
     "re": re.compile(r"new\s+URL\s*\(|openConnection\s*\(|HttpClient|RestTemplate|"
                      r"WebClient"), "title": "URL/HTTP 请求（SSRF 候选）"},
    {"id": "java-file", "lang": "java", "sev": "medium",
     "re": re.compile(r"new\s+FileInputStream|new\s+FileOutputStream|"
                      r"Files\.(?:read|write|copy|delete|newInputStream)|new\s+File\s*\("),
     "title": "文件读写（路径穿越候选）"},
    {"id": "java-reflection", "lang": "java", "sev": "medium",
     "re": re.compile(r"Class\.forName\s*\(|\.invoke\s*\(|setAccessible\s*\("),
     "title": "反射调用"},
    {"id": "java-weak-hash", "lang": "java", "sev": "low",
     "re": re.compile(r"MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-?1)", re.I),
     "title": "弱哈希算法"},
    {"id": "java-random", "lang": "java", "sev": "low",
     "re": re.compile(r"new\s+Random\s*\(|Math\.random\s*\("), "title": "非安全随机数"},
    {"id": "java-upload", "lang": "java", "sev": "medium",
     "re": re.compile(r"MultipartFile|transferTo\s*\("), "title": "文件上传处理"},
    {"id": "java-template", "lang": "java", "sev": "medium",
     "re": re.compile(r"SpelExpressionParser|ExpressionParser|freemarker|"
                      r"Template\.process\s*\("), "title": "模板/SpEL 注入候选"},
    # ---- Python ----
    {"id": "py-eval", "lang": "python", "sev": "high",
     "re": re.compile(r"\beval\s*\("), "title": "eval 代码执行"},
    {"id": "py-exec", "lang": "python", "sev": "high",
     "re": re.compile(r"\bexec\s*\("), "title": "exec 代码执行"},
    {"id": "py-pickle", "lang": "python", "sev": "high",
     "re": re.compile(r"\b(?:pickle|cPickle|dill|marshal)\.loads?\s*\("),
     "title": "Python 反序列化入口"},
    {"id": "py-yaml", "lang": "python", "sev": "medium",
     "re": re.compile(r"\byaml\.load\s*\("), "title": "yaml.load（需 SafeLoader）"},
    {"id": "py-shell", "lang": "python", "sev": "high",
     "re": re.compile(r"subprocess\.(?:run|call|Popen|check_output|check_call)|"
                      r"os\.system\s*\(|os\.popen\s*\(|commands\.getoutput"),
     "title": "子进程/命令执行"},
    {"id": "py-sql", "lang": "python", "sev": "medium",
     "re": re.compile(r"\.(?:execute|executemany)\s*\("), "title": "SQL 执行"},
    {"id": "py-template", "lang": "python", "sev": "medium",
     "re": re.compile(r"render_template_string\s*\(|\bTemplate\s*\(|from_string\s*\("),
     "title": "模板注入候选"},
    {"id": "py-ssrf", "lang": "python", "sev": "medium",
     "re": re.compile(r"requests\.(?:get|post|put|delete|request)\s*\(|"
                      r"urllib\.request|httpx\.|urlopen\s*\("),
     "title": "HTTP 请求（SSRF 候选）"},
    {"id": "py-file", "lang": "python", "sev": "medium",
     "re": re.compile(r"\bopen\s*\(|os\.(?:remove|rename|unlink)\s*\(|"
                      r"shutil\.(?:copy|move|rmtree)\s*\("), "title": "文件操作"},
    {"id": "py-tar", "lang": "python", "sev": "medium",
     "re": re.compile(r"tarfile\.(?:open|extractall)|zipfile\.(?:ZipFile|extractall)"),
     "title": "压缩包解压（路径穿越候选）"},
    {"id": "py-lxml", "lang": "python", "sev": "medium",
     "re": re.compile(r"lxml|etree\.(?:parse|fromstring)|resolve_entities"),
     "title": "XML 解析（XXE 候选）"},
    {"id": "py-import", "lang": "python", "sev": "medium",
     "re": re.compile(r"\b__import__\s*\(|importlib\.import_module\s*\("),
     "title": "动态导入"},
    {"id": "py-weak", "lang": "python", "sev": "low",
     "re": re.compile(r"hashlib\.(?:md5|sha1)\s*\(|\brandom\.(?!SystemRandom)"),
     "title": "弱哈希/非安全随机"},
    {"id": "py-mark-safe", "lang": "python", "sev": "medium",
     "re": re.compile(r"\bmark_safe\s*\(|\|\s*safe\b"), "title": "模板安全标记（XSS 候选）"},
]

SQL_RE = re.compile(
    r"(?i)\b(?:select\s+.+?\s+from|insert\s+into|update\s+\w+\s+set|"
    r"delete\s+from|union\s+select|where\s+.+?=)")
CONCAT_RE = {
    "php": re.compile(r"(?:\.\s*\$|\$[A-Za-z_]\w*\s*\.|\"[^\"\r\n]*\$[A-Za-z_]\w*)"),
    "java": re.compile(r"\+\s*(?:\w+|\")\s*\+|String\.format|\.concat\s*\("),
    "python": re.compile(r"f[\"'].*\{|\.format\s*\(|%\s*\(|%\s*\w+"),
}


def _language(path):
    _, ext = os.path.splitext(path.lower())
    return LANG_EXTS.get(ext, "")


def _context(lines, idx):
    for j in range(idx, max(-1, idx - 80), -1):
        line = lines[j]
        m = re.search(r"\b(?:class|interface|function|def|public|private|protected|"
                      r"static)\b[^\r\n;{}]{0,160}", line)
        if m and ("(" in line or "class " in line or "def " in line or
                  "function " in line):
            return line.strip()[:180]
    return ""


def _source_label(line, lang):
    m = SOURCE_RE[lang].search(line)
    if not m:
        return ""
    return m.group(0).strip()


def _tainted_vars(line, lang, known):
    """返回该行命中的已知污点变量。"""
    hits = []
    for var, info in known.items():
        pattern = re.escape(var) if var.startswith("$") else r"\b%s\b" % re.escape(var)
        if re.search(pattern, line):
            hits.append(info)
    return hits


def _learn_taint(line, lang, known):
    m = TAINT_ASSIGN[lang].search(line)
    if not m:
        return
    groups = m.groups()
    if lang == "php":
        var, expr = groups[0], groups[1]
    elif lang == "java":
        var, expr = groups[0], groups[1]
    else:
        var, expr = groups[1], groups[2]
    if SOURCE_RE[lang].search(expr):
        known[var] = {"var": var, "source": _source_label(expr, lang),
                      "snippet": line.strip()[:240]}
        return
    propagated = _tainted_vars(expr, lang, known)
    if propagated:
        known[var] = {
            "var": var,
            "source": "；".join(x["source"] for x in propagated[:3]),
            "snippet": line.strip()[:240],
        }


def _audit_file(path, lang, result, limit_per_file=250):
    try:
        text = util.read_text(path, 4 * 1024 * 1024)
    except Exception as exc:
        result["notes"].append("读取失败 %s：%s" % (path, exc))
        return 0
    if not text or "\x00" in text[:2048]:
        return 0
    util.flag_scan(text, "源码 %s" % os.path.basename(path), result)
    lines = text.splitlines()
    known = {}
    hits = 0
    seen = set()
    for idx, line in enumerate(lines):
        if len(line) > 2000:
            line = line[:2000]
        _learn_taint(line, lang, known)
        taints = _tainted_vars(line, lang, known)
        direct = _source_label(line, lang)
        if direct:
            taints.append({"var": "", "source": direct, "snippet": line.strip()[:240]})
        for rule in RULES:
            if rule["lang"] != lang:
                continue
            m = rule["re"].search(line)
            if not m:
                continue
            key = (rule["id"], idx + 1)
            if key in seen:
                continue
            seen.add(key)
            tainted = bool(taints)
            level = "warn" if (tainted and rule["sev"] in ("high", "medium")) else "info"
            title = ("可控输入进入危险汇聚点：" if tainted else "危险调用：") + rule["title"]
            detail = ["%s:%d" % (path, idx + 1), line.strip()[:300]]
            if tainted:
                chain = []
                for item in taints[:3]:
                    if item["var"]:
                        chain.append("%s 来自 %s" % (item["var"], item["source"]))
                    else:
                        chain.append("当前行直接读取 %s" % item["source"])
                detail.append("污点链：" + "；".join(chain))
            else:
                detail.append("未在同文件发现直接可控输入，需人工确认调用参数")
            ctx = _context(lines, idx)
            if ctx:
                detail.append("上下文：" + ctx)
            util.add(result, level, title, "\n".join(detail), {
                "rule": rule["id"], "severity": rule["sev"], "language": lang,
                "file": path, "line": idx + 1, "snippet": line.strip()[:500],
                "tainted": tainted,
                "sources": [t["source"] for t in taints][:5],
                "context": ctx,
            })
            hits += 1
            if hits >= limit_per_file:
                result["notes"].append("%s 命中达到上限 %d，已截断" % (
                    os.path.basename(path), limit_per_file))
                return hits
    # SQL 拼接（与具体查询函数解耦）
    for idx, line in enumerate(lines):
        if not SQL_RE.search(line):
            continue
        if not CONCAT_RE[lang].search(line):
            continue
        taints = _tainted_vars(line, lang, known)
        direct = _source_label(line, lang)
        if not direct and not taints:
            continue
        key = ("sql-concat", idx + 1)
        if key in seen:
            continue
        seen.add(key)
        detail = ["%s:%d" % (path, idx + 1), line.strip()[:300]]
        if direct:
            detail.append("当前行直接拼接 %s" % direct)
        for item in taints[:3]:
            if item["var"]:
                detail.append("%s 来自 %s" % (item["var"], item["source"]))
        util.add(result, "warn", "SQL 语句拼接可控输入", "\n".join(detail), {
            "rule": "sql-concat", "severity": "high", "language": lang,
            "file": path, "line": idx + 1, "snippet": line.strip()[:500],
            "tainted": True,
            "sources": ([direct] if direct else []) + [t["source"] for t in taints],
        })
        hits += 1
    return hits


def _render(result):
    data = result["data"]
    lines = ["# 代码审计报告", ""]
    lines.append("- 目标：`%s`" % data.get("target", ""))
    lines.append("- 文件：%s（PHP %s / Java %s / Python %s），行数：%s" % (
        data.get("files", 0), data.get("php_files", 0), data.get("java_files", 0),
        data.get("python_files", 0), data.get("lines", 0)))
    by_sev = data.get("by_severity") or {}
    lines.append("- 命中：%s（high=%s medium=%s low/info=%s）" % (
        data.get("hits", 0), by_sev.get("high", 0), by_sev.get("medium", 0),
        by_sev.get("low", 0)))
    lines.append("")
    lines.append("## 可疑点")
    warn = [f for f in result["findings"] if f["level"] == "warn"]
    info = [f for f in result["findings"] if f["level"] == "info"]
    for item in (warn + info)[:200]:
        lines.append("- [%s] %s" % (item["level"], item["title"]))
        for line in item["detail"].splitlines()[:4]:
            lines.append("  - %s" % line)
    lines.append("")
    lines.append("## 备注")
    lines.append("- 规则为启发式行匹配 + 同文件简单污点传播，存在误报/漏报，需人工复核。")
    for note in result["notes"]:
        lines.append("- %s" % note)
    return "\n".join(lines)


def analyze(target: str, outdir: str = "", max_files: int = 5000,
            log=None) -> dict:
    log = log or (lambda m: None)
    outdir = outdir or util.case_dir("codeaudit", target)
    result = util.make_result("codeaudit", outdir)
    result["data"]["target"] = os.path.abspath(target)
    if not os.path.exists(target):
        result["ok"] = False
        util.add(result, "warn", "目标不存在", target)
        return util.finish(result, _render(result))
    files = []
    if os.path.isfile(target):
        lang = _language(target)
        if not lang:
            result["ok"] = False
            util.add(result, "warn", "不支持的文件类型",
                     "仅支持 PHP/Java/Python 源码")
            return util.finish(result, _render(result))
        files = [(target, lang)]
    else:
        for path in util.iter_artifacts(target, exts=tuple(LANG_EXTS),
                                        max_files=max_files):
            parts = set(os.path.normpath(path).lower().split(os.sep))
            if parts & {"node_modules", ".git", "vendor", "dist", "build",
                        "__pycache__", ".venv", "venv"}:
                continue
            lang = _language(path)
            if lang:
                files.append((path, lang))
    if not files:
        result["ok"] = False
        util.add(result, "warn", "未找到 PHP/Java/Python 源码", target)
        return util.finish(result, _render(result))

    stats = {"php": 0, "java": 0, "python": 0}
    total_lines = 0
    total_hits = 0
    for idx, (path, lang) in enumerate(files):
        stats[lang] += 1
        try:
            total_lines += util.read_text(path, 4 * 1024 * 1024).count("\n") + 1
        except Exception:
            pass
        log("[codeaudit] %d/%d %s" % (idx + 1, len(files), os.path.basename(path)))
        total_hits += _audit_file(path, lang, result)
    result["data"].update({
        "files": len(files), "php_files": stats["php"],
        "java_files": stats["java"], "python_files": stats["python"],
        "lines": total_lines, "hits": total_hits,
        "by_severity": {
            sev: len([f for f in result["findings"] if f["level"] == "warn" and
                      f["data"].get("severity") == sev])
            for sev in ("high", "medium", "low")},
        "by_rule": {},
    })
    for item in result["findings"]:
        rule = item["data"].get("rule")
        if rule:
            result["data"]["by_rule"][rule] = result["data"]["by_rule"].get(rule, 0) + 1
    by_rule = sorted(result["data"]["by_rule"].items(), key=lambda x: -x[1])
    if by_rule:
        util.add(result, "info", "规则命中 Top",
                 "\n".join("%s=%s" % (k, v) for k, v in by_rule[:20]))
    result["summary"] = "源码 %s 个，命中 %s 处（high=%s medium=%s）" % (
        len(files), total_hits, result["data"]["by_severity"]["high"],
        result["data"]["by_severity"]["medium"])
    result["notes"].append("仅扫描本地源码，不执行、不联网；危险函数是否为漏洞取决于参数是否可控。")
    return util.finish(result, _render(result))


def enhance(path, report, outdir):
    try:
        result = analyze(path, os.path.join(outdir, "codeaudit"))
    except Exception as exc:
        report.add("info", "代码审计跳过", str(exc)[:200])
        return None
    for item in result.get("findings") or []:
        report.add(item["level"], item["title"], item["detail"])
    for path_out in result.get("artifacts") or []:
        report.extracted.append(path_out)
    return result
