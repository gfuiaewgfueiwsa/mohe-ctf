# -*- coding: utf-8 -*-
"""webattack 端到端测试：拉起本机靶站，跑一次深度战役，逐项核对检测结果。

只打本机 127.0.0.1 靶站，不涉及任何外部目标。
"""
import json
import os
import re
import subprocess
import sys
import time

SRC = r"D:\工具合集软件\_源码_v2.4"
sys.path.insert(0, SRC)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from ctfbox import webattack  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(HERE, "ctf_deeptarget.py")
LOG = os.path.join(HERE, "deeptarget_requests.log")
PORT = 18081
URL = "http://127.0.0.1:%d/" % PORT

passed, failed, skipped = [], [], []


def check(name, cond, extra=""):
    if cond:
        passed.append(name)
        print("PASS  %-34s %s" % (name, extra))
    else:
        failed.append(name)
        print("FAIL  %-34s %s" % (name, extra))


def skip(name, why):
    skipped.append(name)
    print("SKIP  %-34s %s" % (name, why))


def wait_server(proc, timeout=6.0):
    import socket
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            raise RuntimeError("靶站进程已退出")
        try:
            with socket.create_connection(("127.0.0.1", PORT), 0.3):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def main():
    proc = subprocess.Popen([sys.executable, TARGET, str(PORT), LOG],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        if not wait_server(proc):
            print("靶站未能启动")
            return 2
        t0 = time.time()
        result = webattack.campaign(URL, log=lambda m: print("   " + str(m)),
                                    max_requests=380, max_seconds=300)
        elapsed = time.time() - t0
        types = {f["type"] for f in result["findings"]}
        print("\n--- 结果 ---")
        print("请求 %d 次 / %.1fs / 停止：%s" % (result["requests"], result["elapsed"], result["stopped"] or "无"))
        print("发现类型:", sorted(types))
        print("FLAG:", [f["value"] for f in result["flags"]])

        check("反射型 XSS 命中", "xss-reflected" in types)
        check("SQL 报错命中", "sqli-error" in types)
        check("SQL 布尔命中", "sqli-boolean" in types)
        check("文件读取 LFI 命中", "lfi" in types or "lfi-source" in types)
        check("模板注入 SSTI 命中", "ssti" in types)
        check("命令注入命中", "cmdi" in types)
        check("上传后可执行", "upload-exec" in types)
        check("拿到 flag", any("deep_hunt" in f["value"] for f in result["flags"]),
              str([f["value"] for f in result["flags"]]))
        check("命中总数 ≥ 7", len(result["findings"]) >= 7, "%d 条" % len(result["findings"]))
        check("请求次数受预算约束", result["requests"] <= 380, "%d" % result["requests"])
        check("耗时在预算内", elapsed < 330, "%.1fs" % elapsed)

        # 报告落盘与渲染
        path = webattack.save_report(result)
        with open(path, encoding="utf-8") as fp:
            loaded = json.load(fp)
        check("JSON 报告可读", loaded.get("url") == URL and "findings" in loaded)
        text = webattack.render(result)
        check("文本报告含三段", all(k in text for k in ("== 发现 ==", "== FLAG ==", "== 下一步 ==")))
        check("外部工具建议非空", bool(result.get("external")), "%d 条" % len(result.get("external") or []))

        # 请求日志审计：POST 表单被真正测到、没有破坏性 SQL、上传内容只有标记
        with open(LOG, encoding="utf-8") as fp:
            log = fp.read()
        check("POST 表单进入测试", "POST /login" in log or "POST /upload" in log)
        check("无破坏性 SQL 语句", not re.search(r"(?i)\b(drop|truncate|delete\s+from|update\s+\w+\s+set)\b", log))
        check("上传内容为标记文件", "CTFBOXUPLOAD9137" in log and "eval(" not in log)
        up_kinds = [u.get("kind", "") for u in result.get("uploads") or []]
        check("图片马已实际尝试", any(".png.php" in (u.get("filename") or "") for u in result.get("uploads") or [])
              or any("图片马" in k for k in up_kinds), str(up_kinds))
        multipart = log.count("multipart/form-data")
        # 三种上传形态 + 命中后可执行的取 flag 脚本，共 4 次；被拦截重试另算
        check("上传测试次数受控", multipart <= 12,
              "%d 次 multipart（8 种载荷形态 + 1 次取 flag 脚本 + 允许的断连重试）" % multipart)

        # 同源/协议边界
        try:
            webattack.campaign("file:///etc/passwd", log=lambda m: None, max_requests=5, max_seconds=10)
            check("file:// 被拒绝", False)
        except ValueError:
            check("file:// 被拒绝", True)
        try:
            webattack.campaign("http://user:pass@127.0.0.1:%d/" % PORT, log=lambda m: None,
                               max_requests=5, max_seconds=10)
            check("带凭据 URL 被拒绝", False)
        except ValueError:
            check("带凭据 URL 被拒绝", True)
    finally:
        proc.terminate()
        try:
            proc.wait(3)
        except Exception:
            proc.kill()

    print("\nPASS %d / FAIL %d / SKIP %d" % (len(passed), len(failed), len(skipped)))
    for name in failed:
        print("  失败项:", name)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
