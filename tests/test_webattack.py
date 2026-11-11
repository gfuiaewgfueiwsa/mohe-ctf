# -*- coding: utf-8 -*-
"""webattack 端到端测试：拉起本机靶站，跑两轮战役，逐项核对检测结果。

只打本机 127.0.0.1 靶站，不涉及任何外部目标。
两轮：
  1. 完整模式（stop_on_flag=False）——验证全部漏洞类型与 8 种上传形态都被覆盖；
  2. 快速模式（stop_on_flag=True）——验证拿到 flag 后提前收手，请求数显著下降。
"""
import json
import os
import re
import subprocess
import sys
import time

SRC = r"D:\工具合集软件\魔盒-CTF-v4.1.0-源码"
sys.path.insert(0, SRC)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from ctfbox import webattack  # noqa: E402
from ctfbox.autopilot import consent as _consent  # noqa: E402

# 本测试只打 127.0.0.1 自建靶站：显式授予「本次会话」声明，scope 校验仍然生效。
_consent.grant_session(_consent.FEATURE_WEB_EXPLOIT, "http://127.0.0.1:18081/")

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


def clear_log():
    """请求日志由靶站追加写入，每轮先清空，避免上一轮残留影响 multipart 计数等断言。"""
    with open(LOG, "w", encoding="utf-8"):
        pass


def run_campaign(stop_on_flag):
    clear_log()
    t0 = time.time()
    result = webattack.campaign(URL, log=lambda m: print("   " + str(m)),
                                max_requests=380, max_seconds=300,
                                stop_on_flag=stop_on_flag)
    return result, time.time() - t0


def read_log():
    with open(LOG, encoding="utf-8") as fp:
        return fp.read()


def main():
    proc = subprocess.Popen([sys.executable, TARGET, str(PORT), LOG],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        if not wait_server(proc):
            print("靶站未能启动")
            return 2

        # ---------- 第一轮：完整模式（不做 flag 短路） ----------
        print("\n===== 完整模式 stop_on_flag=False =====")
        full, full_elapsed = run_campaign(stop_on_flag=False)
        types = {f["type"] for f in full["findings"]}
        print("\n--- 完整模式结果 ---")
        print("请求 %d 次 / %.1fs / 停止：%s" % (full["requests"], full["elapsed"], full["stopped"] or "无"))
        print("发现类型:", sorted(types))
        print("FLAG:", [f["value"] for f in full["flags"]])

        check("完整模式：反射型 XSS 命中", "xss-reflected" in types)
        check("完整模式：SQL 报错命中", "sqli-error" in types)
        check("完整模式：SQL 布尔命中", "sqli-boolean" in types)
        check("完整模式：文件读取 LFI 命中", "lfi" in types or "lfi-source" in types)
        check("完整模式：模板注入 SSTI 命中", "ssti" in types)
        check("完整模式：命令注入命中", "cmdi" in types)
        check("完整模式：上传后可执行", "upload-exec" in types)
        check("完整模式：拿到 flag", any("deep_hunt" in f["value"] for f in full["flags"]),
              str([f["value"] for f in full["flags"]]))
        check("完整模式：命中总数 ≥ 7", len(full["findings"]) >= 7, "%d 条" % len(full["findings"]))
        check("完整模式：请求次数受预算约束", full["requests"] <= 380, "%d" % full["requests"])
        check("完整模式：耗时在预算内", full_elapsed < 330, "%.1fs" % full_elapsed)

        path = webattack.save_report(full)
        with open(path, encoding="utf-8") as fp:
            loaded = json.load(fp)
        check("完整模式：JSON 报告可读", loaded.get("url") == URL and "findings" in loaded)
        text = webattack.render(full)
        check("完整模式：文本报告含三段", all(k in text for k in ("== 发现 ==", "== FLAG ==", "== 下一步 ==")))
        check("完整模式：外部工具建议非空", bool(full.get("external")), "%d 条" % len(full.get("external") or []))

        log = read_log()
        check("完整模式：POST 表单进入测试", "POST /login" in log or "POST /upload" in log)
        check("完整模式：无破坏性 SQL 语句", not re.search(r"(?i)\b(drop|truncate|delete\s+from|update\s+\w+\s+set)\b", log))
        check("完整模式：上传内容为标记文件", "CTFBOXUPLOAD9137" in log and "eval(" not in log)
        up_kinds = [u.get("kind", "") for u in full.get("uploads") or []]
        check("完整模式：图片马已实际尝试",
              any(".png.php" in (u.get("filename") or "") for u in full.get("uploads") or [])
              or any("图片马" in k for k in up_kinds), str(up_kinds))
        multipart = log.count("multipart/form-data")
        check("完整模式：上传测试次数受控", multipart <= 12,
              "%d 次 multipart（8 种载荷形态 + 1 次取 flag 脚本 + 允许的断连重试）" % multipart)

        # ---------- 第二轮：快速模式（拿到 flag 就收手） ----------
        print("\n===== 快速模式 stop_on_flag=True =====")
        fast, fast_elapsed = run_campaign(stop_on_flag=True)
        print("\n--- 快速模式结果 ---")
        print("请求 %d 次 / %.1fs / 停止：%s" % (fast["requests"], fast["elapsed"], fast["stopped"] or "无"))
        print("发现类型:", sorted({f["type"] for f in fast["findings"]}))
        print("FLAG:", [f["value"] for f in fast["flags"]])

        check("快速模式：拿到 flag", any("deep_hunt" in f["value"] for f in fast["flags"]),
              str([f["value"] for f in fast["flags"]]))
        ratio = fast["requests"] / float(max(1, full["requests"]))
        check("快速模式：请求数显著少于完整模式", ratio <= 0.6,
              "%.0f%%（%d vs %d）" % (ratio * 100, fast["requests"], full["requests"]))
        check("快速模式：耗时显著少于完整模式", fast_elapsed <= full_elapsed * 0.6,
              "%.1fs vs %.1fs" % (fast_elapsed, full_elapsed))
        fast_log = read_log()
        check("快速模式：无破坏性 SQL 语句",
              not re.search(r"(?i)\b(drop|truncate|delete\s+from|update\s+\w+\s+set)\b", fast_log))
        check("快速模式：上传测试次数受控", fast_log.count("multipart/form-data") <= 12,
              "%d 次 multipart" % fast_log.count("multipart/form-data"))

        # ---------- 同源/协议边界（与模式无关） ----------
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
