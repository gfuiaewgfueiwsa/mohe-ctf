# -*- coding: utf-8 -*-
"""一键梭哈 CLI：python -m ctfbox.autopilot.cli --auto <文件|URL>

v3.7.0 起逐工具授权闸门取消：进入软件时须先同意《软件责任说明》
（GUI 启动弹窗 / CLI 加 --accept-responsibility），之后所有工具直接可用。
--ctf-only / --consent / --i-own-this-target 保留为兼容参数，不再强制。
"""
import argparse
import json
import os
import sys

from . import VERSION
from .orchestrator import AutoPilot


def is_url(target: str) -> bool:
    return target.startswith(("http://", "https://"))


def apply_web_consent(target: str = "", consent_feature: str = "",
                      i_own: bool = False) -> bool:
    """兼容旧调用：授权由启动责任说明统一确认，这里恒放行。"""
    return True


def run_auto(target: str, authorized: bool, allow_private: bool = False,
             allow_hosts=None, deep: bool = False, render: bool = False,
             log=None, user_data: str = "", cdp: str = "",
             headless: bool = True, exploit: bool = False,
             consent_feature: str = "", i_own: bool = False,
             ysoserial: str = "", hints=None, meta=None) -> dict:
    if ysoserial:
        os.environ["YSOSERIAL"] = os.path.abspath(ysoserial)
    pilot = AutoPilot(allow_private=allow_private, allow_hosts=allow_hosts,
                      deep=deep, render=render, log=log, exploit=exploit,
                      user_data=user_data, cdp=cdp, headless=headless,
                      hints=hints, meta=meta)
    if is_url(target):
        return pilot.run_url(target)
    return pilot.run_file(os.path.abspath(target))


def _print_result(result: dict):
    print("\n========== %s 一键梭哈结果 ==========" % VERSION)
    print("工作区:", result.get("workdir"))
    print("结论:", "命中强候选 flag" if result.get("success") else "未得到高置信 flag")
    if "login_required" in result:
        print("SPA:", "是" if result.get("spa") else "否",
              "| 需要登录:", "是" if result.get("login_required") else "否")
    for cand in result.get("candidates", [])[:8]:
        print("  %-6s %-8.2f %s | %s" % ("FLAG" if cand["confidence"] >= 0.8 else "候选",
                                         cand["confidence"], cand["value"], cand["reason"]))
    if result.get("suspicious"):
        print("Web 可疑点:")
        for item in result["suspicious"][:10]:
            print("  [%s] %s -> %s" % (item.get("type"), item.get("url"), item.get("evidence")))
    exploit = result.get("exploit") or {}
    if exploit:
        print("Web 利用:")
        print("  请求 %s/%s | 审计 %s 条 | 发现 %s 项 | 样本 %s 个" % (
            exploit.get("requests"), exploit.get("budget"),
            (exploit.get("audit") or {}).get("entries"),
            len(exploit.get("findings") or []),
            len(exploit.get("artifacts") or [])))
        for f in (exploit.get("findings") or [])[:10]:
            print("  [%s] %s | %s" % (f.get("type"), f.get("url"), f.get("evidence")))
    print("下一步:")
    for step in (result.get("next_steps") or [])[:8]:
        print("  -", step)
    print("报告:", os.path.join(result.get("workdir", ""), "report.md"))
    if result.get("wp"):
        print("WP:", result.get("wp"), "| 格式:", result.get("wp_format", "-"))
        if result.get("wp_copy"):
            print("WP 归档:", result.get("wp_copy"))


def main(argv=None):
    parser = argparse.ArgumentParser(description="魔盒-ctf %s 一键梭哈" % VERSION)
    parser.add_argument("--auto", "--v3", dest="target", required=True,
                        help="文件路径或 URL")
    parser.add_argument("--ctf-only", action="store_true",
                        help="兼容旧参数：已不再强制（授权由启动责任说明确认）")
    parser.add_argument("--allow-private", action="store_true", help="允许内网私网地址")
    parser.add_argument("--allow-host", action="append", default=[],
                        help="域名/主机白名单，可重复；支持 '*.example.com' 通配")
    parser.add_argument("--deep", action="store_true", help="启用可用的深度分析（反编译等）")
    parser.add_argument("--render", action="store_true", help="Web 目标强制浏览器渲染快照")
    parser.add_argument("--user-data", default="", help="浏览器持久化用户目录（复用登录态）")
    parser.add_argument("--cdp", default="", help="附加已开远程调试浏览器，如 http://127.0.0.1:9222")
    parser.add_argument("--headful", action="store_true", help="浏览器有界面运行（首次登录用）")
    parser.add_argument("--exploit", action="store_true",
                        help="启用 Web 全量利用（授权由启动责任说明确认）")
    parser.add_argument("--consent", default="", choices=["", "web-exploit"],
                        help="兼容旧参数：不再强制")
    parser.add_argument("--i-own-this-target", dest="i_own", action="store_true",
                        help="兼容旧参数：不再强制")
    parser.add_argument("--ysoserial", default="", help="ysoserial-all.jar 路径（可选）")
    parser.add_argument("--hint", action="append", default=[],
                        help="题目名/描述等提示词（可重复）：用于过滤白名单绕过猜测")
    parser.add_argument("--json", action="store_true", help="输出完整 JSON")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    log = lambda m: print(m, flush=True)  # noqa: E731
    result = run_auto(args.target, True, args.allow_private, args.allow_host,
                      args.deep, args.render, log=log, user_data=args.user_data,
                      cdp=args.cdp, headless=not args.headful,
                      exploit=args.exploit, consent_feature=args.consent,
                      i_own=args.i_own, ysoserial=args.ysoserial,
                      hints=args.hint)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    else:
        _print_result(result)
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    raise SystemExit(main())
