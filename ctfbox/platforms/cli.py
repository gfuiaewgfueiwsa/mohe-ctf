# -*- coding: utf-8 -*-
"""平台闭环 CLI：登录态 → 题目 → 开实例 → 一键梭哈 → 提交。

v3.7.0 起不再要求 --ctf-only / --i-own-this-target / --consent：
进入软件时的《软件责任说明》已统一确认授权。

用法：
  --platform polarctf --cookie <文件|Cookie 字符串|浏览器导出 JSON>
  --platform polarctf --user <账号> --password <密码>
  --platform polarctf --list [--category WEB] [--all]
  --platform polarctf --show 570 [--download]
  --platform polarctf --boot 570
  --platform polarctf --solve 570 [--no-submit] [--deep] [--render]
  --platform polarctf --submit 570 --flag "flag{...}"
"""
import argparse
import json
import os
import re
import sys
import time

from ..common import WORKSPACE, is_placeholder_flag
from .ctfd import CTFdPlatform, PlatformError, POLARCTF_BASE

FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,20}\{[^}\r\n]{1,200}\}")
FLAG_BRACE_KV_RE = re.compile(r"(?i)flag\s*[=:]\s*\{\s*([0-9a-f]{8,64})\s*\}")


def _submit_candidate(value):
    """把 $flag={hex} 这类题面格式归一化为平台要求的 flag{hex}。"""
    value = (value or "").strip()
    mo = FLAG_BRACE_KV_RE.fullmatch(value)
    if mo:
        return "flag{%s}" % mo.group(1)
    return value


def _platform(args):
    base = POLARCTF_BASE
    if args.platform and args.platform not in ("polarctf", "polar", "ctfd"):
        base = args.platform
    cli = CTFdPlatform(base=base, log=lambda m: print(m, flush=True))
    cli.load()
    return cli


def _need_login(cli):
    me = cli.me()
    if not me:
        raise PlatformError("未登录或登录态已过期：先执行 --cookie <...> 或 --user/--password")
    return me


def cmd_cookie(args):
    cli = _platform(args)
    info = cli.import_cookies(args.cookie)
    print("[+] 登录态已保存：%s（用户 %s）" % (info["state"], info["user"]))
    print("    注意：该文件等价于账号凭据，请勿随交付包分发。")
    return 0


def cmd_login(args):
    if not args.user or not args.password:
        raise PlatformError("需要 --user 与 --password")
    cli = _platform(args)
    info = cli.login_password(args.user, args.password)
    print("[+] 登录成功：%s（%s）" % (info["user"], info["state"]))
    return 0


def cmd_list(args):
    cli = _platform(args)
    _need_login(cli)
    rows = cli.list_challenges(category=args.category or "",
                               unsolved_only=not args.all)
    print("ID\t分值\t通过\t分类\t题目")
    for item in sorted(rows, key=lambda r: (-int(r.get("value") or 0), r.get("id"))):
        print("%s\t%s\t%s\t%s\t%s" % (item.get("id"), item.get("value"),
                                      item.get("solves"), item.get("category"),
                                      item.get("name")))
    print("[*] 共 %d 题（%s）" % (len(rows), "全部" if args.all else "未解"))
    return 0


def cmd_show(args):
    cli = _platform(args)
    _need_login(cli)
    detail = cli.challenge(args.show)
    print("== %s | %s | %s 分 | 已解: %s" % (detail.get("id"), detail.get("name"),
                                             detail.get("value"),
                                             "是" if detail.get("solved_by_me") else "否"))
    print("分类:", detail.get("category"), "| 类型:", detail.get("type"))
    desc = re.sub(r"<[^>]+>", " ", detail.get("description") or "")
    print("描述:", re.sub(r"\s+", " ", desc).strip()[:1200])
    if detail.get("files"):
        print("附件:")
        for f in detail["files"]:
            print("  -", f)
    if args.download:
        dest = os.path.join(WORKSPACE, "platform", "files", str(args.show))
        saved = cli.download_files(detail, dest)
        for p in saved:
            print("[+] 已下载:", p)
    if detail.get("type") == "dynamic_docker":
        info = cli.instance(args.show)
        if info.get("user_access"):
            print("实例:", info["user_access"],
                  "| 剩余 %s 秒" % info.get("remaining_time"))
        else:
            print("实例: 未启动（用 --boot %s 开机）" % args.show)
    return 0


def cmd_boot(args):
    cli = _platform(args)
    _need_login(cli)
    info = cli.boot(args.boot)
    print("[+] 实例已就绪：%s" % info.get("user_access"))
    print("    剩余 %s 秒 | 内网域名 %s" % (info.get("remaining_time"),
                                          info.get("lan_domain") or "-"))
    return 0


def cmd_submit(args):
    cli = _platform(args)
    _need_login(cli)
    value = _submit_candidate(args.flag)
    if is_placeholder_flag(value):
        print("[submit] 拒绝提交模板占位 flag：%s（附件源码里的占位符不是答案）" % value)
        return 2
    res = cli.submit(args.submit, value)
    print("[submit] %s -> %s %s" % (args.submit, res["status"], res["message"]))
    return 0 if res["status"] in ("correct", "already_solved") else 1


def _candidate_flags(result):
    out = []
    for cand in result.get("candidates") or []:
        value = _submit_candidate(cand.get("value"))
        if FLAG_RE.fullmatch(value) and not is_placeholder_flag(value) and value not in out:
            out.append(value)
    return out


def cmd_solve(args):
    from ..autopilot.cli import run_auto

    cli = _platform(args)
    me = _need_login(cli)
    cid = int(args.solve)
    detail = cli.challenge(cid)
    print("[*] 题目 %s | %s | %s" % (cid, detail.get("name"), detail.get("category")))
    if detail.get("solved_by_me") and not args.force:
        print("[*] 该题已解，退出（--force 可重跑）")
        return 0

    targets = []
    if detail.get("type") != "dynamic_docker" and not args.url:
        files = cli.download_files(detail, os.path.join(WORKSPACE, "platform",
                                                        "files", str(cid)))
        print("[*] 非动态实例题；附件 %d 个" % len(files))
        if not files:
            print("[!] 该题没有附件，无法自动梭哈；请人工确认题型。")
            return 2
        # 多附件题（如「源码 + 密文」「两个镜像」）旧实现只分析第一个，
        # 若答案在第二个附件就永远解不出。这里逐个尝试，命中即停。
        targets = files[:3]
        if len(files) > 1:
            print("[*] 多附件：逐个尝试（最多 3 个，命中即停）")
    else:
        url = args.url
        if not url:
            info = cli.boot(cid)
            url = info.get("user_access")
            print("[+] 实例：%s（剩余 %s 秒）" % (url, info.get("remaining_time")))
        ready = cli.wait_ready(url, timeout=args.boot_wait)
        if not ready["ready"]:
            raise PlatformError("实例 URL 可达但服务未就绪（%s）：%s"
                                % (ready["probe"], url))
        print("[+] 服务已就绪：%s" % ready["probe"])
        targets = [url]

    hosts = list(args.allow_host or [])
    pbase = re.sub(r"^https?://", "", cli.base).split("/")[0]
    hosts.append(pbase)
    if "polarctf.com" in pbase:
        hosts.append("*.polarctf.com")
    desc = re.sub(r"<[^>]+>", " ", detail.get("description") or "")
    hints = [detail.get("name") or "", detail.get("category") or "",
             re.sub(r"\s+", " ", desc).strip()]
    result = {}
    target = targets[0]
    for idx, target in enumerate(targets, 1):
        is_web = str(target).startswith("http")
        if len(targets) > 1:
            print("[*] 附件 %d/%d：%s" % (idx, len(targets), target))
        cli.log("[*] 启动一键梭哈：%s" % target)
        result = run_auto(target, True, allow_private=args.allow_private, allow_hosts=hosts,
                          deep=args.deep, render=args.render, log=lambda m: print(m, flush=True),
                          headless=not args.headful, exploit=is_web,
                          consent_feature=args.consent, i_own=args.i_own,
                          hints=hints,
                          meta={"name": detail.get("name") or "",
                                "category": detail.get("category") or "",
                                "id": cid,
                                "description": re.sub(r"\s+", " ", desc).strip(),
                                "platform": pbase})
        if _candidate_flags(result):
            break
        if idx < len(targets):
            print("[*] 本附件未得强候选，继续下一个")
    if result.get("wp"):
        print("[*] WP：%s（格式 %s）" % (result.get("wp"),
                                        result.get("wp_format", "-")))
        if result.get("wp_copy"):
            print("[*] WP 归档：%s" % result.get("wp_copy"))
    flags = _candidate_flags(result)
    if not flags:
        print("[!] 未得到强候选 flag。工作区：%s" % result.get("workdir"))
        for step in (result.get("next_steps") or [])[:6]:
            print("    -", step)
        return 1
    print("[*] 候选 flag %d 个：%s" % (len(flags), " | ".join(flags)))
    if args.no_submit:
        print("[*] --no-submit：不提交")
        return 0

    lines = []
    ok = False
    for flag in flags:
        res = cli.submit(cid, flag)
        line = "%s -> %s %s" % (flag, res["status"], res["message"])
        print("[submit]", line)
        lines.append(line)
        if res["status"] in ("correct", "already_solved"):
            ok = True
            break
    out = os.path.join(WORKSPACE, "platform", "solve_%s_%s.txt"
                       % (cid, time.strftime("%Y%m%d_%H%M%S")))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fp:
        fp.write("题目: %s %s\n用户: %s\n目标: %s\nWP: %s\n\n%s\n"
                 % (cid, detail.get("name"), me.get("name"), target,
                    result.get("wp") or "-", "\n".join(lines)))
    print("[*] 提交记录:", out)
    return 0 if ok else 1


def build_parser():
    p = argparse.ArgumentParser(prog="platform", add_help=True)
    p.add_argument("--platform", nargs="?", const="polarctf", default="polarctf",
                   help="polarctf（默认）或平台根 URL")
    p.add_argument("--cookie", default="", help="Cookie 文件/JSON/Cookie 头")
    p.add_argument("--user", default="", help="平台账号")
    p.add_argument("--password", default="", help="平台密码")
    p.add_argument("--list", action="store_true", help="列出题目")
    p.add_argument("--category", default="", help="按分类过滤，如 WEB")
    p.add_argument("--all", action="store_true", help="包含已解")
    p.add_argument("--show", default="", help="查看题目详情")
    p.add_argument("--download", action="store_true", help="下载附件")
    p.add_argument("--boot", default="", help="开启动态实例")
    p.add_argument("--solve", default="", help="开实例并一键梭哈")
    p.add_argument("--submit", default="", help="提交指定题目的 flag")
    p.add_argument("--flag", default="", help="--submit 的 flag")
    p.add_argument("--url", default="", help="已有的实例 URL（跳过开机）")
    p.add_argument("--no-submit", action="store_true", help="只解题不提交")
    p.add_argument("--force", action="store_true", help="已解题目也重跑")
    p.add_argument("--allow-private", action="store_true")
    p.add_argument("--allow-host", action="append", default=[])
    p.add_argument("--deep", action="store_true")
    p.add_argument("--render", action="store_true")
    p.add_argument("--headful", action="store_true")
    p.add_argument("--boot-wait", type=int, default=120, help="开机/就绪等待秒数")
    p.add_argument("--consent", default="", choices=["", "web-exploit"],
                   help="兼容旧参数：不再强制")
    p.add_argument("--i-own-this-target", dest="i_own", action="store_true",
                   help="兼容旧参数：不再强制")
    return p


def main(argv):
    args = build_parser().parse_args(argv)
    try:
        action = bool(args.list or args.show or args.boot or args.submit or args.solve)
        # --cookie/--user 是凭据来源：与动作同时出现时先登录，再继续动作
        if args.cookie:
            code = cmd_cookie(args)
            if code or not action:
                return code
        if args.user or args.password:
            code = cmd_login(args)
            if code or not action:
                return code
        if args.list:
            return cmd_list(args)
        if args.show:
            return cmd_show(args)
        if args.boot:
            return cmd_boot(args)
        if args.submit:
            if not args.flag:
                raise PlatformError("--submit 需要同时提供 --flag")
            return cmd_submit(args)
        if args.solve:
            return cmd_solve(args)
        raise PlatformError("未指定动作：--cookie/--user/--list/--show/--boot/--solve/--submit")
    except PlatformError as exc:
        print("[!]", exc, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
