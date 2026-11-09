# -*- coding: utf-8 -*-
"""赛事专项 CLI：python main.py --comp <子命令> ...

所有子命令均为离线分析或「只生成不执行」；不会发起攻击请求。
"""
import argparse
import json
import os
import sys

from . import util
from ..versioning import APP_VERSION


def _add_common(parser):
    parser.add_argument("--out", default="", help="输出目录（默认 workspace/competition 下自动命名）")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="魔盒-CTF --comp",
        description=APP_VERSION + " 赛事专项：内存/流量/移动/代码审计/基线/日志/攻防验证"
                    "（离线分析；加固与检测用例只生成不执行）")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("memory", help="内存镜像取证（Volatility 3 + 明文扫描）")
    p.add_argument("image", help="内存镜像路径")
    p.add_argument("--os", default="auto", choices=("auto", "windows", "linux"))
    p.add_argument("--dump-files", action="store_true", help="提取内存文件对象内容")
    p.add_argument("--max-scan-mb", type=int, default=1024)
    _add_common(p)

    p = sub.add_parser("traffic", help="流量深度分析（协议/HTTP/DNS/文件还原/TCP 重组）")
    p.add_argument("pcap", help="pcap/pcapng 文件")
    p.add_argument("--max-stream-mb", type=int, default=20)
    _add_common(p)

    p = sub.add_parser("mobile", help="APK 分析（清单/权限/证书/DEX 字符串/凭据）")
    p.add_argument("apk", help="APK 文件")
    p.add_argument("--decompile", default="auto", choices=("auto", "off", "jadx"))
    p.add_argument("--apktool", action="store_true")
    _add_common(p)

    p = sub.add_parser("codeaudit", help="PHP/Java/Python 源码危险点审计")
    p.add_argument("target", help="源码文件或目录")
    p.add_argument("--max-files", type=int, default=5000)
    _add_common(p)

    p = sub.add_parser("baseline", help="Windows/Linux 安全基线检查（只读）")
    p.add_argument("target", nargs="?", default="",
                   help="Linux rootfs 目录；Windows 留空检查本机")
    p.add_argument("--platform", default="auto", choices=("auto", "windows", "linux"))
    p.add_argument("--no-scripts", action="store_true", help="不生成加固/回滚脚本")
    _add_common(p)

    p = sub.add_parser("logtime", help="Windows EVTX / Linux auth.log/syslog 时间线")
    p.add_argument("target", nargs="?", default="",
                   help="日志文件或目录；Windows 留空在线收集本机事件")
    p.add_argument("--platform", default="auto", choices=("auto", "windows", "linux"))
    _add_common(p)

    p = sub.add_parser("defense", help="WAF/NGFW 检查清单与检测用例（只生成不发送）")
    p.add_argument("--profile", default="both", choices=("waf", "ngfw", "both"))
    p.add_argument("--vendor", default="", help="厂商/环境标识（可选）")
    p.add_argument("--target", default="", help="仅记录到报告，不发送请求")
    _add_common(p)

    p = sub.add_parser("compare", help="两次基线结果对比，生成加固前后报告")
    p.add_argument("--before", required=True, help="加固前 baseline result.json")
    p.add_argument("--after", required=True, help="加固后 baseline result.json")
    _add_common(p)

    return parser


def _log(message):
    try:
        print("[comp] %s" % message, file=sys.stderr)
    except Exception:
        pass


def _summary(result):
    return {
        "kind": result.get("kind", ""),
        "ok": bool(result.get("ok")),
        "summary": result.get("summary", ""),
        "outdir": result.get("outdir", ""),
        "artifacts": result.get("artifacts", [])[:30],
    }


def dispatch(args):
    cmd = args.command
    if cmd == "memory":
        from . import memory
        return memory.analyze(args.image, args.out, os_type=args.os,
                              dump_files=args.dump_files,
                              max_scan_mb=args.max_scan_mb, log=_log)
    if cmd == "traffic":
        from . import traffic
        return traffic.analyze(args.pcap, args.out, log=_log,
                               max_stream_mb=args.max_stream_mb)
    if cmd == "mobile":
        from . import mobile
        return mobile.analyze(args.apk, args.out, decompile=args.decompile,
                              apktool=args.apktool, log=_log)
    if cmd == "codeaudit":
        from . import codeaudit
        return codeaudit.analyze(args.target, args.out,
                                 max_files=args.max_files, log=_log)
    if cmd == "baseline":
        from . import baseline
        return baseline.analyze(args.target, args.out, platform=args.platform,
                                generate_scripts=not args.no_scripts, log=_log)
    if cmd == "logtime":
        from . import logtime
        return logtime.analyze(args.target, args.out, platform=args.platform,
                               log=_log)
    if cmd == "defense":
        from . import defense
        return defense.analyze(args.target, args.out, profile=args.profile,
                               vendor=args.vendor, log=_log)
    if cmd == "compare":
        from . import defense
        return defense.compare(args.before, args.after, args.out, log=_log)
    raise SystemExit("未知子命令：%s" % cmd)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    result = dispatch(args)
    payload = _summary(result)
    try:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    except Exception:
        print(json.dumps(payload, ensure_ascii=True, indent=2))
    return 0 if payload["ok"] else 1
