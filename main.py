# -*- coding: utf-8 -*-
"""魔盒-CTF 启动入口（原 CTFToolbox）。
用法：
  双击/无参数          启动图形界面（启动时须勾选同意《软件责任说明》）
  魔盒-CTF.exe --cli <文件> [文件...]   命令行批量分析（报告写入 workspace/cli_report.txt）
  魔盒-CTF.exe --rac "题目描述" [附件...]  RAC 自动化流水线（识别→匹配脚本→填参→执行→提取 flag）
  魔盒-CTF.exe --webauto <URL>   Web 自动化解题（只读、同源、限速的取证链）
  魔盒-CTF.exe --webattack <URL> Web 深度全自动（页面分析+全 payload 矩阵+上传测试）
  魔盒-CTF.exe --auto <文件|URL> [--deep] [--render] [--ai]
                                      v3.7.0 一键梭哈（识别→反编译/密码试解/Web 全量利用→证据链→候选 flag）
  魔盒-CTF.exe --comp <memory|traffic|mobile|codeaudit|baseline|logtime|defense|compare> ...
                                      v3.7.0 赛事专项（离线取证/审计/加固基线，只生成不执行）
  魔盒-CTF.exe --platform polarctf --cookie <文件|Cookie>
  魔盒-CTF.exe --platform polarctf --list [--category WEB]
  魔盒-CTF.exe --platform polarctf --solve <题目ID>
                                      v3.7.0 平台闭环（登录态→开实例→一键梭哈→自动提交）

CLI 首次使用须加 --accept-responsibility（同意《软件责任说明》并记住本机）；
之后可直接运行。逐工具授权闸门与 --ctf-only 强制参数已取消。
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 最早期安装崩溃保护（必须在重型库 import 之前）
try:
    from ctfbox.crashguard import install as _install_crashguard
    _install_crashguard()
except Exception:
    pass


def _reconfig_utf8():
    """控制台/重定向统一 UTF-8：guard 报错也要可读，不能落在 GBK 默认上乱码。"""
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _bootstrap_console():
    """CLI 模式：切换代码页 + UTF-8 重配置。

    此前 8 个 CLI 分支各自复制同一段初始化代码（约 90 行），任何一处修改
    都要改 8 遍且容易漏；统一收敛到这里。
    """
    if sys.platform.startswith("win"):
        try:
            os.system("chcp 65001 >nul 2>nul")
        except Exception:
            pass
    _reconfig_utf8()


def run_cli(files):
    from ctfbox.dispatcher import Dispatcher
    from ctfbox.common import WORKSPACE

    lines = []
    d = Dispatcher(log_cb=lambda m: lines.append(m))
    for f in files:
        if not os.path.isfile(f):
            lines.append(f"[!] 文件不存在: {f}")
            continue
        lines.append(f"\n########## 分析: {f} ##########")
        try:
            rep = d.run(os.path.abspath(f))
        except Exception as e:
            import traceback
            lines.append(f"[!] 分析失败: {e}\n{traceback.format_exc()}")
            continue

        def walk(r, depth=0):
            indent = "    " * depth
            lines.append(f"{indent}== {r.path} [{r.ftype}]")
            for fnd in r.findings:
                icon = {"flag": "!!!", "ok": "+", "warn": "!", "info": "*"}.get(fnd.level, "*")
                lines.append(f"{indent} [{icon}] {fnd.title}")
                if fnd.detail:
                    for ln in str(fnd.detail).splitlines()[:40]:
                        lines.append(f"{indent}     {ln}")
            for c in r.children:
                walk(c, depth + 1)
        walk(rep)
        lines.append("")

    out = os.path.join(WORKSPACE, "cli_report.txt")
    os.makedirs(WORKSPACE, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))
    return out


def run_rac(args):
    """RAC 自动化流水线 CLI：--rac "描述" [附件...] 或 --rac -f 附件..."""
    from ctfbox.rac import RacPipeline
    from ctfbox.common import WORKSPACE

    rest = list(args)
    desc, atts = "", []
    if rest and rest[0] == "-f":
        atts = [a for a in rest[1:] if os.path.isfile(a)]
        missing = [a for a in rest[1:] if not os.path.isfile(a)]
    else:
        if rest and not os.path.isfile(rest[0]):
            desc = rest[0]
            atts = [a for a in rest[1:] if os.path.isfile(a)]
        else:
            atts = [a for a in rest if os.path.isfile(a)]
        missing = [a for a in rest if a != desc and not os.path.isfile(a)]
    if missing:
        print("[!] 以下附件不存在，已跳过:", "; ".join(missing[:8]))

    lines = []

    def log(m):
        try:
            print(m)
        except Exception:
            pass
        lines.append(str(m))

    pipe = RacPipeline(log_cb=log)
    res = pipe.run(desc, atts)

    out = os.path.join(WORKSPACE, "rac_cli_report.txt")
    os.makedirs(WORKSPACE, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines) + f"\n\nFLAG: {'; '.join(res.flags) or '(无)'}\n")
    return out


def run_pwn(args):
    """Pwn 自动化 CLI：--pwn <ELF> [--host H --port P --offset N --win 0xADDR]"""
    from ctfbox import pwnrun
    from ctfbox.common import Report, WORKSPACE

    path = next((a for a in args if os.path.isfile(a)), "")
    if not path:
        raise SystemExit("用法：魔盒-CTF.exe --pwn <ELF> [--host H --port P]")
    opts = {}
    for i, a in enumerate(args):
        if a.startswith("--") and i + 1 < len(args):
            opts[a[2:]] = args[i + 1]
    host = opts.get("host", "")
    port = opts.get("port", "")
    offset = int(opts.get("offset", "0") or 0)
    win = int(opts.get("win", "0") or 0, 0)

    lines = []

    def log(m):
        try:
            print(m)
        except Exception:
            pass
        lines.append(str(m))

    rep = Report(path)
    info = pwnrun.analyze(path, rep, log)
    lines.append(pwnrun.render_plan(info, path))
    result = None
    if host and port:
        result = pwnrun.exploit(path, host, port, offset=offset, win_addr=win, report=rep, log=log)
        lines.append("远端结果：%s" % (result.get("flags") or result.get("reason")))
    else:
        lines.append("未提供 --host/--port，只做了静态定位；要打通请补远端地址。")

    out = os.path.join(WORKSPACE, "pwn_report.txt")
    os.makedirs(WORKSPACE, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines) + "\n\nFLAG: %s\n"
                 % ("; ".join((result or {}).get("flags") or []) or "(无)"))
    return out


def run_webauto(url):
    """Web 自动化解题 CLI：--webauto <URL>"""
    from ctfbox import webauto
    from ctfbox.common import WORKSPACE

    lines = []

    def log(m):
        try:
            print(m)
        except Exception:
            pass
        lines.append(str(m))

    res = webauto.auto_solve(url, log=log)
    out = os.path.join(WORKSPACE, "webauto_report.txt")
    os.makedirs(WORKSPACE, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))
        fp.write("\n\n========== 汇总 ==========\n")
        fp.write(str(res.get("summary") or ""))
        fp.write("\n请求数：%s\n" % res.get("requests"))
        fp.write("FLAG: " + ("; ".join(res.get("flags") or []) or "(无)") + "\n")
        # 只在拿到 flag 时落盘 JSON 报告
        if res.get("flags"):
            fp.write("\nJSON 报告：" + webauto.save_report(res) + "\n")
    return out


def run_v3_auto(args):
    """一键梭哈 CLI：--auto <文件|URL> [选项]"""
    from ctfbox.autopilot.cli import run_auto, _print_result

    opts = {"allow_private": "--allow-private" in args,
            "deep": "--deep" in args, "render": "--render" in args,
            "headless": "--headful" not in args,
            "exploit": "--exploit" in args,
            "ai": True if "--ai" in args else None,
            "i_own": "--i-own-this-target" in args}
    hosts, target, user_data, cdp, consent_feature, ysoserial = [], "", "", "", "", ""
    hints = []
    skip = False
    value_flags = ("--allow-host", "--user-data", "--cdp", "--consent",
                   "--ysoserial", "--hint")
    for i, a in enumerate(args):
        if skip:
            skip = False
            continue
        if a in value_flags:
            val = args[i + 1] if i + 1 < len(args) else ""
            if a == "--allow-host":
                hosts.append(val)
            elif a == "--hint":
                hints.append(val)
            elif a == "--user-data":
                user_data = val
            elif a == "--cdp":
                cdp = val
            elif a == "--consent":
                consent_feature = val
            else:
                ysoserial = val
            skip = True
            continue
        if a in ("--allow-private", "--deep", "--render", "--headful", "--ctf-only",
                 "--json", "--exploit", "--ai", "--i-own-this-target"):
            continue
        if not target and not a.startswith("--"):
            target = a
    if not target:
        raise SystemExit("用法：魔盒-CTF.exe --auto <文件|URL>")

    def log(m):
        try:
            print(m, flush=True)
        except Exception:
            pass

    result = run_auto(target, True, opts["allow_private"], hosts,
                      opts["deep"], opts["render"], log=log,
                      user_data=user_data, cdp=cdp, headless=opts["headless"],
                      exploit=opts["exploit"], consent_feature=consent_feature,
                      i_own=opts["i_own"], ysoserial=ysoserial, hints=hints,
                      ai=opts["ai"])
    _print_result(result)
    return os.path.join(result.get("workdir", ""), "report.md")


def run_webattack(url):
    """深度 Web 全自动 CLI：--webattack <URL>"""
    from ctfbox import webattack
    from ctfbox.common import WORKSPACE

    lines = []

    def log(m):
        try:
            print(m)
        except Exception:
            pass
        lines.append(str(m))

    res = webattack.campaign(url, log=log)
    out = os.path.join(WORKSPACE, "webattack_report.txt")
    os.makedirs(WORKSPACE, exist_ok=True)
    text = webattack.render(res)
    with open(out, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))
        fp.write("\n\n========== 汇总 ==========\n")
        fp.write(text)
        # 只在拿到 flag 时落盘 JSON 报告
        if res.get("flags"):
            fp.write("\n\nJSON 报告：" + webattack.save_report(res) + "\n")
    return out


if __name__ == "__main__":
    # Windows(spawn) + PyInstaller 下 CRC 多进程批量碰撞必需，且必须尽早调用
    try:
        import multiprocessing
        multiprocessing.freeze_support()
    except Exception:
        pass

    # 控制台/重定向统一 UTF-8：guard 报错也要可读，不能落在 GBK 默认上乱码
    _reconfig_utf8()

    if len(sys.argv) > 1 and sys.argv[1] == "--analysis-worker":
        from ctfbox.analysis_worker import worker_main
        if len(sys.argv) != 5:
            raise SystemExit(2)
        raise SystemExit(worker_main(sys.argv[2], int(sys.argv[3]), sys.argv[4]))

    # 唯一责任闸门：CLI 首次使用须同意《软件责任说明》（GUI 走启动弹窗）
    CLI_MODES = {"--cli", "-c", "--rac", "--webauto", "--web", "--pwn",
                 "--auto", "--v3", "--webattack", "--deep", "--platform", "--comp"}
    if len(sys.argv) > 1 and sys.argv[1] in CLI_MODES:
        from ctfbox.responsibility import ensure_cli
        if not ensure_cli(sys.argv[1:]):
            raise SystemExit(2)
        sys.argv = [a for a in sys.argv if a != "--accept-responsibility"]

    if len(sys.argv) > 1 and sys.argv[1] in ("--cli", "-c"):
        # CLI 模式统一 UTF-8 输出，避免 PowerShell/cmd 默认 GBK 代码页下中文乱码
        # （报告文件本身始终为 UTF-8，这里只修控制台/重定向输出层）。
        _bootstrap_console()
        report_path = run_cli(sys.argv[2:])
        try:
            if sys.stdout:
                print("report written to:", report_path)
        except Exception:
            pass
    elif len(sys.argv) > 1 and sys.argv[1] == "--rac":
        _bootstrap_console()
        report_path = run_rac(sys.argv[2:])
        try:
            if sys.stdout:
                print("report written to:", report_path)
        except Exception:
            pass
    elif len(sys.argv) > 1 and sys.argv[1] in ("--webauto", "--web"):
        target = sys.argv[2] if len(sys.argv) > 2 else ""
        if not target:
            raise SystemExit('用法：魔盒-CTF.exe --webauto <URL>')
        _bootstrap_console()
        report_path = run_webauto(target)
        try:
            if sys.stdout:
                print("report written to:", report_path)
        except Exception:
            pass
    elif len(sys.argv) > 1 and sys.argv[1] == "--pwn":
        _bootstrap_console()
        report_path = run_pwn(sys.argv[2:])
        try:
            if sys.stdout:
                print("report written to:", report_path)
        except Exception:
            pass
    elif len(sys.argv) > 1 and sys.argv[1] in ("--auto", "--v3"):
        _bootstrap_console()
        try:
            report_path = run_v3_auto(sys.argv[2:])
        except Exception as exc:
            raise SystemExit(str(exc))
        try:
            if sys.stdout:
                print("report written to:", report_path)
        except Exception:
            pass
    elif len(sys.argv) > 1 and sys.argv[1] in ("--webattack", "--deep"):
        argv = sys.argv[2:]
        target = next((a for a in argv if not a.startswith("--")), "")
        if not target:
            raise SystemExit('用法：魔盒-CTF.exe --webattack <URL>')
        _bootstrap_console()
        try:
            report_path = run_webattack(target)
        except Exception as exc:
            raise SystemExit(str(exc))
        try:
            if sys.stdout:
                print("report written to:", report_path)
        except Exception:
            pass
    elif len(sys.argv) > 1 and sys.argv[1] == "--platform":
        _bootstrap_console()
        from ctfbox.platforms.cli import main as platform_main
        platform_args = ["--platform"] + [a for a in sys.argv[2:] if a != "--ctf-only"]
        raise SystemExit(platform_main(platform_args))
    elif len(sys.argv) > 1 and sys.argv[1] == "--comp":
        _bootstrap_console()
        from ctfbox.competition.cli import main as comp_main
        raise SystemExit(comp_main([a for a in sys.argv[2:] if a != "--ctf-only"]))
    else:
        try:
            from ctfbox.ui_consent import confirm_ctf_use
            if confirm_ctf_use():
                from ctfbox.ui_main import main
                main()
        except Exception:
            # 兜底：启动期异常写入 crash.log 并弹框，避免双击后窗口一闪而过
            import traceback, time
            try:
                from ctfbox.common import WORKSPACE
                os.makedirs(WORKSPACE, exist_ok=True)
                with open(os.path.join(WORKSPACE, "crash.log"), "a", encoding="utf-8") as fp:
                    fp.write(f"\n[STARTUP FAILURE {time.strftime('%Y-%m-%d %H:%M:%S')}]\n")
                    fp.write(traceback.format_exc())
                from tkinter import Tk, messagebox
                r = Tk(); r.withdraw()
                messagebox.showerror("魔盒-CTF 启动失败",
                                     "启动出错，详情见 workspace/crash.log\n\n" + traceback.format_exc()[-800:])
            except Exception:
                raise
