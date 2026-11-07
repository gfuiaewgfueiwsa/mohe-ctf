# -*- coding: utf-8 -*-
"""赛事专项页（v3.7.0）：离线取证与审计，加固清单只生成不执行。"""
import os
import queue
import threading
import traceback
import customtkinter as ctk
from tkinter import filedialog, messagebox

from . import ui_theme as theme

OPS = [
    ("内存镜像分析", "仅本地镜像", "memory"),
    ("流量深度分析", "会话重组 / HTTP 对象 / DNS 隧道", "traffic"),
    ("APK 深度分析", "清单 / 证书 / DEX / 硬编码密钥", "mobile"),
    ("源码审计", "PHP / Java / Python 污点链", "codeaudit"),
    ("系统加固基线", "Windows / Linux 只读检查", "baseline"),
    ("日志关键事件", "EVTX / auth.log 时间线", "logtime"),
    ("WAF / NGFW 清单", "仅生成用例，不发送", "defense"),
    ("加固前后对比", "选择两次 result.json", "compare"),
]


class CompetitionFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._q = queue.Queue()
        self._busy = False
        self._closed = False
        self._last_out = ""
        self._build()
        self.after(120, self._poll)
        threading.Thread(target=self._probe_tools, daemon=True).start()

    def _build(self):
        head = theme.card(self)
        head.pack(fill="x", padx=8, pady=(10, 6))
        theme.section(head, "赛事专项", "离线分析 · 只读 · 不联网", padx=14, pady=(12, 6))
        theme.notice(head, "全部功能只读取本地磁盘/镜像并在任务工作区生成报告；加固脚本与 WAF 用例仅生成、"
                          "需人工在授权环境执行。不提供免杀、持久化、公网扫描。",
                     "warn", wrap=980, padx=14, pady=(0, 6))
        self.tool_status = theme.hint(head, "正在检测 Volatility / jadx / apktool ...",
                                      wrap=980, padx=14, pady=(0, 12))
        self.tool_status.configure(text_color=theme.TEXT_MUTE)

        tgt = theme.card(self)
        tgt.pack(fill="x", padx=8, pady=(0, 6))
        theme.section(tgt, "目标", "文件或目录；日志/防守项可留空", padx=14, pady=(10, 6))
        bar = theme.panel(tgt)
        bar.pack(fill="x", padx=14, pady=(0, 8))
        theme.button(bar, "选择文件", "subtle", width=90,
                     command=self._pick_file).pack(side="left")
        theme.button(bar, "选择目录", "subtle", width=90,
                     command=self._pick_dir).pack(side="left", padx=(6, 0))
        self.target = theme.entry(bar, placeholder_text="目标路径（内存镜像 / pcap / apk / 源码目录 / 日志 / rootfs）")
        self.target.pack(side="left", fill="x", expand=True, padx=8)
        theme.button(bar, "清空", "ghost", width=64,
                     command=lambda: self.target.delete(0, "end")).pack(side="left")

        opts = theme.panel(tgt)
        opts.pack(fill="x", padx=14, pady=(0, 12))
        theme.hint(opts, "平台", side="left", padx=(2, 4))
        self.opt_platform = theme.option_menu(opts, ["auto", "windows", "linux"], width=104)
        self.opt_platform.set("auto")
        self.opt_platform.pack(side="left", padx=(0, 12))
        theme.hint(opts, "APK 反编译", side="left", padx=(2, 4))
        self.opt_decompile = theme.option_menu(opts, ["auto", "off", "jadx"], width=96)
        self.opt_decompile.set("auto")
        self.opt_decompile.pack(side="left", padx=(0, 12))
        theme.hint(opts, "防守清单", side="left", padx=(2, 4))
        self.opt_profile = theme.option_menu(opts, ["both", "waf", "ngfw"], width=92)
        self.opt_profile.set("both")
        self.opt_profile.pack(side="left", padx=(0, 12))
        self.chk_dump = self._check(opts, "内存提取文件")
        self.chk_scripts = self._check(opts, "生成加固/回滚脚本", True)
        self.chk_live = self._check(opts, "在线收集本机 Windows 日志")

        grid_card = theme.card(self)
        grid_card.pack(fill="x", padx=8, pady=(0, 6))
        theme.section(grid_card, "分析任务", "结果写入 workspace/competition", padx=14, pady=(10, 6))
        grid = theme.scroll(grid_card, height=166)
        grid.pack(fill="x", padx=14, pady=(0, 12))
        for i, (title, desc, kind) in enumerate(OPS):
            cell = theme.card(grid)
            cell.grid(row=i // 4, column=i % 4, padx=4, pady=4, sticky="nsew")
            theme.button(cell, title, "subtle", height=32,
                         command=lambda k=kind: self._run(k)).pack(
                fill="x", padx=8, pady=(8, 2))
            theme.hint(cell, desc, wrap=170, padx=8, pady=(0, 8))
        for c in range(4):
            grid.grid_columnconfigure(c, weight=1)

        out = theme.card(self)
        out.pack(fill="both", expand=True, padx=8, pady=(0, 10))
        bar = theme.panel(out)
        bar.pack(fill="x", padx=12, pady=(8, 4))
        ctk.CTkLabel(bar, text="任务输出", font=theme.font(theme.FONT_BODY, "bold"),
                     text_color=theme.TEXT_DIM).pack(side="left")
        theme.button(bar, "打开输出目录", "ghost", width=112, height=26,
                     command=self._open_out).pack(side="right", padx=(6, 0))
        theme.button(bar, "复制", "ghost", width=64, height=26,
                     command=self._copy).pack(side="right", padx=(6, 0))
        theme.button(bar, "清空", "ghost", width=64, height=26,
                     command=lambda: self.out.delete("1.0", "end")).pack(side="right")
        self.out = theme.textbox(out, mono_font=True, size=12)
        self.out.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._log("[*] 就绪。选择目标后点击任务；所有分析均为离线只读。\n")

    def _check(self, master, text, checked=False):
        box = theme.checkbox(master, text)
        box.pack(side="left", padx=(0, 12))
        if checked:
            box.select()
        return box

    def _probe_tools(self):
        try:
            from .competition import util as comp_util
            vol = comp_util.find_volatility()
            jadx = comp_util.find_jadx()
            apktool = comp_util.find_apktool()
            seven = comp_util.find_7z()
            text = "工具状态：Volatility 3 %s ｜ jadx %s ｜ apktool %s ｜ 7z %s" % (
                "已就绪" if vol.get("available") else "未安装（内存题将只做明文扫描）",
                os.path.basename(jadx) if jadx else "未找到（APK 仅内置解析）",
                os.path.basename(apktool) if apktool else "未找到",
                os.path.basename(seven) if seven else "未找到")
        except Exception as exc:
            text = "工具状态检测失败：%s" % exc
        self._q.put(("tools", text))

    def _pick_file(self):
        path = filedialog.askopenfilename()
        if path:
            self._set_target(path)

    def _pick_dir(self):
        path = filedialog.askdirectory()
        if path:
            self._set_target(path)

    def _set_target(self, path):
        self.target.delete(0, "end")
        self.target.insert(0, path)

    def _target(self):
        return self.target.get().strip().strip('"')

    def _log(self, text):
        self.out.insert("end", text)
        self.out.see("end")

    def _run(self, kind):
        if self._busy:
            messagebox.showwarning("提示", "当前任务尚未结束，请稍候。")
            return
        target = self._target()
        live = bool(self.chk_live.get())
        need = kind not in ("defense", "compare")
        if kind == "logtime" and live:
            need = False
        if need and not target:
            messagebox.showwarning("提示", "请先选择目标文件或目录。")
            return
        if need and not os.path.exists(target):
            messagebox.showwarning("提示", "目标不存在：%s" % target)
            return
        before = after = ""
        if kind == "compare":
            before = filedialog.askopenfilename(
                title="选择加固前 baseline/result.json",
                filetypes=[("result.json", "result.json"), ("JSON", "*.json")])
            if not before:
                return
            after = filedialog.askopenfilename(
                title="选择加固后 baseline/result.json",
                filetypes=[("result.json", "result.json"), ("JSON", "*.json")])
            if not after:
                return
        self._busy = True
        self.out.delete("1.0", "end")
        self._log("[*] 开始：%s\n" % dict((k, t) for t, _d, k in OPS).get(kind, kind))
        opts = {
            "target": target,
            "platform": self.opt_platform.get(),
            "decompile": self.opt_decompile.get(),
            "profile": self.opt_profile.get(),
            "dump_files": bool(self.chk_dump.get()),
            "scripts": bool(self.chk_scripts.get()),
            "live": live,
            "before": before,
            "after": after,
        }

        def work():
            try:
                result = _dispatch(kind, opts, lambda m: self._q.put(("log", str(m)[:4000] + "\n")))
                self._q.put(("done", (kind, result)))
            except Exception:
                self._q.put(("error", (kind, traceback.format_exc())))
        threading.Thread(target=work, daemon=True).start()

    def _poll(self):
        if self._closed:
            return
        try:
            while True:
                kind, payload = self._q.get_nowait()
                if kind == "log":
                    self._log(payload)
                elif kind == "done":
                    self._render(*payload)
                elif kind == "error":
                    self._render_error(*payload)
                elif kind == "tools":
                    self.tool_status.configure(text=payload)
        except queue.Empty:
            pass
        except Exception:
            pass
        finally:
            if not self._closed:
                self.after(120, self._poll)

    def _render(self, kind, result):
        self._busy = False
        outdir = result.get("outdir") or ""
        self._last_out = outdir
        self._log("\n[+] %s\n" % (result.get("summary") or "任务完成"))
        if outdir:
            self._log("    输出目录: %s\n" % outdir)
        report = next((a for a in result.get("artifacts") or []
                       if str(a).lower().endswith("report.md")), "")
        if report:
            self._log("    报告: %s\n" % report)
        findings = result.get("findings") or []
        if findings:
            self._log("-" * 72 + "\n")
        for item in findings[:400]:
            icon = {"flag": "[!!!]", "ok": "[+]", "warn": "[!]",
                    "info": "[*]", "tool": "[TOOL]"}.get(item.get("level"), "[*]")
            self._log("%s %s\n" % (icon, item.get("title", "")))
            detail = str(item.get("detail") or "")
            if detail:
                lines = detail.splitlines()
                shown = "\n".join("    " + x[:300] for x in lines[:8])
                self._log(shown + ("\n    ...（截断）\n" if len(lines) > 8 else "\n"))
        if len(findings) > 400:
            self._log("[*] 其余 %d 条见报告。\n" % (len(findings) - 400))
        for note in (result.get("notes") or [])[:8]:
            self._log("[*] %s\n" % note)
        if not result.get("ok", True):
            self._log("[!] 任务存在未完成项，请查看报告与备注。\n")
        self._log("\n[*] 完成。可直接打开输出目录查看 report.md / result.json 与 artifacts。\n")

    def _render_error(self, kind, tb):
        self._busy = False
        self._log("\n[!] 任务失败：%s\n" % kind)
        self._log("\n".join(tb.splitlines()[-12:]) + "\n")

    def _open_out(self):
        path = self._last_out
        if not path or not os.path.isdir(path):
            messagebox.showinfo("提示", "尚无输出目录；请先完成一次任务。")
            return
        try:
            if os.name == "nt":
                os.startfile(path)
            else:
                import subprocess
                subprocess.Popen(["xdg-open", path])
        except Exception as exc:
            messagebox.showerror("打开失败", str(exc))

    def _copy(self):
        try:
            text = self.out.get("1.0", "end-1c")
        except Exception:
            return
        self.clipboard_clear()
        self.clipboard_append(text)


def _dispatch(kind, opts, log):
    from .competition import memory, traffic, mobile, codeaudit, baseline, logtime, defense
    target = opts["target"]
    if kind == "memory":
        return memory.analyze(target, os_type=opts["platform"],
                              dump_files=opts["dump_files"], log=log)
    if kind == "traffic":
        return traffic.analyze(target, log=log)
    if kind == "mobile":
        return mobile.analyze(target, decompile=opts["decompile"], log=log)
    if kind == "codeaudit":
        return codeaudit.analyze(target, log=log)
    if kind == "baseline":
        return baseline.analyze(target, platform=opts["platform"],
                                generate_scripts=opts["scripts"], log=log)
    if kind == "logtime":
        return logtime.analyze(target, platform=opts["platform"],
                               live=opts["live"], log=log)
    if kind == "defense":
        return defense.analyze(target, profile=opts["profile"], log=log)
    if kind == "compare":
        return defense.compare(opts["before"], opts["after"], log=log)
    raise ValueError("未知任务：%s" % kind)
