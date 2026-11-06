# -*- coding: utf-8 -*-
"""CTFToolbox 主界面。"""
import os
import sys
import queue
import threading
import subprocess
import time
import customtkinter as ctk
from tkinter import filedialog, messagebox

from .common import (WORKSPACE, TOOLS_DIR, REPORTS_DIR, EXPORTS_DIR, Report,
                     human_size, safe_name, external_python)
from .analysis_worker import run_analysis
from .process_runner import TaskCancelled, TaskTimeout
from . import toolsmgr
from . import webtools
from . import modules_text
from . import modules_archive
from .modules_text import auto_decode, hash_text, identify_hash, crack_hash
from .ui_ssh import SSHTab
from .ui_scripts import ScriptsLibraryFrame
from .ui_rac import RACTab

from .ui_consent import USAGE_TEXT
from . import ui_theme as theme

theme.init()

LEVEL_COLORS = dict(theme.TAGS)


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        theme.init(self)
        self.title(f"{theme.APP_NAME} {theme.APP_VERSION} · 万能 CTF 集合工具箱 | 仅限 CTF 比赛")
        # 自适应窗口：小屏 / 高 DPI 下不把按钮和状态栏挤出屏幕外
        screen_w, screen_h = self.winfo_screenwidth(), self.winfo_screenheight()
        win_w = max(1080, min(1360, screen_w - 40))
        win_h = max(660, min(900, screen_h - 90))
        self.geometry(f"{win_w}x{win_h}+{max(0, (screen_w - win_w) // 2)}"
                      f"+{max(0, (screen_h - win_h) // 2 - 24)}")
        self.minsize(min(1120, win_w), min(740, win_h))
        self.q = queue.Queue()
        self._dropped_logs = 0
        self.last_report = None
        self.current_file = None
        self.wordlist = None
        self._file_queue = []    # 批量分析待处理文件
        self._busy = False
        self._run_token = 0
        self._analysis_cancel = None
        self._analysis_thread = None
        self._closing = False
        self._drop_target = None
        self._center_detecting = False
        self._render_pending = False
        self._analysis_done = False
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._build_header()
        theme.divider(self, pady=(0, 0))
        self._build_statusbar()

        self.tabs = theme.tabview(self, command=self._on_tab)
        self.tabs.pack(fill="both", expand=True, padx=14, pady=(8, 6))
        self.t_ana = self.tabs.add("一键分析")
        self.t_code = self.tabs.add("编码/密码")
        self.t_cipher = self.tabs.add("密文加解密")
        self.t_util = self.tabs.add("实用小工具")
        self.t_tool = self.tabs.add("专项工具")
        self.t_rac = self.tabs.add("RAC 自动化")
        self.t_web = self.tabs.add("Web / Pwn")
        self.t_lib = self.tabs.add("📚 脚本库")
        self.t_ssh = self.tabs.add("SSH 终端")
        self.t_center = self.tabs.add("工具中心")
        self.t_media = self.tabs.add("媒体中心")
        self.t_nav = self.tabs.add("网页导航")
        self.t_help = self.tabs.add("使用说明")

        self._build_analysis()
        self._build_code()
        self._build_cipher()
        self._build_util()
        self._build_tools()
        self._build_web()
        self.scripts_lib = ScriptsLibraryFrame(self.t_lib)
        self.scripts_lib.pack(fill="both", expand=True)
        self.ssh = SSHTab(self.t_ssh)
        self.ssh.pack(fill="both", expand=True)
        self._build_center()
        self._lazy_tabs = {"媒体中心": self._build_media, "网页导航": self._build_webnav,
                           "RAC 自动化": self._build_rac}

        help_wrap = theme.card(self.t_help)
        help_wrap.pack(fill="both", expand=True, padx=8, pady=8)
        theme.section(help_wrap, "使用说明", "仅限 CTF 比赛授权题目", padx=14, pady=(12, 8))
        help_box = theme.textbox(help_wrap, size=13, wrap="word")
        help_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        help_box.insert("1.0", USAGE_TEXT)
        help_box.configure(state="disabled")

        if sys.platform == "win32":
            from .win_drop import DropTarget
            try:
                self._drop_target = DropTarget(self, lambda paths: self.q.put(("drop", paths)),
                                               on_error=lambda error: self.q.put(("drop_error", str(error))))
            except Exception as error:
                self.q.put(("drop_error", str(error)))
        self.after(50, self._drain)
        self._center_log("提示：拖入题目文件即可分析；使用前请阅读「使用说明」。\n")
        self._set_status("就绪 · 拖入题目文件即可开始分析", "ok", "● 就绪")

    # ===================================================================
    # 顶栏 / 状态栏
    # ===================================================================
    def _build_header(self):
        header = theme.panel(self)
        header.pack(fill="x", padx=14, pady=(12, 10))

        brand = theme.panel(header)
        brand.pack(side="left")
        ctk.CTkLabel(brand, text="CTF", width=52, height=36, corner_radius=10,
                     fg_color=theme.ACCENT, text_color="#ffffff",
                     font=theme.font(15, "bold")).pack(side="left", padx=(0, 12))
        text_wrap = theme.panel(brand)
        text_wrap.pack(side="left")
        title_row = theme.panel(text_wrap)
        title_row.pack(anchor="w")
        ctk.CTkLabel(title_row, text=theme.APP_NAME, font=theme.font(19, "bold"),
                     text_color=theme.TEXT, anchor="w").pack(side="left")
        ctk.CTkLabel(title_row, text=theme.APP_VERSION, font=theme.font(11),
                     text_color=theme.INFO, fg_color=theme.ACCENT_SOFT, corner_radius=8,
                     padx=7, height=19).pack(side="left", padx=(7, 0))
        ctk.CTkLabel(text_wrap, text=theme.APP_SUBTITLE, font=theme.font(11),
                     text_color=theme.TEXT_MUTE, anchor="w").pack(anchor="w", pady=(2, 0))

        right = theme.panel(header)
        right.pack(side="right")
        self.header_state = theme.chip(right, "● 就绪", "info")
        self.header_state.pack(side="right", padx=(8, 0))
        theme.chip(right, "仅限 CTF 授权赛事", "warn").pack(side="right", padx=(8, 0))
        theme.chip(right, "本地运行 · 结果不外传", "ok").pack(side="right")

    def _build_statusbar(self):
        bar = ctk.CTkFrame(self, fg_color=theme.BG_SURFACE, corner_radius=0, height=28)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        self.status_dot = ctk.CTkLabel(bar, text="●", font=theme.font(11),
                                       text_color=theme.SUCCESS, width=12)
        self.status_dot.pack(side="left", padx=(14, 2))
        self.status_label = ctk.CTkLabel(bar, text="就绪", font=theme.font(11),
                                         text_color=theme.TEXT_DIM, anchor="w")
        self.status_label.pack(side="left")
        ctk.CTkLabel(bar, text="CTFToolbox · workspace / reports / exports",
                     font=theme.mono(10), text_color=theme.TEXT_MUTE).pack(side="right", padx=14)

    def _set_status(self, text, kind="info", short=None):
        """底部状态栏 + 顶栏状态胶囊同步，避免两处提示不一致。"""
        colors = {"ok": theme.SUCCESS, "warn": theme.WARNING,
                  "danger": theme.DANGER, "info": theme.INFO}
        color = colors.get(kind, theme.INFO)
        try:
            self.status_label.configure(text=text, text_color=theme.TEXT_DIM)
            self.status_dot.configure(text_color=color)
            if short:
                self.header_state.configure(text=short, text_color=color)
        except Exception:
            pass

    # ===================================================================
    # 一键分析页
    # ===================================================================
    def _build_analysis(self):
        top = theme.card(self.t_ana)
        top.pack(fill="x", padx=8, pady=(10, 6))

        row_file = theme.panel(top)
        row_file.pack(fill="x", padx=14, pady=(12, 6))
        theme.button(row_file, "选择文件", "subtle", width=92, height=32,
                     command=self._pick_file).pack(side="left")
        self.file_entry = theme.entry(row_file, placeholder_text="题目文件路径（支持拖入任意后缀文件）")
        self.file_entry.pack(side="left", fill="x", expand=True, padx=(10, 12))
        ctk.CTkLabel(row_file, text="递归深度", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(0, 6))
        self.depth = theme.option_menu(row_file, values=["1", "2", "3", "4", "5", "6"], width=72)
        self.depth.set("4")
        self.depth.pack(side="left")

        row_act = theme.panel(top)
        row_act.pack(fill="x", padx=14, pady=(0, 12))
        ctk.CTkLabel(row_act, text="独立进程分析 · 单文件最长 300 秒 · 报告写入 reports、提取文件写入 workspace",
                     font=theme.font(theme.FONT_SMALL), text_color=theme.TEXT_MUTE,
                     anchor="w").pack(side="left")
        theme.button(row_act, "报告/导出目录", "ghost", width=112, height=32,
                     command=self._open_output_dirs).pack(side="right", padx=(6, 0))
        theme.button(row_act, "导出报告", "subtle", width=92, height=32,
                     command=self._export_report).pack(side="right", padx=(6, 0))
        self.stop_btn = theme.button(row_act, "停止", "ghost", width=72, height=32,
                                     state="disabled", command=self._stop_analysis)
        self.stop_btn.pack(side="right", padx=(6, 0))
        self.ana_btn = theme.button(row_act, "开始分析", "primary", width=104, height=32,
                                    command=self._start_analysis)
        self.ana_btn.pack(side="right")

        body = theme.panel(self.t_ana)
        body.pack(fill="both", expand=True, padx=8, pady=(0, 10))

        left = theme.card(body, width=340)
        left.pack(side="left", fill="y", padx=(0, 8))
        left.pack_propagate(False)
        theme.section(left, "文件信息", "拖入后自动识别", padx=12, pady=(12, 6))
        self.info_box = theme.textbox(left, mono_font=True, size=12, width=310, height=250)
        self.info_box.pack(fill="x", padx=12)

        theme.section(left, "外部工具打开", "需先在工具中心安装", padx=12, pady=(16, 6))
        tools_grid = theme.panel(left)
        tools_grid.pack(fill="x", padx=10)
        for i, (name, tname) in enumerate([("Ghidra 反编译", "ghidra"), ("x64dbg 动态调试", "x64dbg"),
                                           ("dnSpy(.NET)", "dnspy"), ("DIE 查壳", "die"),
                                           ("radare2", "radare2"), ("ExifTool 元数据", "exiftool")]):
            r, c = divmod(i, 2)
            theme.button(tools_grid, name, "ghost", height=30, font=theme.font(theme.FONT_SMALL),
                         command=lambda t=tname: self._open_in_tool(t)).grid(
                row=r, column=c, sticky="ew", padx=2, pady=3)
        for c in range(2):
            tools_grid.grid_columnconfigure(c, weight=1)
        theme.button(left, "打开工作区（提取文件目录）", "ghost", height=30,
                     command=lambda: os.startfile(WORKSPACE)).pack(fill="x", padx=10, pady=(10, 4))
        theme.hint(left, "分析结果会自动按类型归档；导出报告可在右侧「分析报告」页签查看。",
                   wrap=300, padx=10, pady=(0, 10))

        right = theme.tabview(body)
        right.pack(side="left", fill="both", expand=True)
        right.add("分析报告")
        right.add("提取的文件")
        right.add("实时日志")
        self.report_box = theme.textbox(right.tab("分析报告"), size=13)
        self.report_box.pack(fill="both", expand=True, padx=8, pady=8)
        self.extract_box = theme.textbox(right.tab("提取的文件"), mono_font=True, size=12)
        self.extract_box.pack(fill="both", expand=True, padx=8, pady=8)
        logbar = theme.toolbar(right.tab("实时日志"))
        logbar.pack(fill="x", padx=8, pady=(8, 4))
        theme.hint(logbar, "实时日志只保留最近 2000 行；完整结果见导出的报告。",
                   side="left", padx=(10, 4), pady=6)
        theme.button(logbar, "清空", "ghost", width=72, height=26,
                     command=lambda: self._clear_box(self.ana_log)).pack(side="right", padx=8, pady=4)
        self.ana_log = theme.textbox(right.tab("实时日志"), mono_font=True, size=12)
        self.ana_log.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.progress = theme.progress(self.t_ana, mode="indeterminate")
        self.progress.set(0)

    def _pick_file(self):
        p = filedialog.askopenfilename(title="选择题目文件（任意后缀）")
        if p:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, p)
            self.current_file = p

    def _decode_dropped(self, paths):
        out = []
        for path in paths or []:
            if isinstance(path, bytes):
                path = os.fsdecode(path)
            if path and os.path.isfile(path):
                out.append(os.path.abspath(path))
        return list(dict.fromkeys(out))

    def _on_drop(self, paths):
        if self._closing:
            return
        files = self._decode_dropped(paths)
        if not files:
            self._append_log(self.ana_log, "[!] 请拖入文件；文件夹和不存在的路径已忽略。\n")
            return
        if self._busy and self._analysis_cancel and self._analysis_cancel.is_set():
            self._append_log(self.ana_log, "[!] 正在停止分析，请待清理完成后再次拖入。\n")
            return
        self.tabs.set("一键分析")
        self._enqueue(files, clear=not self._busy)

    def _start_analysis(self):
        path = self.file_entry.get().strip().strip('"')
        if not path or not os.path.isfile(path):
            messagebox.showwarning("提示", "请先选择有效文件")
            return
        self._enqueue([path], clear=not self._busy)

    def _enqueue(self, files, clear=True):
        files = [f for f in files if os.path.isfile(f)]
        if not files:
            return
        if clear:
            self._file_queue = list(dict.fromkeys(files))
            self._batch_first = True
        else:
            for f in files:
                if f not in self._file_queue and f != self.current_file:
                    self._file_queue.append(f)
        if self._busy:
            self._append_log(self.ana_log, f"[*] 等待分析的文件：{len(self._file_queue)} 个。\n")
        elif self._file_queue:
            self._next_file()

    def _next_file(self):
        if self._busy or self._closing:
            return
        if not self._file_queue:
            self.ana_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.progress.stop()
            self.progress.pack_forget()
            self._busy = False
            self._set_status("就绪 · 拖入题目文件即可开始分析", "ok", "● 就绪")
            return
        path = self._file_queue.pop(0)
        self.current_file = path
        self.file_entry.delete(0, "end")
        self.file_entry.insert(0, path)
        if getattr(self, "_batch_first", True):
            self.report_box.configure(state="normal")
            self.report_box.delete("1.0", "end")
            self.extract_box.delete("1.0", "end")
            self._batch_first = False
        else:
            self.report_box.insert("end", "\n\n" + "=" * 90 + "\n")
        self._busy = True
        self._analysis_done = False
        self._render_pending = False
        self._set_status(f"分析中 · {os.path.basename(path)}（剩余队列 {len(self._file_queue)}）",
                         "warn", "● 分析中")
        self._run_token += 1
        token = self._run_token
        self.ana_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.progress.pack(fill="x", side="bottom")
        self.progress.start()
        depth = int(self.depth.get())

        cancel = self._analysis_cancel = threading.Event()

        def work():
            try:
                rep = run_analysis(path, depth, log=lambda m: self._queue_log("log", (str(m)[:8000], token)),
                                   cancel_event=cancel, timeout=300)
                if not cancel.is_set():
                    self.q.put(("report", (rep, token)))
            except TaskCancelled:
                self.q.put(("log", ("[*] 分析已停止，所属子进程已清理。", token)))
            except TaskTimeout:
                self.q.put(("log", ("[!] 单文件分析超过 300 秒，任务已结束。", token)))
            except Exception as error:
                self.q.put(("log", (f"[!] 分析失败（界面仍可使用）: {error}", token)))
            finally:
                self.q.put(("done", token))
        self._analysis_thread = threading.Thread(target=work, daemon=True)
        self._analysis_thread.start()

    def _stop_analysis(self):
        self._render_pending = False
        self._file_queue.clear()
        if self._analysis_cancel:
            self._analysis_cancel.set()
        self.stop_btn.configure(state="disabled")
        self._set_status("正在停止分析并清理子进程…", "warn", "● 停止中")
        self._append_log(self.ana_log, "[*] 正在停止分析并清理子进程，请稍候。\n")

    def _on_close(self):
        if self._closing:
            return
        self._closing = True
        self._file_queue.clear()
        if self._analysis_cancel:
            self._analysis_cancel.set()
        self.web_workflow.stop()
        if self._drop_target:
            self._drop_target.close()
        self.title(f"{theme.APP_NAME} · 正在停止后台任务")
        self._set_status("正在停止后台任务并退出…", "warn", "● 退出中")
        self._finish_close()

    def _finish_close(self):
        analysis_running = self._analysis_thread and self._analysis_thread.is_alive()
        if analysis_running or self.web_workflow.is_running() or getattr(self, "_exporting", False):
            self.after(50, self._finish_close)
            return
        self.destroy()

    def report_callback_exception(self, exception_type, error, tb):
        import traceback
        from .crashguard import _write
        _write("GUI CALLBACK", "".join(traceback.format_exception(exception_type, error, tb)))
        if not self._closing:
            self.q.put(("log", (f"[!] 界面操作失败：{error}；详情见 workspace/crash.log", self._run_token)))

    def _open_output_dirs(self):
        """打开软件目录下的报告/导出文件夹。"""
        try:
            os.makedirs(REPORTS_DIR, exist_ok=True)
            os.startfile(REPORTS_DIR)
        except Exception:
            pass

    def _export_report(self):
        if not self.last_report:
            self._append_log(self.ana_log, "[!] 还没有可导出的分析报告\n")
            return
        if getattr(self, "_exporting", False):
            return
        self._exporting = True
        self._set_status("正在导出报告（后台线程，界面可继续使用）…", "warn", "● 导出中")
        threading.Thread(target=self._write_report, args=(self.last_report, self._run_token), daemon=True).start()

    def _write_report(self, report, token):
        try:
            import time as _time
            import html as _html
            os.makedirs(REPORTS_DIR, exist_ok=True)
            stem = safe_name(os.path.splitext(os.path.basename(report.path))[0]) or "report"
            ts = _time.strftime("%Y%m%d_%H%M%S")
            tp = os.path.join(REPORTS_DIR, f"{stem}_{ts}.txt")
            hp = os.path.join(REPORTS_DIR, f"{stem}_{ts}.html")

            lines = []

            def walk_txt(r, d=0):
                lines.append("    " * d + f"[{r.ftype}] {r.path}")
                for fnd in r.findings:
                    lines.append("    " * d + f"  ({fnd.level}) {fnd.title}")
                    if fnd.detail:
                        for ln in str(fnd.detail).splitlines():
                            lines.append("    " * d + f"      {ln}")
                for c in r.children:
                    walk_txt(c, d + 1)
            walk_txt(report)
            with open(tp, "w", encoding="utf-8") as f:
                f.write(f"{theme.APP_NAME} {theme.APP_VERSION} 分析报告\n" + "=" * 70 + "\n" + "\n".join(lines))

            parts = ["<html><head><meta charset='utf-8'><title>CTFToolbox 报告</title>",
                     f"<style>body{{font-family:'Microsoft YaHei UI',sans-serif;"
                     f"background:{theme.BG_WINDOW};color:{theme.TEXT};margin:24px;line-height:1.7}}"
                     f".flag{{color:{theme.TAGS['flag']};font-weight:bold}}"
                     f".ok{{color:{theme.TAGS['ok']}}}.warn{{color:{theme.TAGS['warn']}}}"
                     f".info{{color:{theme.TAGS['info']}}}"
                     f".title{{color:{theme.TAGS['title']};font-weight:bold;font-size:15px;margin-top:18px}}"
                     f".detail{{margin-left:20px;white-space:pre-wrap;"
                     f"font-family:Consolas,monospace;color:{theme.TEXT_DIM}}}</style></head><body>",
                     f"<h2>{theme.APP_NAME} {theme.APP_VERSION} 分析报告</h2>"]

            def walk_html(r, d=0):
                parts.append(f"<div class='title'>{'&nbsp;'*d*4}├ {_html.escape(os.path.basename(r.path))} "
                             f"[{_html.escape(r.ftype)}]</div>")
                for fnd in r.findings:
                    parts.append(f"<div class='{fnd.level}'>● {_html.escape(fnd.title)}</div>")
                    if fnd.detail:
                        parts.append(f"<div class='detail {fnd.level}_d'>{_html.escape(str(fnd.detail))}</div>")
                for c in r.children:
                    walk_html(c, d + 1)
            walk_html(report)
            parts.append("</body></html>")
            with open(hp, "w", encoding="utf-8") as f:
                f.write("\n".join(parts))
            self.q.put(("log", (f"[+] 报告已导出：\n    {hp}\n    {tp}", token)))
            self.q.put(("status", ("报告已导出 · reports 目录", "ok")))
        except Exception as error:
            self.q.put(("log", (f"[!] 报告导出失败: {error}", token)))
            self.q.put(("status", (f"报告导出失败：{error}", "danger")))
        finally:
            self._exporting = False

    def _render_report(self, rep: Report):
        self.info_box.delete("1.0", "end")
        self.info_box.insert("end", f"文件：{os.path.basename(rep.path)}\n"
                                   f"类型：{rep.ftype}\n"
                                   f"大类：{rep.category}\n"
                                   f"路径：{rep.path}\n")
        for finding in rep.findings:
            if finding.title == "文件指纹":
                self.info_box.insert("end", "\n" + str(finding.detail)[:2000])
                break

        def chunks(report, depth=0):
            indent = "    " * depth
            yield f"{indent}┌─ {os.path.basename(report.path)} [{report.ftype}]\n", "title"
            for finding in report.findings:
                yield f"{indent}│  {finding.title[:1000]}\n", finding.level
                detail = str(finding.detail)
                if detail:
                    yield detail[:6000] + ("\n[内容较长，完整内容见导出报告]" if len(detail) > 6000 else "") + "\n\n", finding.level + "_d"
            for child in report.children:
                yield from chunks(child, depth + 1)

        self._report_chunks = iter(chunks(rep))
        self._render_pending = True
        self._render_count = 0
        self._render_chars = 0

    def _render_report_chunk(self):
        deadline = time.monotonic() + 0.008
        for _ in range(30):
            if time.monotonic() >= deadline:
                break
            try:
                text, tag = next(self._report_chunks)
            except StopIteration:
                self._render_pending = False
                break
            self.report_box.insert("end", text, tag)
            self._render_count += 1
            self._render_chars += len(text)
            if self._render_count >= 3000 or self._render_chars >= 500000:
                self.report_box.insert("end", "\n[界面预览已限量；请导出完整报告。]\n", "warn")
                self._render_pending = False
                break

    def _open_in_tool(self, tname):
        path = self.file_entry.get().strip().strip('"')
        if not path:
            messagebox.showinfo("提示", "请先选择文件")
            return
        ok, msg = toolsmgr.launch(tname, filepath=path)
        if not ok:
            if "未安装" in msg:
                messagebox.showinfo("提示", f"{tname} 未安装，请到「工具中心」下载/安装")
                self.tabs.set("工具中心")
            else:
                messagebox.showerror("错误", msg)

    # ===================================================================
    # 编码/密码页
    # ===================================================================
    def _build_code(self):
        wrap = theme.panel(self.t_code)
        wrap.pack(fill="both", expand=True, padx=8, pady=8)

        libbar = theme.toolbar(wrap)
        libbar.pack(fill="x", pady=(0, 8))
        theme.hint(libbar, "需要可复制的完整解题脚本？右侧脚本库按方向收录，可查看、复制或另存。",
                   side="left", padx=(12, 4), pady=8)
        theme.button(libbar, "📚 Crypto / 编码脚本库", "ghost", width=184,
                     command=lambda: self._goto_scripts("crypto")).pack(side="right", padx=10, pady=5)

        in_card = theme.card(wrap)
        in_card.pack(fill="x", pady=(0, 8))
        theme.field_label(in_card, "输入", "密文 / 编码文本 / 哈希；10 万字符以内", padx=12, pady=(10, 4))
        self.code_in = theme.textbox(in_card, mono_font=True, size=13, height=170)
        self.code_in.pack(fill="x", padx=12, pady=(0, 12))

        btn_card = theme.card(wrap)
        btn_card.pack(fill="x", pady=(0, 8))
        theme.section(btn_card, "快捷解码", "点一下即用，结果输出到下方", padx=12, pady=(10, 6))
        grid = theme.panel(btn_card)
        grid.pack(fill="x", padx=10, pady=(0, 10))
        btns = [
            ("自动解码(全家桶)", self._code_auto),
            ("Base64", lambda: self._code_single("Base64")),
            ("Base32", lambda: self._code_single("Base32")),
            ("Hex", lambda: self._code_single("HEX")),
            ("Base58", lambda: self._code_single("Base58")),
            ("Base85", lambda: self._code_single("Base85(b85)")),
            ("Base91", lambda: self._code_single("Base91")),
            ("URL编码", lambda: self._code_single("URL编码")),
            ("Unicode/HTML", lambda: self._code_single("HTML实体")),
            ("ROT13", lambda: self._code_single("ROT13")),
            ("ROT47", lambda: self._code_single("ROT47")),
            ("凯撒全爆破", self._code_caesar),
            ("栅栏全爆破", self._code_fence),
            ("摩斯解码", lambda: self._code_single("摩斯密码")),
            ("Brainfuck", lambda: self._code_single("Brainfuck")),
            ("JWT解码", lambda: self._code_single("JWT")),
            ("核心价值观解码", self._code_cv_dec),
            ("核心价值观编码", self._code_cv_enc),
            ("与佛论禅解码", self._code_tudou_dec),
            ("与佛论禅编码", self._code_tudou_enc),
            ("UUencode解码", self._code_uu),
            ("XXencode解码", self._code_xx),
            ("Jother解码", self._code_jother),
            ("Hex字节倒序", self._code_revhex),
            ("文本倒序", self._code_revtext),
            ("计算哈希", self._code_hash),
            ("识别哈希类型", self._code_hashid),
            ("哈希弱口令爆破", self._code_crackhash),
        ]
        for i, (txt, cmd) in enumerate(btns):
            r, c = divmod(i, 5)
            theme.button(grid, txt, "subtle", width=150, height=30, command=cmd).grid(
                row=r, column=c, padx=4, pady=4, sticky="ew")
        for c in range(5):
            grid.grid_columnconfigure(c, weight=1)

        out_card = theme.card(wrap)
        out_card.pack(fill="both", expand=True)
        out_head = theme.panel(out_card)
        out_head.pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkLabel(out_head, text="结果", font=theme.font(theme.FONT_BODY, "bold"),
                     text_color=theme.TEXT_DIM).pack(side="left")
        theme.button(out_head, "复制结果", "ghost", width=88, height=26,
                     command=lambda: self._copy_text(self.code_out)).pack(side="right", padx=(6, 0))
        theme.button(out_head, "清空", "ghost", width=64, height=26,
                     command=lambda: self._clear_box(self.code_out)).pack(side="right")
        self.code_out = theme.textbox(out_card, mono_font=True, size=13)
        self.code_out.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _code_input(self):
        return self.code_in.get("1.0", "end").strip("\n")

    def _code_put(self, text):
        self.code_out.delete("1.0", "end")
        self.code_out.insert("1.0", text)

    def _code_auto(self):
        text = self._code_input()
        if getattr(self, "_code_running", False):
            return
        if len(text) > 100000:
            self._code_put("自动解码最多接收 100000 个字符；大文件请使用文件分析。")
            return
        self._code_running = True
        self._code_put("正在后台自动解码…")

        def work():
            try:
                results = auto_decode(text, depth=3)
                lines = [f"[{chain}] (可读分 {score:.1f})\n{value[:500]}\n{'-'*70}"
                         for chain, value, score in results[:40]]
                self.q.put(("code_replace", "\n".join(lines) or "未尝试出任何结果"))
            except Exception as error:
                self.q.put(("code_replace", f"解码失败: {error}"))
            finally:
                self._code_running = False
        threading.Thread(target=work, daemon=True).start()

    def _code_single(self, want):
        t = self._code_input()
        res = auto_decode(t, depth=1)
        hit = [r for r in res if r[0] == want]
        if not hit:
            self._code_put(f"{want} 解码失败（输入可能不是该编码）")
        else:
            self._code_put(hit[0][1])

    def _code_caesar(self):
        t = self._code_input()
        from .modules_text import caesar
        self._code_put("\n".join(f"偏移{sh:>2}: {caesar(t, sh)}" for sh in range(26)))

    def _code_fence(self):
        t = self._code_input().replace(" ", "").replace("\n", "")
        from .modules_text import fence_decode
        out = []
        for rails in range(2, min(10, len(t))):
            out.append(f"{rails}栏: {fence_decode(t, rails)}")
        self._code_put("\n".join(out))

    def _code_hash(self):
        t = self._code_input()
        d = hash_text(t)
        self._code_put("\n".join(f"{k}: {v}" for k, v in d.items()))

    def _code_hashid(self):
        t = self._code_input()
        out = []
        for token in set(x.strip() for x in t.replace(",", " ").split()):
            if token:
                out.append(f"{token}\n  -> " + "; ".join(identify_hash(token)))
        self._code_put("\n".join(out))

    def _code_crackhash(self):
        tokens = self._code_input().strip().split()
        if not tokens:
            self._code_put("请先输入哈希值。")
            return
        t = tokens[0]
        self.code_out.delete("1.0", "end")
        self.code_out.insert("end", f"正在用内置弱口令表爆破 {t} …\n")
        wl = self.wordlist

        def work():
            r = crack_hash(t, wl)
            self.q.put(("code", f"\n明文: {r[0]}\n算法: {r[1]}" if r else "\n内置字典未命中，可在专项工具页挂载大字典(rockyou)"))
        threading.Thread(target=work, daemon=True).start()

    def _code_cv_dec(self):
        try:
            self._code_put(modules_text.core_values_decode(self._code_input()))
        except Exception as e:
            self._code_put(f"核心价值观解码失败: {e}")

    def _code_cv_enc(self):
        try:
            self._code_put(modules_text.core_values_encode(self._code_input()))
        except Exception as e:
            self._code_put(f"核心价值观编码失败: {e}")

    def _code_tudou_dec(self):
        try:
            self._code_put(modules_text.tudou_decode(self._code_input()))
        except Exception as e:
            self._code_put(f"与佛论禅解码失败: {e}")

    def _code_tudou_enc(self):
        try:
            self._code_put(modules_text.tudou_encode(self._code_input()))
        except Exception as e:
            self._code_put(f"与佛论禅编码失败: {e}")

    def _code_uu(self):
        from . import modules_morecode as mm
        try:
            self._code_put(mm.uu_decode(self._code_input()).decode("utf-8", "replace"))
        except Exception as e:
            self._code_put(f"UUencode 解码失败: {e}")

    def _code_xx(self):
        from . import modules_morecode as mm
        try:
            self._code_put(mm.xx_decode(self._code_input()).decode("utf-8", "replace"))
        except Exception as e:
            self._code_put(f"XXencode 解码失败: {e}")

    def _code_jother(self):
        from . import modules_morecode as mm
        try:
            self._code_put(mm.jother_decode(self._code_input()))
        except Exception as e:
            self._code_put(f"Jother 解码失败: {e}")

    def _code_revhex(self):
        from . import modules_morecode as mm
        try:
            self._code_put(mm.reverse_hex(self._code_input()))
        except Exception as e:
            self._code_put(f"Hex 倒序失败: {e}")

    def _code_revtext(self):
        from . import modules_morecode as mm
        self._code_put(mm.reverse_text(self._code_input()))

    # ===================================================================
    # 密文加解密页
    # ===================================================================
    def _build_cipher(self):
        from . import modules_codes as mc
        from . import modules_morecode as mm
        wrap = theme.panel(self.t_cipher)
        wrap.pack(fill="both", expand=True, padx=8, pady=8)

        libbar = theme.toolbar(wrap)
        libbar.pack(fill="x", pady=(0, 8))
        theme.hint(libbar, "需要可复制的完整解题脚本？脚本库「Crypto 密码学」方向可直接取用。",
                   side="left", padx=(12, 4), pady=8)
        theme.button(libbar, "📚 Crypto 密码学脚本库", "ghost", width=186,
                     command=lambda: self._goto_scripts("crypto")).pack(side="right", padx=10, pady=5)

        in_card = theme.card(wrap)
        in_card.pack(fill="x", pady=(0, 8))
        theme.field_label(in_card, "输入", "密文 / 明文 / 数据；XOR 与对称加密支持 Hex 或 Base64",
                          padx=12, pady=(10, 4))
        self.ci_in = theme.textbox(in_card, mono_font=True, size=13, height=150)
        self.ci_in.pack(fill="x", padx=12)
        prow = theme.panel(in_card)
        prow.pack(fill="x", padx=12, pady=(8, 12))
        ctk.CTkLabel(prow, text="密钥 / 参数", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(0, 8))
        self.ci_key = theme.entry(prow, placeholder_text="维吉尼亚/Playfair/AES 密钥；仿射填 a,b；对称填 算法:模式:密钥 如 AES:CBC:123456")
        self.ci_key.pack(side="left", fill="x", expand=True)
        self.ci_hex = ctk.StringVar(value="off")
        theme.checkbox(prow, "密钥为 Hex", variable=self.ci_hex,
                       onvalue="on", offvalue="off", width=104).pack(side="left", padx=(10, 0))

        op_card = theme.card(wrap)
        op_card.pack(fill="x", pady=(0, 8))
        theme.section(op_card, "加解密操作", "32 项内置算法，点击即执行", padx=12, pady=(10, 6))
        grid = theme.scroll(op_card, height=232)
        grid.pack(fill="x", padx=12, pady=(0, 12))

        def out(res):
            self.ci_out.delete("1.0", "end")
            self.ci_out.insert("1.0", str(res))

        def T(fn):
            def w():
                try:
                    out(fn(self.ci_in.get("1.0", "end").strip("\n"),
                            self.ci_key.get().strip()))
                except Exception as e:
                    out(f"失败: {type(e).__name__}: {e}")
            return w

        def enc_dec(algo, decrypt):
            def w():
                import base64
                raw = self.ci_in.get("1.0", "end").strip("\n")
                spec = self.ci_key.get().strip()
                # 参数格式：密钥  或  算法:模式:密钥[:IV]，例如 AES:CBC:123456 或 SM4:ECB:key
                parts = spec.split(":")
                iv = ""
                if len(parts) >= 3 and parts[0].upper() in ("AES", "DES", "3DES", "RC4", "SM4"):
                    algo, mode, key = parts[0], parts[1], parts[2]
                    if len(parts) >= 4:
                        iv = parts[3]
                else:
                    mode = "ECB"
                    key = spec
                hexkey = self.ci_hex.get() == "on"
                try:
                    if decrypt:
                        data = bytes.fromhex(raw) if hexkey else \
                            base64.b64decode(raw + "=" * (-len(raw) % 4))
                    else:
                        data = raw.encode()
                    r = mc.symmetric_crypt(algo, mode, data, key, iv, decrypt, key_hex=hexkey)
                    if decrypt:
                        out(r.decode("utf-8", "replace"))
                    else:
                        out(base64.b64encode(r).decode())
                except Exception as e:
                    out(f"失败: {type(e).__name__}: {e}（参数示例 AES:CBC:密钥 或直接填密钥）")
            return w

        btns = [
            ("兽音→明文", T(lambda t, k: mc.roar_decode(t))),
            ("明文→兽音", T(lambda t, k: mc.roar_encode(t))),
            ("盲文→明文", T(lambda t, k: mc.braille_decode(t))),
            ("明文→盲文", T(lambda t, k: mc.braille_encode(t))),
            ("云影→明文", T(lambda t, k: mc.yunying_decode(t))),
            ("明文→云影", T(lambda t, k: mc.yunying_encode(t))),
            ("QWE→明文", T(lambda t, k: mc.qwe_decode(t))),
            ("明文→QWE", T(lambda t, k: mc.qwe_encode(t))),
            ("Base100→明文", T(lambda t, k: mc.base100_decode(t))),
            ("明文→Base100", T(lambda t, k: mc.base100_encode(t))),
            ("敲击码→明文", T(lambda t, k: mc.tapcode_decode(t))),
            ("当铺密码→明文", T(lambda t, k: mc.dangpu_decode(t))),
            ("五笔编码→明文", T(lambda t, k: mc.wubi_decode(t))),
            ("AA/JS/JJ混淆解码", T(lambda t, k: mc.js_obfuscation_decode(t))),
            ("维吉尼亚解密", T(lambda t, k: mc.vigenere(t, k or "key", True))),
            ("维吉尼亚加密", T(lambda t, k: mc.vigenere(t, k or "key", False))),
            ("维吉尼亚自动破解", T(lambda t, k: self._fmt_vig(mc.vigenere_crack(t)))),
            ("仿射解密(a,b)", T(lambda t, k: self._affine(t, k, True))),
            ("仿射自动破解", T(lambda t, k: self._fmt_affine(mc.affine_crack(t)))),
            ("Playfair解密", T(lambda t, k: mc.playfair(t, k or "key", True))),
            ("列移位破解", T(lambda t, k: self._fmt_col(mc.columnar_crack(t)))),
            ("单字节XOR破解", T(lambda t, k: self._fmt_xor1(mc.xor_single_crack(self._input_bytes(t))))),
            ("重复密钥XOR破解", T(lambda t, k: self._fmt_xorr(mc.xor_repeating_crack(self._input_bytes(t))))),
            ("Base64隐写提取", T(lambda t, k: mc.base64_steg_extract(t))),
            ("JWT检查/弱密钥", T(lambda t, k: self._fmt_jwt(mc.jwt_inspect(t)))),
            ("Flask Session解码", T(lambda t, k: self._fmt_flask(mc.flask_session_decode(t, self.wordlist)))),
            ("对称解密(AES/DES/3DES/RC4/SM4)", enc_dec("AES", True)),
            ("对称加密(输出Base64)", enc_dec("AES", False)),
            ("Rabbit解密", self._ci_rabbit_dec),
            ("Rabbit加密", self._ci_rabbit_enc),
            ("猪圈→明文", T(lambda t, k: mm.pigpen_decode(t))),
            ("明文→猪圈", T(lambda t, k: mm.pigpen_encode(t))),
            ("生成二维码", self._ci_qr),
        ]
        for i, (txt, cmd) in enumerate(btns):
            r, c = divmod(i, 4)
            theme.button(grid, txt, "subtle", height=30, command=cmd).grid(
                row=r, column=c, padx=4, pady=4, sticky="ew")
        for c in range(4):
            grid.grid_columnconfigure(c, weight=1)

        out_card = theme.card(wrap)
        out_card.pack(fill="both", expand=True)
        out_head = theme.panel(out_card)
        out_head.pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkLabel(out_head, text="结果", font=theme.font(theme.FONT_BODY, "bold"),
                     text_color=theme.TEXT_DIM).pack(side="left")
        theme.button(out_head, "复制结果", "ghost", width=88, height=26,
                     command=lambda: self._copy_text(self.ci_out)).pack(side="right", padx=(6, 0))
        theme.button(out_head, "清空", "ghost", width=64, height=26,
                     command=lambda: self._clear_box(self.ci_out)).pack(side="right")
        self.ci_out = theme.textbox(out_card, mono_font=True, size=13, height=150)
        self.ci_out.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _input_bytes(self, t):
        import binascii, base64
        try:
            return bytes.fromhex(t.strip())
        except Exception:
            try:
                return base64.b64decode(t.strip() + "=" * (-len(t.strip()) % 4))
            except Exception:
                return t.encode()

    def _fmt_vig(self, res):
        if not res:
            return "未破解（文本可能过短或非维吉尼亚）"
        return "\n".join(f"密钥={k!r} 可读分={s:.1f}\n{v[:300]}" for v, k, s in res[:8])

    def _affine(self, t, k, dec):
        from . import modules_codes as mc
        a, b = (int(x) for x in k.replace(" ", "").split(","))
        return mc.affine(t, a, b, dec)

    def _fmt_affine(self, res):
        if not res:
            return "未破解"
        return "\n".join(f"a={a},b={b} 可读分={s:.1f}\n{v[:300]}" for v, a, b, s in res[:8])

    def _fmt_col(self, res):
        if not res:
            return "未破解"
        return "\n".join(f"列数={c}\n{v[:300]}" for v, c, s in res[:8])

    def _fmt_xor1(self, res):
        if not res:
            return "未发现可读单字节 XOR 明文"
        return "\n".join(f"密钥 0x{k:02x} 评分={s:.1f}\n{txt[:300]}" for k, txt, s in res)

    def _fmt_xorr(self, res):
        if not res:
            return "未破解"
        return "\n".join(f"密钥={k!r} 评分={s:.1f}\n{txt[:300]}" for k, txt, s in res[:6])

    def _fmt_jwt(self, res):
        import json
        header, payload, cracked, notes = res
        return (f"Header: {json.dumps(header, ensure_ascii=False)}\n"
                f"Payload: {json.dumps(payload, ensure_ascii=False)}\n{notes}"
                + (f"\n弱密钥: {cracked!r}" if cracked else ""))

    def _fmt_flask(self, res):
        payload, cracked = res
        return f"Session 内容:\n{payload}" + (f"\n弱密钥: {cracked!r}" if cracked else "\n(内置弱密钥未命中)")

    def _rabbit_key_iv(self):
        from . import modules_morecode as mm
        spec = self.ci_key.get().strip()
        parts = spec.split(":")
        kb = parts[0].encode("utf-8", "replace")
        key = (kb + b"\0" * 16)[:16]
        iv = None
        if len(parts) >= 2 and parts[1]:
            ib = parts[1].encode("utf-8", "replace")
            iv = (ib + b"\0" * 8)[:8]
        return key, iv

    def _ci_rabbit_dec(self):
        from . import modules_morecode as mm
        import base64 as _b64
        try:
            raw = self.ci_in.get("1.0", "end").strip("\n").strip()
            key, iv = self._rabbit_key_iv()
            try:
                data = bytes.fromhex(raw)
            except Exception:
                data = _b64.b64decode(raw + "=" * (-len(raw) % 4))
            out = mm.rabbit_crypt(data, key, iv)
            self.ci_out.delete("1.0", "end")
            self.ci_out.insert("1.0", out.decode("utf-8", "replace"))
        except Exception as e:
            self.ci_out.delete("1.0", "end")
            self.ci_out.insert("1.0", f"Rabbit 解密失败: {type(e).__name__}: {e}")

    def _ci_rabbit_enc(self):
        from . import modules_morecode as mm
        import base64 as _b64
        try:
            raw = self.ci_in.get("1.0", "end").strip("\n").encode("utf-8")
            key, iv = self._rabbit_key_iv()
            out = mm.rabbit_crypt(raw, key, iv)
            self.ci_out.delete("1.0", "end")
            self.ci_out.insert("1.0", _b64.b64encode(out).decode())
        except Exception as e:
            self.ci_out.delete("1.0", "end")
            self.ci_out.insert("1.0", f"Rabbit 加密失败: {type(e).__name__}: {e}")

    def _ci_qr(self):
        from . import modules_codes as mc
        t = self.ci_in.get("1.0", "end").strip("\n")
        fp = mc.qr_encode(t)
        self.ci_out.delete("1.0", "end")
        self.ci_out.insert("1.0", "二维码已生成: " + fp)
        try:
            os.startfile(fp)
        except Exception:
            pass

    # ===================================================================
    # 实用小工具页
    # ===================================================================
    def _build_util(self):
        from . import modules_util as mu
        from . import modules_morecode as mm
        wrap = theme.panel(self.t_util)
        wrap.pack(fill="both", expand=True, padx=8, pady=8)

        libbar = theme.toolbar(wrap)
        libbar.pack(fill="x", pady=(0, 8))
        theme.hint(libbar, "需要可复制的完整解题脚本？脚本库「Utils 实用工具」方向可直接取用。",
                   side="left", padx=(12, 4), pady=8)
        theme.button(libbar, "📚 Utils 实用脚本库", "ghost", width=176,
                     command=lambda: self._goto_scripts("utils")).pack(side="right", padx=10, pady=5)

        in_card = theme.card(wrap)
        in_card.pack(fill="x", pady=(0, 8))
        theme.field_label(in_card, "输入", "按工具需要粘贴文本；参数可留空", padx=12, pady=(10, 4))
        self.u_in = theme.textbox(in_card, mono_font=True, size=13, height=120)
        self.u_in.pack(fill="x", padx=12)
        prow = theme.panel(in_card)
        prow.pack(fill="x", padx=12, pady=(8, 12))
        ctk.CTkLabel(prow, text="参数", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(0, 8))
        self.u_param = theme.entry(prow, placeholder_text="正则表达式 / 替换文本 等（按需）")
        self.u_param.pack(side="left", fill="x", expand=True)

        op_card = theme.card(wrap)
        op_card.pack(fill="x", pady=(0, 8))
        theme.section(op_card, "实用工具", "13 项常用换算与处理", padx=12, pady=(10, 6))
        grid = theme.panel(op_card)
        grid.pack(fill="x", padx=10, pady=(0, 10))

        def out(res):
            self.u_out.delete("1.0", "end")
            self.u_out.insert("1.0", str(res))

        def T(fn):
            def w():
                try:
                    out(fn(self.u_in.get("1.0", "end").strip("\n"),
                            self.u_param.get().strip()))
                except Exception as e:
                    out(f"失败: {type(e).__name__}: {e}")
            return w

        def kv(res):
            if isinstance(res, dict):
                return "\n".join(f"{k}: {v}" for k, v in res.items())
            if isinstance(res, (list, tuple)) and res and isinstance(res[0], tuple):
                return "\n".join(f"{k}: {v}" for k, v in res)
            return str(res)

        btns = [
            ("时间戳互转", T(lambda t, p: kv(mu.convert_timestamp(t)))),
            ("进制互转(2/8/10/16)", T(lambda t, p: kv(mu.convert_number(t)))),
            ("浮点→Hex(double)", T(lambda t, p: kv(mu.float_to_hex(t, 64)))),
            ("浮点→Hex(float)", T(lambda t, p: kv(mu.float_to_hex(t, 32)))),
            ("Hex→浮点(double)", T(lambda t, p: kv(mu.hex_to_float(t, 64)))),
            ("Hex→浮点(float)", T(lambda t, p: kv(mu.hex_to_float(t, 32)))),
            ("大小端交换", T(lambda t, p: kv(mu.endian_swap(t)))),
            ("JSON美化", T(lambda t, p: mu.json_format(t))),
            ("正则提取", T(lambda t, p: self._fmt_regex(mu.regex_extract(p, t)))),
            ("字符频率统计", T(lambda t, p: kv(mu.char_frequency(t)))),
            ("编码探测", T(lambda t, p: kv(mu.detect_encoding(t.encode("utf-8", "replace"))))),
            ("子网/掩码计算", T(lambda t, p: mm.subnet_calc(t))),
            ("生成密码字典", self._u_wordlist),
        ]
        for i, (txt, cmd) in enumerate(btns):
            r, c = divmod(i, 4)
            theme.button(grid, txt, "subtle", height=30, width=180, command=cmd).grid(
                row=r, column=c, padx=4, pady=4, sticky="ew")
        for c in range(4):
            grid.grid_columnconfigure(c, weight=1)

        out_card = theme.card(wrap)
        out_card.pack(fill="both", expand=True)
        out_head = theme.panel(out_card)
        out_head.pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkLabel(out_head, text="结果", font=theme.font(theme.FONT_BODY, "bold"),
                     text_color=theme.TEXT_DIM).pack(side="left")
        theme.button(out_head, "复制结果", "ghost", width=88, height=26,
                     command=lambda: self._copy_text(self.u_out)).pack(side="right", padx=(6, 0))
        theme.button(out_head, "清空", "ghost", width=64, height=26,
                     command=lambda: self._clear_box(self.u_out)).pack(side="right")
        self.u_out = theme.textbox(out_card, mono_font=True, size=13)
        self.u_out.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _fmt_ts(self, res):
        if not res:
            return "无法识别该时间格式"
        return "\n".join(f"{k}: {v}" for k, v in res.items())

    def _fmt_regex(self, res):
        if not res:
            return "无匹配"
        if isinstance(res[0], tuple):
            return "\n".join(str(m) for m in res[:200])
        return "\n".join(res[:500])

    def _u_wordlist(self):
        from . import modules_util as mu
        words = [w.strip() for w in self.u_in.get("1.0", "end").replace(",", "\n").splitlines() if w.strip()]
        if not words:
            self.u_out.delete("1.0", "end")
            self.u_out.insert("1.0", "请在输入中给出姓名/拼音/单词，每行或逗号分隔")
            return
        wl = mu.generate_passwords(words)
        fp, n = mu.save_wordlist(wl)
        self.u_out.delete("1.0", "end")
        self.u_out.insert("1.0", f"已生成 {n} 条口令: {fp}\n\n" + "\n".join(wl[:200]))

    # ===================================================================
    # 专项工具页
    # ===================================================================
    def _build_tools(self):
        wrap = theme.panel(self.t_tool)
        wrap.pack(fill="both", expand=True, padx=8, pady=8)

        libbar = theme.toolbar(wrap)
        libbar.pack(fill="x", pady=(0, 8))
        theme.hint(libbar, "脚本库直达：", side="left", padx=(12, 6), pady=8)
        for txt, cat in [("📚 Misc 杂项", "misc"), ("📁 Reverse 逆向", "reverse"),
                         ("🔍 Forensics 取证", "forensics")]:
            theme.button(libbar, txt, "ghost", width=142, height=28,
                         command=lambda c=cat: self._goto_scripts(c)).pack(side="left", padx=(0, 6), pady=5)

        file_card = theme.card(wrap)
        file_card.pack(fill="x", pady=(0, 8))
        theme.section(file_card, "目标文件", "专项工具只对单个文件做只读分析", padx=12, pady=(10, 6))
        bar = theme.panel(file_card)
        bar.pack(fill="x", padx=12, pady=(0, 12))
        theme.button(bar, "选择文件", "subtle", width=92, command=self._pick_tool_file).pack(side="left")
        self.tool_file = theme.entry(bar, placeholder_text="目标文件路径（可拖入或手动选择）")
        self.tool_file.pack(side="left", fill="x", expand=True, padx=8)
        theme.button(bar, "选择字典", "subtle", width=92, command=self._pick_wordlist).pack(side="left")
        self.wl_label = ctk.CTkLabel(bar, text="字典：内置弱口令表", width=190, anchor="w",
                                     font=theme.font(theme.FONT_SMALL), text_color=theme.TEXT_MUTE)
        self.wl_label.pack(side="left", padx=(8, 0))

        grid_card = theme.card(wrap)
        grid_card.pack(fill="x", pady=(0, 8))
        theme.section(grid_card, "专项分析", "压缩包 / 隐写 / 逆向 / 取证 / 日志", padx=12, pady=(10, 6))
        grid = theme.scroll(grid_card, height=232)
        grid.pack(fill="x", padx=12, pady=(0, 12))
        btns = [
            ("压缩包弱口令+解压", self._m_archive),
            ("压缩包大字典爆破", self._m_archive_big),
            ("CRC套件批量还原(选目录)", self._m_crcsuite),
            ("损坏ZIP容错雕刻", self._m_carvebroken),
            ("bkcrack明文攻击向导", self._m_bkcrack),
            ("文件雕刻(提取内嵌)", self._m_carve),
            ("strings 字符串", self._m_strings),
            ("图片隐写全套", self._m_image),
            ("图片马/Polyglot扫描", self._m_polyglot),
            ("steghide隐写链", self._m_steghide),
            ("盲水印提取", self._m_bwm),
            ("流量包分析", self._m_traffic),
            ("PE/ELF 逆向分析", self._m_reverse),
            ("UPX 脱壳", self._m_upx),
            ("PE 文件头修复", self._m_pe_repair),
            ("PE资源提取", self._m_peres),
            ("PyInstaller解包", self._m_pyi),
            ("pyc 反编译", self._m_pyc),
            ("asar 解包", self._m_asar),
            ("音频隐写全套(MP3/WAV/OGG/FLAC/M4A)", self._m_audio),
            ("DTMF拨号音解码", self._m_dtmf),
            ("Office/PDF文档分析", self._m_document),
            ("文件头修复/伪加密", self._m_repair),
            ("零宽字符隐写", self._m_zerowidth),
            ("RSA密钥分析/分解", self._m_rsa),
            ("NTFS ADS数据流", self._m_ads),
            ("vim swap恢复", self._m_swap),
            ("分片自动合并", self._m_merge),
            ("磁盘镜像(vmdk/vhd/dd)", self._m_disk),
            ("路由器配置/内嵌流", self._m_router),
            ("注册表hive分析", self._m_reg),
            ("Windows evtx日志", self._m_evtx),
            ("Web访问日志分析", self._m_weblog),
            ("一键完整分析", lambda: (self.file_entry.delete(0, "end"),
                                      self.file_entry.insert(0, self.tool_file.get()),
                                      self._start_analysis())),
        ]
        for i, (txt, cmd) in enumerate(btns):
            r, c = divmod(i, 3)
            theme.button(grid, txt, "subtle", height=32, command=cmd).grid(
                row=r, column=c, padx=5, pady=5, sticky="ew")
        for c in range(3):
            grid.grid_columnconfigure(c, weight=1)

        out_card = theme.card(wrap)
        out_card.pack(fill="both", expand=True)
        out_head = theme.panel(out_card)
        out_head.pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkLabel(out_head, text="分析输出", font=theme.font(theme.FONT_BODY, "bold"),
                     text_color=theme.TEXT_DIM).pack(side="left")
        theme.button(out_head, "复制结果", "ghost", width=88, height=26,
                     command=lambda: self._copy_text(self.tool_out)).pack(side="right", padx=(6, 0))
        theme.button(out_head, "清空", "ghost", width=64, height=26,
                     command=lambda: self._clear_box(self.tool_out)).pack(side="right")
        self.tool_out = theme.textbox(out_card, mono_font=True, size=12)
        self.tool_out.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _pick_tool_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.tool_file.delete(0, "end")
            self.tool_file.insert(0, p)

    def _pick_wordlist(self):
        p = filedialog.askopenfilename(title="选择字典（如 rockyou.txt）")
        if p:
            self.wordlist = p
            self.wl_label.configure(text="字典: " + os.path.basename(p))

    def _tool_file_path(self):
        return self.tool_file.get().strip().strip('"')

    def _run_module(self, fn):
        p = self._tool_file_path()
        if not p or not os.path.isfile(p):
            messagebox.showwarning("提示", "请先选择文件")
            return
        self.tool_out.delete("1.0", "end")

        def work():
            rep = Report(path=p)
            outdir = os.path.join(WORKSPACE, "manual_" + os.path.basename(p).replace(".", "_"))
            os.makedirs(outdir, exist_ok=True)
            try:
                fn(p, rep, outdir)
            except Exception as e:
                import traceback
                rep.add("warn", "执行异常", f"{e}\n{traceback.format_exc()[:800]}")
            self.q.put(("manual", rep))
        threading.Thread(target=work, daemon=True).start()

    def _m_archive(self, big=False):
        from .identifier import identify
        wl = self.wordlist if big else None

        def fn(p, rep, outdir):
            info = identify(p)
            if wl:
                # 大字典直接走 7z
                ok, pwd, exdir = modules_archive._crack_7z(p, outdir, wl)
                if ok:
                    rep.add("flag", f"大字典命中密码: {pwd}", exdir)
                else:
                    rep.add("warn", "大字典未命中", "")
            else:
                modules_archive.analyze(p, rep, info.ftype, outdir)
        self._run_module(fn)

    def _m_archive_big(self):
        if not self.wordlist:
            messagebox.showinfo("提示", "请先选择字典文件（rockyou.txt 等）")
            return
        self._m_archive(big=True)

    def _m_carve(self):
        from .modules_carve import scan_and_carve
        self._run_module(lambda p, r, o: scan_and_carve(p, r, o))

    def _m_strings(self):
        from .modules_carve import strings_scan
        def fn(p, rep, outdir):
            strs = strings_scan(p, rep)
            rep.add("info", f"全部字符串({len(strs)}条)前200", "\n".join(strs[:200]))
        self._run_module(fn)

    def _m_image(self):
        from .modules_image import analyze
        self._run_module(lambda p, r, o: analyze(p, r))

    def _m_traffic(self):
        from .modules_traffic import analyze
        self._run_module(lambda p, r, o: analyze(p, r, o))

    def _m_reverse(self):
        from .identifier import identify
        from .modules_reverse import analyze
        def fn(p, r, o):
            info = identify(p)
            analyze(p, r, info.ftype, o)
        self._run_module(fn)

    def _m_upx(self):
        def fn(p, rep, outdir):
            upx = toolsmgr.get_tool("upx")
            if not upx:
                rep.add("warn", "未安装 UPX", "工具中心可一键下载")
                return
            fp = os.path.join(outdir, "unpacked_" + os.path.basename(p))
            r = subprocess.run([upx, "-d", p, "-o", fp, "-f"], capture_output=True, timeout=120)
            if r.returncode == 0:
                rep.add("ok", "UPX 脱壳成功", fp)
            else:
                rep.add("warn", "脱壳失败", (r.stdout + r.stderr).decode("latin-1", "replace")[:500])
        self._run_module(fn)

    def _m_audio(self):
        from . import modules_audio

        def fn(p, rep, outdir):
            modules_audio.analyze(p, rep, os.path.join(outdir, "audio"), do_carve=True)
        self._run_module(fn)

    def _m_wav(self):
        # 兼容旧入口：统一走音频隐写全套
        self._m_audio()

    def _m_document(self):
        from .modules_document import analyze_office, analyze_pdf
        def fn(p, rep, outdir):
            with open(p, "rb") as f:
                head = f.read(16)
            if head[:2] == b"PK":
                analyze_office(p, rep, outdir)
            elif head[:4] == b"%PDF":
                with open(p, "rb") as f:
                    raw = f.read(60 * 1024 * 1024)
                analyze_pdf(p, raw, rep, outdir)
            else:
                rep.add("warn", "不是 Office/PDF", f"文件头: {head!r}")
        self._run_module(fn)

    def _m_repair(self):
        from .modules_stego import repair_file
        def fn(p, rep, outdir):
            ok = repair_file(p, rep, outdir)
            if not ok:
                rep.add("info", "文件头修复", "未发现可自动修复的问题（垃圾头/magic损坏/ZIP伪加密）")
        self._run_module(fn)

    def _m_zerowidth(self):
        from .modules_stego import analyze_zero_width
        def fn(p, rep, outdir):
            raw = open(p, "rb").read(2 * 1024 * 1024)
            text = raw.decode("utf-8", errors="replace")
            analyze_zero_width(text, rep)
        self._run_module(fn)

    def _m_rsa(self):
        from .modules_crypto import analyze_rsa
        def fn(p, rep, outdir):
            with open(p, "rb") as f:
                analyze_rsa(f.read(20 * 1024 * 1024), rep)
        self._run_module(fn)

    # ---- 取证 / 逆向 / 日志 等新增专项 ----
    def _m_ads(self):
        from .modules_forensics import extract_ads
        self._run_module(lambda p, r, o: extract_ads(p, r, o))

    def _m_swap(self):
        from .modules_forensics import recover_vim_swap
        self._run_module(lambda p, r, o: recover_vim_swap(p, r, o))

    def _m_merge(self):
        from .modules_forensics import detect_fragment_dir, merge_fragments

        def fn(p, rep, outdir):
            folder = os.path.dirname(os.path.abspath(p))
            groups = detect_fragment_dir(folder)
            if not groups:
                rep.add("warn", "分片合并", "该目录未发现成组的连续编号分片(.001/part1/out0)")
                return
            for gi, grp in enumerate(groups):
                op = os.path.join(outdir, f"merged_{gi}.bin")
                merge_fragments(grp, op, rep)
        self._run_module(fn)

    def _m_polyglot(self):
        from .modules_forensics import scan_polyglot
        self._run_module(lambda p, r, o: scan_polyglot(p, r, o))

    def _m_pe_repair(self):
        from .modules_forensics import repair_pe
        self._run_module(lambda p, r, o: repair_pe(p, r, o))

    def _m_router(self):
        from .modules_forensics import extract_embedded_streams
        self._run_module(lambda p, r, o: extract_embedded_streams(p, r, o))

    def _m_disk(self):
        from .modules_forensics import extract_disk_image
        self._run_module(lambda p, r, o: extract_disk_image(p, r, o))

    def _m_pyi(self):
        from .modules_pyre import extract_pyinstaller
        self._run_module(lambda p, r, o: extract_pyinstaller(p, r, o))

    def _m_pyc(self):
        from .modules_pyre import decompile_pyc
        self._run_module(lambda p, r, o: decompile_pyc(p, r, o))

    def _m_asar(self):
        from .modules_pyre import extract_asar
        self._run_module(lambda p, r, o: extract_asar(p, r, o))

    def _m_peres(self):
        from .modules_pyre import extract_pe_resources
        self._run_module(lambda p, r, o: extract_pe_resources(p, r, o))

    def _m_dtmf(self):
        from .modules_forensics import dtmf_decode_wav
        self._run_module(lambda p, r, o: dtmf_decode_wav(p, r))

    def _m_reg(self):
        from .modules_forensics import analyze_registry_hive
        self._run_module(lambda p, r, o: analyze_registry_hive(p, r, o))

    def _m_evtx(self):
        from .modules_forensics import analyze_evtx
        self._run_module(lambda p, r, o: analyze_evtx(p, r, o))

    def _m_weblog(self):
        from .modules_log import analyze_weblog
        self._run_module(lambda p, r, o: analyze_weblog(p, r, o))

    def _m_steghide(self):
        from .modules_forensics import steghide_chain

        def fn(p, rep, outdir):
            words = None
            if self.wordlist:
                try:
                    words = [w.strip() for w in open(self.wordlist, errors="ignore") if w.strip()]
                except Exception:
                    words = None
            steghide_chain(p, rep, words, outdir)
        self._run_module(fn)

    def _m_bwm(self):
        from .modules_forensics import blind_watermark_decode

        def fn(p, rep, outdir):
            op = os.path.join(outdir, "blind_wm.png")
            blind_watermark_decode(p, out_path=op, report=rep)
        self._run_module(fn)

    def _m_carvebroken(self):
        from .modules_archive import carve_broken

        def fn(p, rep, outdir):
            raw = open(p, "rb").read()
            carve_broken(raw, outdir, rep)
        self._run_module(fn)

    def _m_bkcrack(self):
        enc = filedialog.askopenfilename(title="选择【加密】zip")
        if not enc:
            return
        plain = filedialog.askopenfilename(title="选择含已知明文的【未加密】zip（可用 7z 对部分文件明文打包）")
        if not plain:
            return
        self.tool_out.delete("1.0", "end")

        def work():
            rep = Report(path=enc)
            outdir = os.path.join(WORKSPACE, "bkcrack_" + os.path.basename(enc).replace(".", "_"))
            os.makedirs(outdir, exist_ok=True)
            try:
                modules_archive.bkcrack_attack(enc, plain, rep, outdir,
                                               log=lambda m: self.q.put(("manual_log", str(m))))
            except Exception as e:
                import traceback
                rep.add("warn", "执行异常", f"{e}\n{traceback.format_exc()[:800]}")
            self.q.put(("manual", rep))
        threading.Thread(target=work, daemon=True).start()

    def _m_crcsuite(self):
        folder = filedialog.askdirectory(title="选择包含一批加密小 zip（out0.zip、out1.zip…）的目录")
        if not folder:
            return
        self.tool_out.delete("1.0", "end")

        def work():
            import glob
            paths = sorted(glob.glob(os.path.join(folder, "*.zip")))
            rep = Report(path=folder)
            outdir = os.path.join(WORKSPACE, "crcsuite_" + os.path.basename(folder))
            os.makedirs(outdir, exist_ok=True)
            if len(paths) < 2:
                rep.add("warn", "CRC 套件", "目录中不足 2 个 zip")
            else:
                try:
                    modules_archive.analyze_crc_suite(paths, rep, outdir)
                except Exception as e:
                    import traceback
                    rep.add("warn", "执行异常", f"{e}\n{traceback.format_exc()[:800]}")
            self.q.put(("manual", rep))
        threading.Thread(target=work, daemon=True).start()

    # ===================================================================
    # Web / Pwn 页
    # ===================================================================
    def _build_web(self):
        wrap = theme.panel(self.t_web)
        wrap.pack(fill="both", expand=True, padx=8, pady=8)

        libbar = theme.toolbar(wrap)
        libbar.pack(fill="x", pady=(0, 8))
        theme.hint(libbar, "可复制脚本库：", side="left", padx=(12, 6), pady=8)
        theme.button(libbar, "📚 Web 脚本 / payload", "ghost", width=172, height=28,
                     command=lambda: self._goto_scripts("web")).pack(side="left", padx=(0, 6), pady=5)
        theme.button(libbar, "📚 Pwn 利用脚本", "ghost", width=152, height=28,
                     command=lambda: self._goto_scripts("pwn")).pack(side="left", pady=5)

        from .ui_web import WebWorkflowFrame
        self.web_workflow = WebWorkflowFrame(wrap, log=self._wlog, analyze_files=self._on_drop,
                                             post=lambda callback: self.q.put(("web_callback", callback)))
        self.web_workflow.pack(fill="x", pady=(0, 8))
        self.web_url = self.web_workflow.url_entry

        port_card = theme.card(wrap)
        port_card.pack(fill="x", pady=(0, 8))
        prow = theme.panel(port_card)
        prow.pack(fill="x", padx=12, pady=10)
        theme.hint(prow, "端口扫描", side="left", padx=(0, 10))
        self.port_range = theme.entry(prow, width=200, placeholder_text="80,443,8000-8100（空=常见端口）")
        self.port_range.pack(side="left")
        theme.button(prow, "开始端口扫描（nmap 优先）", "subtle", width=196,
                     command=self._w_ports).pack(side="left", padx=(8, 0))

        pf = theme.card(wrap)
        pf.pack(fill="x", pady=(0, 8))
        theme.section(pf, "Pwn 二进制 / 远程", "checksec 与 pwntools 模板", padx=12, pady=(10, 6))
        pr = theme.panel(pf)
        pr.pack(fill="x", padx=12, pady=(0, 12))
        theme.button(pr, "选择 ELF 并 checksec", "subtle", width=168, command=self._w_checksec).pack(side="left")
        ctk.CTkLabel(pr, text="IP", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(12, 4))
        self.pwn_host = theme.entry(pr, width=130)
        self.pwn_host.insert(0, "127.0.0.1")
        self.pwn_host.pack(side="left")
        ctk.CTkLabel(pr, text="端口", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(8, 4))
        self.pwn_port = theme.entry(pr, width=84)
        self.pwn_port.insert(0, "9999")
        self.pwn_port.pack(side="left")
        theme.button(pr, "生成 pwntools exp 模板", "subtle", width=184,
                     command=self._w_exp).pack(side="left", padx=(10, 0))

        out_card = theme.card(wrap)
        out_card.pack(fill="both", expand=True)
        out_head = theme.panel(out_card)
        out_head.pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkLabel(out_head, text="Web / Pwn 输出", font=theme.font(theme.FONT_BODY, "bold"),
                     text_color=theme.TEXT_DIM).pack(side="left")
        theme.button(out_head, "复制结果", "ghost", width=88, height=26,
                     command=lambda: self._copy_text(self.web_out)).pack(side="right", padx=(6, 0))
        theme.button(out_head, "清空", "ghost", width=64, height=26,
                     command=lambda: self._clear_box(self.web_out)).pack(side="right")
        self.web_out = theme.textbox(out_card, mono_font=True, size=12)
        self.web_out.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _queue_log(self, kind, value):
        if self._closing:
            return
        if self.q.qsize() < 2000:
            self.q.put((kind, value))
        else:
            self._dropped_logs += 1

    def _wlog(self, m):
        self._queue_log("web", str(m)[:8000] + "\n")

    def _w_ports(self):
        self.web_workflow.start_ports(self.port_range.get().strip())

    def _w_checksec(self):
        p = filedialog.askopenfilename(title="选择 ELF 二进制")
        if not p:
            return
        def work():
            from .modules_reverse import analyze_elf
            rep = Report(path=p)
            outdir = os.path.join(WORKSPACE, "pwn_" + os.path.basename(p))
            os.makedirs(outdir, exist_ok=True)
            try:
                analyze_elf(p, rep, outdir)
            except Exception as e:
                rep.add("warn", "异常", str(e))
            self.q.put(("web_report", rep))
        threading.Thread(target=work, daemon=True).start()

    def _w_exp(self):
        p = filedialog.askopenfilename(title="选择本地 ELF（可取消，默认文件名 pwn）")
        name = os.path.basename(p) if p else "pwn"
        fp = webtools.make_exp(name, self.pwn_host.get().strip(), int(self.pwn_port.get()))
        self._wlog(f"[+] exp 模板已生成: {fp}\n    本地调试: python {fp}\n    远程: python {fp} r")

    # ===================================================================
    # 工具中心
    # ===================================================================
    def _build_center(self):
        head_card = theme.card(self.t_center)
        head_card.pack(fill="x", padx=8, pady=(10, 6))
        theme.notice(head_card, "便携工具统一放在 tools/portable/，仅从官方 GitHub / 官网下载；"
                                "商业软件（IDA / Xshell）请自备正版，逆向推荐 Ghidra / x64dbg。",
                     "warn", wrap=880, padx=12, pady=(12, 8))
        btns = theme.panel(head_card)
        btns.pack(fill="x", padx=12, pady=(0, 12))
        theme.hint(btns, "首次准备约 1～2 GB，失败项会自动跳过并记录到下方安装日志。",
                   side="left", padx=(2, 8))
        theme.button(btns, "一键预置全部工具与运行时", "danger", width=234,
                     command=self._predownload_all).pack(side="right")
        theme.button(btns, "补全便携运行时（JRE/Node/FFmpeg）", "primary", width=274,
                     command=self._bootstrap_runtime).pack(side="right", padx=(0, 6))
        theme.button(btns, "刷新检测状态", "subtle", width=130,
                     command=self._refresh_center).pack(side="right", padx=(0, 6))

        self.center_scroll = theme.scroll(self.t_center)
        self.center_scroll.pack(fill="both", expand=True, padx=8)
        self.center_rows = {}
        logf = theme.card(self.t_center)
        logf.pack(fill="x", padx=8, pady=(6, 10))
        log_head = theme.panel(logf)
        log_head.pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkLabel(log_head, text="安装日志", font=theme.font(theme.FONT_BODY, "bold"),
                     text_color=theme.TEXT_DIM).pack(side="left")
        theme.button(log_head, "复制日志", "ghost", width=92, height=26,
                     command=lambda: self._copy_text(self.center_log)).pack(side="right", padx=(6, 0))
        theme.button(log_head, "清空", "ghost", width=64, height=26,
                     command=lambda: self._clear_box(self.center_log)).pack(side="right")
        self.center_log = theme.textbox(logf, mono_font=True, size=12, height=160)
        self.center_log.pack(fill="x", padx=12, pady=(0, 12))
        self._refresh_center()

    def _clog(self, m):
        self._queue_log("center", str(m)[:8000] + "\n")

    def _refresh_center(self):
        if self._center_detecting or self._closing:
            return
        self._center_detecting = True
        self._clog("[*] 正在后台检测工具，界面可继续使用。")

        def work():
            try:
                toolsmgr._cache.clear()
                status = toolsmgr.detect_all()
                self.q.put(("center_status", status))
            except Exception as error:
                self.q.put(("center_status", {}))
                self._clog(f"[!] 工具检测失败: {error}")
        threading.Thread(target=work, daemon=True).start()

    def _render_center(self, status):
        self._center_detecting = False
        for w in self.center_scroll.winfo_children():
            w.destroy()
        self.center_rows.clear()
        total = len(toolsmgr.TOOL_META)
        ready = sum(1 for k in toolsmgr.TOOL_META if status.get(k))
        for key, (cn, desc, kind) in toolsmgr.TOOL_META.items():
            p = status.get(key)
            row = ctk.CTkFrame(self.center_scroll, fg_color=theme.BG_SURFACE,
                               corner_radius=theme.RADIUS_SMALL, border_width=1,
                               border_color=theme.BORDER_SOFT)
            row.pack(fill="x", pady=2, padx=2)
            ctk.CTkLabel(row, text="● 已就绪" if p else "○ 未安装", width=92, anchor="w",
                         font=theme.font(theme.FONT_SMALL, "bold"),
                         text_color=theme.SUCCESS if p else theme.TEXT_MUTE).pack(
                side="left", padx=(10, 4), pady=7)
            ctk.CTkLabel(row, text=cn, width=152, anchor="w",
                         font=theme.font(theme.FONT_BODY, "bold"),
                         text_color=theme.TEXT).pack(side="left", pady=7)
            ctk.CTkLabel(row, text=desc, anchor="w", font=theme.font(theme.FONT_SMALL),
                         text_color=theme.TEXT_MUTE).pack(
                side="left", fill="x", expand=True, pady=7)

            def add(text, cmd, style="subtle", width=124):
                theme.button(row, text, style, width=width, height=28,
                             command=cmd).pack(side="right", padx=8, pady=5)

            if p:
                add("启动", lambda k=key: self._launch_center(k), "subtle", 82)
            elif kind == "portable":
                add("一键下载安装", lambda k=key: self._install_center(k), "primary")
            elif kind.startswith("winget:"):
                pkg = kind.split(":", 1)[1]
                add("winget 安装", lambda x=pkg: self._winget_center(x))
            elif kind.startswith("pip:"):
                pkg = kind.split(":", 1)[1]
                add("pip 安装", lambda x=pkg: self._pip_center(x))
            elif kind == "wsl":
                add("安装 Kali（WSL2）", self._kali_install, "subtle", 146)
                add("Kali 装全套 CTF 工具", self._kali_suite, "subtle", 168)
            elif kind.startswith("runtime:"):
                rt = kind.split(":", 1)[1]
                add("下载便携运行时", lambda x=rt: self._install_runtime(x), "subtle", 134)
            elif kind.startswith("guide"):
                url = kind.split(":", 1)[1] if ":" in kind else ""
                add("打开官网指引", lambda u=url: self._open_url(u))
            elif kind == "path":
                ctk.CTkLabel(row, text="（安装后自动识别 PATH）",
                             font=theme.font(theme.FONT_SMALL),
                             text_color=theme.TEXT_MUTE).pack(side="right", padx=10, pady=7)
            self.center_rows[key] = (row, p)
        self._set_status(f"工具检测完成 · {ready}/{total} 已就绪", "ok", "● 就绪")

    def _launch_center(self, key):
        if key == "kali":
            # Kali 是用户显式打开的交互式控制台，需保留独立窗口
            subprocess.Popen(["wsl", "-d", "kali-linux"],
                             creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10))
            return
        if key.startswith("volatility") or key == "binwalk":
            self.q.put(("center", "[i] 该工具为命令行/pip 模块，在终端中调用，软件分析时会自动调用\n"))
            return
        if key in ("ffmpeg", "ffprobe", "wabt", "java", "node"):
            p = toolsmgr.detect_one(key)
            self.q.put(("center", f"[i] {key} 为命令行运行时，已就绪并由软件内部静默调用：\n{p}\n"))
            return
        ok, msg = toolsmgr.launch(key)
        if not ok:
            self.q.put(("center", f"[!] 启动失败: {msg}\n"))

    def _install_runtime(self, rt):
        def work():
            self._clog(f"[*] 下载便携运行时 {rt} …")
            ok, msg = toolsmgr.install_runtime(rt, log=lambda m: self._clog(m),
                                               progress=lambda d, t: self._clog(f"\r下载中 {d*100//t}%"))
            self._clog(("[+] " if ok else "[!] ") + msg)
            self.q.put(("refresh", None))
        threading.Thread(target=work, daemon=True).start()

    def _bootstrap_runtime(self):
        if not messagebox.askyesno("确认", "将把 JRE21 / Node / FFmpeg 便携版下载到软件主目录 tools/runtime，\n"
                                          "用于在没有环境的电脑上即开即用，是否继续？"):
            return

        def work():
            rep = toolsmgr.bootstrap_runtimes(log=lambda m: self._clog(m),
                                              progress=lambda d, t: self._clog(f"\r下载中 {d*100//t}%"))
            ok_all = all(v[0] for v in rep.values())
            self._clog("[+] 便携运行时全部就绪" if ok_all else "[!] 部分运行时未就绪，见上方日志")
            self.q.put(("refresh", None))
        threading.Thread(target=work, daemon=True).start()

    def _predownload_all(self):
        if not messagebox.askyesno("确认",
                                   "将一次性下载【全部开源便携工具 + JRE/Node/FFmpeg 运行时】到软件目录，\n"
                                   "总量约 1～2 GB（含 Ghidra），耗时取决于网速，失败项会跳过并记录。\n"
                                   "是否现在开始？"):
            return

        def work():
            self._clog("############ 开始一键预置（后台进行，可切换页面）############")
            rep = toolsmgr.predownload_all(log=lambda m: self._clog(m),
                                           progress=lambda d, t: self._clog(f"\r下载中 {d*100//t}%"))
            rt_ok = sum(1 for v in rep["runtime"].values() if v[0])
            tk_ok = sum(1 for v in rep["tools"].values() if v[0])
            self._clog(f"############ 预置结束：运行时 {rt_ok}/{len(rep['runtime'])}，"
                       f"工具 {tk_ok}/{len(rep['tools'])} ############")
            self.q.put(("refresh", None))
        threading.Thread(target=work, daemon=True).start()

    def _install_center(self, key):
        def work():
            self._clog(f"[*] 开始下载 {key} …")
            ok, msg = toolsmgr.install_portable(key, log=lambda m: self._clog(m),
                                                progress=lambda d, t: self._clog(
                                                    f"\r下载中 {d*100//t}%"))
            self._clog(("[+] 安装成功" if ok else "[!] 安装失败") + f": {msg}")
            self.q.put(("refresh", None))
        threading.Thread(target=work, daemon=True).start()

    def _winget_center(self, pkg):
        def work():
            self._clog(f"[*] winget 安装 {pkg}（可能弹出 UAC，请确认）…")
            ok, out = toolsmgr.winget_install(pkg)
            self._clog(("[+] 完成" if ok else "[!] 失败") + "\n" + out[-1500:])
            self.q.put(("refresh", None))
        threading.Thread(target=work, daemon=True).start()

    def _pip_center(self, pkg):
        def work():
            self._clog(f"[*] pip 安装 {pkg} …")
            ok, out = toolsmgr.pip_install(pkg)
            self._clog(("[+] 完成" if ok else "[!] 失败") + "\n" + out[-1500:])
            self.q.put(("refresh", None))
        threading.Thread(target=work, daemon=True).start()

    def _kali_install(self):
        def work():
            ok, out = toolsmgr.wsl_install_kali(log=self._clog)
            self._clog(("[+] 完成" if ok else "[!] 失败/需重启") + "\n" + out)
            self.q.put(("refresh", None))
        threading.Thread(target=work, daemon=True).start()

    def _kali_suite(self):
        def work():
            self._clog("[*] 在 Kali 中安装全套 CTF 工具，耗时较长…")
            ok, out = toolsmgr.wsl_kali_setup_tools(log=self._clog)
            self._clog(("[+] 完成" if ok else "[!] 失败") + "\n" + out[-2000:])
        threading.Thread(target=work, daemon=True).start()

    def _open_url(self, url):
        if url:
            os.startfile(url)

    # ===================================================================
    # 媒体中心
    # ===================================================================
    def _build_media(self):
        from .ui_media import MediaFrame
        self.media = MediaFrame(self.t_media)
        self.media.pack(fill="both", expand=True)

    # ===================================================================
    # 网页导航（离线镜像优先）
    # ===================================================================
    def _build_webnav(self):
        from . import webnav
        wrap = theme.scroll(self.t_nav)
        wrap.pack(fill="both", expand=True, padx=8, pady=8)
        legend = theme.toolbar(wrap)
        legend.pack(fill="x", pady=(0, 8))
        theme.hint(legend, "绿色「离线打开」= 已镜像到软件目录、断网可用；「在线打开」= 走浏览器（仅收录正当 CTF / 学习工具）。",
                   side="left", padx=(12, 4), pady=8)
        for cat, items in webnav.DATA.items():
            cf = theme.card(wrap)
            cf.pack(fill="x", pady=(0, 8))
            theme.section(cf, cat, f"{len(items)} 项", padx=12, pady=(10, 6))
            for name, url, okey, desc in items:
                row = theme.panel(cf)
                row.pack(fill="x", padx=10, pady=2)
                off = webnav.offline_path(okey) if okey else None
                if off:
                    theme.button(row, "● 离线打开", "success", width=112, height=28,
                                 command=lambda p=off: os.startfile(p)).pack(side="left")
                    theme.button(row, name, "subtle", width=200, height=28,
                                 command=lambda u=url: os.startfile(u)).pack(side="left", padx=6)
                else:
                    theme.button(row, "在线打开", "primary", width=112, height=28,
                                 command=lambda u=url: os.startfile(u)).pack(side="left")
                    ctk.CTkLabel(row, text=name, width=200, anchor="w",
                                 font=theme.font(theme.FONT_BODY),
                                 text_color=theme.TEXT).pack(side="left", padx=6)
                ctk.CTkLabel(row, text=desc, anchor="w", font=theme.font(theme.FONT_SMALL),
                             text_color=theme.TEXT_MUTE).pack(side="left", fill="x", expand=True)
        theme.button(wrap, "重新镜像离线网页（CyberChef 等，需联网）", "ghost", width=320,
                     command=self._remirror_web).pack(pady=12)

    def _remirror_web(self):
        def work():
            self.q.put(("center", "[*] 开始重新镜像离线网页工具…\n"))
            import subprocess
            from .common import IS_FROZEN, APP_DIR
            if IS_FROZEN:
                script = os.path.join(APP_DIR, "_mirror_webtools.py")
            else:
                script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                      "_mirror_webtools.py")
            if not os.path.exists(script):
                self.q.put(("center", f"[!] 镜像脚本缺失: {script}（打包不完整），无法重新镜像。\n"))
                return
            py = external_python()
            if not py:
                self.q.put(("center", "[!] 未找到可用的 Python 解释器（随包便携 Python 缺失且系统未装 Python），无法镜像。\n"))
                return
            r = subprocess.run([py, script], capture_output=True, text=True,
                               errors="replace", cwd=os.path.dirname(script))
            out = (r.stdout or "")[-2500:] + (r.stderr or "")[-800:]
            self.q.put(("center", out + "\n[+] 镜像结束，可重新打开本页查看离线状态\n"))
            self.q.put(("rebuild_nav", None))
        threading.Thread(target=work, daemon=True).start()

    # ===================================================================
    # RAC 自动化页（懒加载）
    # ===================================================================
    def _build_rac(self):
        self.rac = RACTab(self.t_rac)
        self.rac.pack(fill="both", expand=True)

    # ===================================================================
    # 队列分发
    # ===================================================================
    def _on_tab(self):
        builder = getattr(self, "_lazy_tabs", {}).pop(self.tabs.get(), None)
        if builder:
            builder()

    def _goto_scripts(self, cat="all"):
        """跳转到脚本库标签页并预选方向。"""
        self.tabs.set("📚 脚本库")
        self.scripts_lib.select_category(cat)

    def _clear_box(self, box):
        box.delete("1.0", "end")

    def _copy_text(self, box):
        """把输出区内容复制到剪贴板，并在底部状态栏给出字符数反馈。"""
        try:
            text = box.get("1.0", "end-1c")
        except Exception:
            return
        if not text.strip():
            self._set_status("没有可复制的内容", "warn")
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self._set_status(f"已复制到剪贴板（{len(text)} 字符）", "ok")
        except Exception as error:
            self._set_status(f"复制失败：{error}", "danger")

    def _append_log(self, box, text):
        box.insert("end", str(text)[-16000:])
        lines = int(box.index("end-1c").split(".")[0])
        if lines > 2000:
            box.delete("1.0", f"{lines - 1600}.0")
        box.see("end")

    def _center_log(self, m):
        self._append_log(self.center_log, m)

    def _render_manual(self, rep):
        self.tool_out.delete("1.0", "end")
        for fnd in rep.findings:
            self.tool_out.insert("end", f"● {fnd.title}\n", fnd.level)
            if fnd.detail:
                self.tool_out.insert("end", f"    {fnd.detail}\n\n", fnd.level + "_d")
        if rep.extracted:
            self.tool_out.insert("end", "\n提取/生成的文件:\n", "ok")
            for p in rep.extracted:
                self.tool_out.insert("end", f"  {p}\n", "info_d")

    def _drain(self):
        deadline = time.monotonic() + 0.012
        try:
            for _ in range(80):
                if time.monotonic() >= deadline:
                    break
                kind, val = self.q.get_nowait()
                if kind == "log":
                    message, token = val
                    if token == self._run_token:
                        self._append_log(self.ana_log, str(message) + "\n")
                elif kind == "status":
                    text, level = val
                    self._set_status(text, level)
                elif kind == "drop":
                    self._on_drop(val)
                elif kind == "drop_error":
                    self._append_log(self.ana_log, f"[!] 拖入失败，请改用选择文件：{val}\n")
                elif kind == "report":
                    rep, token = val
                    if token != self._run_token or self._analysis_cancel.is_set():
                        continue
                    self._configure_tags()
                    self._render_report(rep)
                    self.last_report = rep
                    files = []
                    def walk(report):
                        files.extend(report.extracted[:1000])
                        for child in report.children:
                            walk(child)
                    walk(rep)
                    self.extract_box.insert("end", "\n".join(dict.fromkeys(files[:1000])) + "\n")
                    if len(files) > 1000:
                        self.extract_box.insert("end", "[更多提取文件见导出报告]\n")
                elif kind == "done":
                    if val == self._run_token:
                        self._analysis_done = True
                elif kind == "code":
                    self._append_log(self.code_out, val)
                elif kind == "code_replace":
                    self._code_put(val)
                elif kind == "manual":
                    self._configure_tags()
                    self._render_manual(val)
                elif kind == "manual_log":
                    self._append_log(self.tool_out, str(val) + "\n")
                elif kind == "web":
                    self._append_log(self.web_out, val)
                elif kind == "web_callback":
                    if not self._closing:
                        val()
                elif kind == "web_report":
                    self.web_out.delete("1.0", "end")
                    for finding in val.findings[:300]:
                        self._append_log(self.web_out, f"{finding.title}\n{str(finding.detail)[:4000]}\n\n")
                elif kind == "center":
                    self._center_log(val)
                elif kind == "center_status":
                    if not self._closing:
                        self._render_center(val)
                elif kind == "refresh":
                    self._refresh_center()
                elif kind == "rebuild_nav":
                    for widget in self.t_nav.winfo_children():
                        widget.destroy()
                    self._lazy_tabs.pop("网页导航", None)
                    self._build_webnav()
        except queue.Empty:
            pass
        except Exception:
            import traceback
            self.report_callback_exception(*sys.exc_info())
        finally:
            if self._render_pending and not self._closing:
                try:
                    self._render_report_chunk()
                except Exception:
                    self._render_pending = False
                    self.report_callback_exception(*sys.exc_info())
            if self._analysis_done and not self._render_pending:
                self._analysis_done = False
                self._busy = False
                self._next_file()
            if not self._closing:
                if self._dropped_logs and self.q.qsize() < 100:
                    self._append_log(self.ana_log, f"[!] 为保持响应，已省略 {self._dropped_logs} 条高频日志；请查看任务报告。\n")
                    self._dropped_logs = 0
                self.after(20 if not self.q.empty() or self._render_pending else 60, self._drain)

    def _configure_tags(self):
        # 注意：CTkTextbox.tag_config 禁止 font 参数（与缩放不兼容），仅用颜色区分
        for box in (self.report_box, self.tool_out, self.web_out, self.ana_log,
                    self.extract_box, self.info_box):
            theme.apply_tags(box)


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
