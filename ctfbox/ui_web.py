import json
import os
import threading
from tkinter import BooleanVar, StringVar, filedialog, messagebox

import customtkinter as ctk

from . import webworkflow
from .common import REPORTS_DIR
from .process_runner import TaskCancelled, TaskTimeout
from . import ui_theme as theme


class WebWorkflowFrame(ctk.CTkFrame):
    def __init__(self, master, log, post, analyze_files=None, **kwargs):
        kwargs.setdefault("fg_color", theme.BG_SURFACE)
        kwargs.setdefault("corner_radius", theme.RADIUS_CARD)
        kwargs.setdefault("border_width", 1)
        kwargs.setdefault("border_color", theme.BORDER_SOFT)
        super().__init__(master, **kwargs)
        self.log = log
        self.post = post
        self.analyze_files = analyze_files
        self._thread = None
        self._cancel = None
        self._task_id = 0
        self.results = []
        self.url_value = StringVar()

        head = theme.panel(self)
        head.pack(fill="x", padx=14, pady=(12, 6))
        ctk.CTkLabel(head, text="Web CTF · 单目标顺序检测", font=theme.font(16, "bold"),
                     text_color=theme.TEXT, anchor="w").pack(side="left")
        theme.chip(head, "每步限时 180 秒", "mute").pack(side="right")
        theme.chip(head, "单目标 · 请求留审计", "info").pack(side="right", padx=(0, 6))
        url_row = theme.panel(self)
        url_row.pack(fill="x", padx=14)
        self.url_entry = theme.entry(url_row, textvariable=self.url_value,
                                     placeholder_text="填写完整的 CTF 题目网址（SQLMap / XSS 建议含查询参数）")
        self.url_entry.pack(side="left", fill="x", expand=True)
        theme.button(url_row, "工具配置 / 手动入口", "ghost", width=172,
                     command=self.open_tools).pack(side="right", padx=(8, 0))

        step_card = theme.card(self)
        step_card.pack(fill="x", padx=14, pady=(10, 0))
        theme.section(step_card, "检测步骤", "勾选后按顺序执行", padx=12, pady=(10, 4))
        options = theme.panel(step_card)
        options.pack(fill="x", padx=12, pady=(0, 10))
        self.steps = {}
        for key, label in (("deep", "★ 深度全自动"), ("auto", "0. 快速取证"),
                           ("http", "1. HTTP / HAR"),
                           ("dirs", "2. 目录探测"), ("source", "3. Git 泄露线索"),
                           ("sqlmap", "4. SQLMap 检测"), ("xss", "5. XSS 反射线索")):
            variable = BooleanVar(value=(key == "deep"))
            self.steps[key] = variable
            theme.checkbox(options, label, variable=variable, width=132).pack(side="left", padx=(0, 6))

        util_row = theme.panel(self)
        util_row.pack(fill="x", padx=14, pady=(8, 0))
        ctk.CTkLabel(util_row, text="目录引擎", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(0, 6))
        self.dir_engine = theme.option_menu(util_row, values=["内置", "dirsearch", "ffuf"], width=118)
        self.dir_engine.pack(side="left", padx=(0, 12))
        theme.button(util_row, "JWT 离线解析", "ghost", width=130,
                     command=self.open_jwt).pack(side="left", padx=(0, 4))
        theme.button(util_row, "图片马 / 流量附件分析", "ghost", width=184,
                     command=self.open_attachment).pack(side="left", padx=4)
        theme.button(util_row, "查看报告 / HAR", "ghost", width=142,
                     command=self.open_reports).pack(side="left", padx=4)

        ctl_row = theme.panel(self)
        ctl_row.pack(fill="x", padx=14, pady=(10, 0))
        self.start_button = theme.button(ctl_row, "开始测试", "primary", width=130, command=self.start)
        self.start_button.pack(side="right")
        self.stop_button = theme.button(ctl_row, "停止检测", "subtle", width=104,
                                        state="disabled", command=self.stop)
        self.stop_button.pack(side="right", padx=(0, 8))

        state_bar = theme.toolbar(self)
        state_bar.pack(fill="x", padx=14, pady=(10, 4))
        ctk.CTkLabel(state_bar, text="●", font=theme.font(11),
                     text_color=theme.INFO).pack(side="left", padx=(10, 3))
        self.state_label = ctk.CTkLabel(
            state_bar, anchor="w", justify="left", font=theme.font(theme.FONT_SMALL),
            text_color=theme.TEXT_DIM,
            text="就绪 · 每步限时 180 秒 · 缺少工具会明确跳过 · 不自动提取数据或连接 WebShell")
        self.state_label.pack(side="left", pady=7, padx=(0, 8))

        theme.notice(self, "HAR 仅记录本次 HTTP 请求；XSS 反射不等于可执行漏洞。"
                           "JWT / SSRF / 上传题需额外上下文，使用上方工具入口。",
                     "warn", wrap=980, padx=14, pady=(4, 12))

    def open_reports(self):
        try:
            os.startfile(REPORTS_DIR)
        except OSError as error:
            messagebox.showerror("无法打开报告目录", str(error), parent=self)

    def open_attachment(self):
        paths = filedialog.askopenfilenames(parent=self, title="选择 CTF 图片、流量包或附件（只读分析，不上传）")
        if paths and self.analyze_files:
            self.analyze_files(paths)

    def open_jwt(self):
        if getattr(self, "jwt_window", None) and self.jwt_window.winfo_exists():
            self.jwt_window.focus()
            return
        window = self.jwt_window = ctk.CTkToplevel(self)
        window.title("JWT 离线解析 · 不发请求、不验证签名")
        window.geometry("780x560")
        window.transient(self.winfo_toplevel())
        theme.apply_root(window)
        theme.notice(window, "粘贴题目 JWT；仅在内存中解码，不保存令牌、不发送到网络。",
                     "warn", wrap=720, padx=14, pady=(14, 8))
        token = theme.textbox(window, mono_font=True, size=12, height=96, wrap="word")
        token.pack(fill="x", padx=14)
        output = theme.textbox(window, mono_font=True, size=12, wrap="word")

        def decode():
            output.delete("1.0", "end")
            try:
                value = webworkflow.decode_jwt(token.get("1.0", "end").strip())
                value["warning"] = "仅解码：签名、算法、签发者、受众与过期时间均未验证，不可据此信任令牌。"
                output.insert("end", json.dumps(value, ensure_ascii=False, indent=2))
            except ValueError as error:
                output.insert("end", "无法解析 JWT：" + str(error))

        ctk.CTkButton(window, text="离线解析", fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER,
                      font=theme.font(theme.FONT_BODY), height=30, corner_radius=theme.RADIUS_CTRL,
                      command=decode).pack(anchor="w", padx=14, pady=10)
        output.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.jwt_token = token
        self.jwt_output = output
        self.decode_jwt_input = decode

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self, selected=None):
        if self.is_running():
            return
        url = self.url_value.get().strip()
        if not url:
            messagebox.showwarning("需要网址", "请输入完整的 HTTP/HTTPS 题目网址。", parent=self)
            return
        try:
            url = webworkflow.validate_url(url)
        except ValueError as error:
            messagebox.showwarning("网址无效", str(error), parent=self)
            return
        steps = selected if selected is not None else [key for key, variable in self.steps.items() if variable.get()]
        if not steps:
            messagebox.showwarning("需要检测步骤", "请至少选择一个检测步骤。", parent=self)
            return
        engine = self.dir_engine.get()
        steps = [engine if key == "dirs" and engine != "内置" else key for key in steps]
        self._start_task(lambda cancel: webworkflow.run_workflow(
            url, steps, log=self.log, cancel_event=cancel, step_timeout=420), url)

    def start_ports(self, ports):
        if self.is_running():
            return
        from urllib.parse import urlsplit
        from . import webtools
        try:
            target = urlsplit(webworkflow.validate_url(self.url_value.get().strip()))
            if ports:
                webtools._parse_ports(ports)
        except ValueError as error:
            messagebox.showwarning("目标或端口无效", str(error), parent=self)
            return

        def scan(cancel):
            webtools.port_scan(target.hostname, ports or None, log=self.log, cancel_event=cancel)
            return [{"step": "ports", "status": "completed", "detail": "端口结果见日志"}]
        self._start_task(scan, f"端口探测 {target.hostname}")

    def _start_task(self, job, description):
        self._task_id += 1
        task_id = self._task_id
        self.results = []
        cancel = self._cancel = threading.Event()
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.url_entry.configure(state="disabled")
        self.state_label.configure(text="运行中 · 日志显示当前步骤 · 可随时停止")
        self.log("\n========== 开始 CTF 单目标任务 ==========\n" + description)

        def work():
            state = "任务完成，详情见日志与 reports 中的报告"
            try:
                results = job(cancel)
                self.results = results
                statuses = [item.get("status") for item in results]
                if cancel.is_set() or "cancelled" in statuses:
                    state = "已停止，已清理当前工具进程"
                elif any(status not in ("completed", "ok", "success") for status in statuses):
                    state = "流程结束，包含跳过或失败步骤，请查看日志"
            except TaskCancelled:
                state = "已停止，已清理当前工具进程"
            except TaskTimeout:
                state = "任务超时，工具进程已结束"
            except Exception as error:
                state = f"任务未完成：{error}"
                self.log("[!] " + state)
            finally:
                self.post(lambda text=state: self._finished(text, task_id))
        self._thread = threading.Thread(target=work, daemon=True)
        self._thread.start()

    def _finished(self, state, task_id):
        if task_id != self._task_id:
            return
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.url_entry.configure(state="normal")
        labels = {"ok": "已执行", "completed": "已执行", "skipped": "跳过", "error": "失败",
                  "timeout": "超时", "cancelled": "取消"}
        summary = " · ".join(f"{item['step']}：{labels.get(item.get('status'), item.get('status', '未知'))}"
                             for item in self.results)
        self.state_label.configure(text=state + ("\n" + summary if summary else ""))
        self.log("[*] " + state)

    def stop(self):
        if self._cancel:
            self._cancel.set()
        if self.is_running():
            self.stop_button.configure(state="disabled")
            self.state_label.configure(text="正在停止当前步骤并清理子进程…")

    def open_tools(self):
        if getattr(self, "tools_window", None) and self.tools_window.winfo_exists():
            self.tools_window.focus()
            return
        window = self.tools_window = ctk.CTkToplevel(self)
        window.title("Web CTF 工具管理 · 配置可信本机工具")
        window.geometry("900x580")
        window.transient(self.winfo_toplevel())
        theme.apply_root(window)
        names = {f"{key} · {metadata.get('name', key)}": key for key, metadata in webworkflow.TOOLS.items()}
        row = theme.toolbar(window)
        row.pack(fill="x", padx=14, pady=12)
        selector = theme.option_menu(row, values=list(names), width=290)
        selector.pack(side="left", padx=8, pady=8)
        output = theme.textbox(window, size=13, wrap="word")
        output.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        def show(text):
            if window.winfo_exists():
                output.delete("1.0", "end")
                output.insert("end", text)

        def refresh(*_):
            key = names[selector.get()]
            metadata = webworkflow.TOOLS[key]
            show(f"{metadata.get('name', key)}\n\n{metadata.get('description', '')}\n\n正在检测本机路径…")
            def work():
                try:
                    status = webworkflow.tool_status()[key]
                    availability = "入口与运行时已找到（依赖需实测）" if status["ready"] else "尚未配置 / 运行时不可用"
                    if not metadata["candidates"]:
                        availability = "浏览器内使用，无独立程序入口"
                    text = (f"{metadata.get('name', key)}\n\n{metadata.get('description', '')}\n\n"
                            f"本机状态：{availability}\n入口：{status.get('path') or '无'}\n\n"
                            f"{status.get('detail', '')}\n\n配置只登记路径，不下载工具或安装依赖。"
                            "GUI 工具点击后打开；命令行专项工具会在主界面日志提供启动命令与所需参数指引。")
                except Exception as error:
                    text = f"检测失败: {error}"
                self.post(lambda: show(text) if window.winfo_exists() and names[selector.get()] == key else None)
            threading.Thread(target=work, daemon=True).start()

        def configure():
            key = names[selector.get()]
            path = filedialog.askopenfilename(parent=window, title="选择可信工具的入口文件")
            if not path:
                return
            try:
                webworkflow.configure_tool(key, path)
            except (ValueError, OSError) as error:
                messagebox.showerror("配置失败", str(error), parent=window)
                return
            refresh()

        def launch():
            key = names[selector.get()]
            if key == "antsword" and not messagebox.askyesno(
                    "仅限比赛授权 WebShell", "只打开本机蚁剑，不代填地址、不上传或执行代码。\n确认比赛明确允许此类操作，并继续打开？", parent=window):
                return
            def work():
                try:
                    webworkflow.launch_tool(key, log=self.log)
                except Exception as error:
                    self.log(f"[!] 工具入口打开失败：{error}")
            threading.Thread(target=work, daemon=True).start()

        selector.configure(command=refresh)
        theme.button(row, "选择入口文件", "subtle", width=120, command=configure).pack(side="left", padx=4)
        theme.button(row, "打开 / 使用指引", "primary", width=142, command=launch).pack(side="left", padx=4)
        theme.button(row, "刷新", "ghost", width=78, command=refresh).pack(side="left", padx=4)
        refresh()
