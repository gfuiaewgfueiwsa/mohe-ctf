# -*- coding: utf-8 -*-
"""v3.7.0「一键梭哈」标签页：串起识别→静态分析→编码/异或→对称密码→Web 利用→证据链→结论。"""
import os
import queue
import threading
import traceback
from tkinter import filedialog, messagebox

import customtkinter as ctk

from . import ui_theme as theme

VERSION_TAG = "v3.7.0"


class AutoPilotTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._q = queue.Queue()
        self._running = False
        self._result = None
        self._build()
        self.after(150, self._drain)

    # ------------------------------------------------------------------
    def _build(self):
        theme.notice(self, "使用前须已同意《软件责任说明》：仅对已获合法授权的目标操作；"
                           "未知二进制默认只做静态分析。", kind="warn",
                     wrap=1100, padx=10, pady=(10, 4))

        top = theme.card(self)
        top.pack(fill="x", padx=10, pady=(4, 8))
        theme.section(top, "一键梭哈", "v3.7.0 · 文件或 URL", padx=14, pady=(12, 6))

        row = theme.panel(top)
        row.pack(fill="x", padx=14, pady=(0, 8))
        self.target = theme.entry(row, placeholder_text="题目文件路径，或 http(s):// 靶场地址")
        self.target.pack(side="left", fill="x", expand=True)
        theme.button(row, "选择文件", "subtle", width=92, height=32,
                     command=self._pick_file).pack(side="left", padx=(8, 0))

        row2 = theme.panel(top)
        row2.pack(fill="x", padx=14, pady=(0, 4))
        self.render_var = ctk.BooleanVar(value=False)
        self.deep_var = ctk.BooleanVar(value=False)
        self.exploit_var = ctk.BooleanVar(value=False)
        theme.checkbox(row2, "浏览器渲染", variable=self.render_var).pack(side="left")
        theme.checkbox(row2, "深度分析", variable=self.deep_var).pack(side="left", padx=(14, 0))
        theme.checkbox(row2, "启用 Web 利用模块", variable=self.exploit_var).pack(side="left", padx=(14, 0))

        row3 = theme.panel(top)
        row3.pack(fill="x", padx=14, pady=(0, 4))
        self.run_btn = theme.button(row3, "一键梭哈", "primary", width=112, height=32,
                                    command=self._start)
        self.run_btn.pack(side="right")
        theme.button(row3, "打开工作区", "ghost", width=104, height=32,
                     command=self._open_workdir).pack(side="right", padx=(0, 6))
        theme.button(row3, "清空", "ghost", width=72, height=32,
                     command=self._clear).pack(side="right", padx=(0, 6))

        row4 = theme.panel(top)
        row4.pack(fill="x", padx=14, pady=(0, 12))
        theme.toolbar_label(row4, "登录目录").pack(side="left")
        self.user_data = theme.entry(row4, placeholder_text="浏览器持久化目录，复用登录态（可留空）")
        self.user_data.pack(side="left", fill="x", expand=True, padx=(8, 10))
        theme.toolbar_label(row4, "CDP").pack(side="left")
        self.cdp = theme.entry(row4, placeholder_text="http://127.0.0.1:9222（可留空）")
        self.cdp.pack(side="left", fill="x", expand=True)

        body = theme.panel(self)
        body.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        left = theme.card(body)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        theme.section(left, "结论", "候选 flag / 可疑点 / 下一步", padx=12, pady=(12, 6))
        self.result_box = theme.textbox(left, mono_font=True, size=12)
        self.result_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        right = theme.card(body, width=460)
        right.pack(side="left", fill="both")
        right.pack_propagate(False)
        theme.section(right, "运行日志", "逐步证据", padx=12, pady=(12, 6))
        self.log_box = theme.textbox(right, mono_font=True, size=11)
        self.log_box.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.status = ctk.CTkLabel(right, text="就绪", font=theme.font(theme.FONT_SMALL),
                                   text_color=theme.TEXT_MUTE, anchor="w")
        self.status.pack(fill="x", padx=12, pady=(0, 10))

    # ------------------------------------------------------------------
    def _pick_file(self):
        path = filedialog.askopenfilename(title="选择题目文件（任意后缀）")
        if path:
            self.target.delete(0, "end")
            self.target.insert(0, path)

    def _clear(self):
        self.result_box.delete("1.0", "end")
        self.log_box.delete("1.0", "end")

    def _open_workdir(self):
        path = (self._result or {}).get("workdir") or ""
        if path and os.path.isdir(path):
            try:
                os.startfile(path)
            except Exception as exc:
                messagebox.showerror("打开失败", str(exc))
        else:
            messagebox.showinfo("暂无工作区", "先运行一次一键梭哈")

    def _log(self, message):
        self._q.put(("log", str(message)))

    def _start(self):
        if self._running:
            return
        target = self.target.get().strip().strip('"')
        if not target:
            messagebox.showwarning("缺少输入", "请输入文件路径或 http(s):// 地址")
            return
        is_url = target.startswith(("http://", "https://"))
        if not is_url and not os.path.isfile(target):
            messagebox.showwarning("文件不存在", target)
            return
        exploit = bool(self.exploit_var.get())
        if exploit and not is_url:
            messagebox.showwarning("仅 Web 目标", "Web 利用模块只适用于 http(s):// 地址。")
            self.exploit_var.set(False)
            return
        hosts = []
        self._running = True
        self.run_btn.configure(state="disabled")
        self.status.configure(text="运行中…", text_color=theme.WARNING)
        self._log(f"===== {VERSION_TAG} 一键梭哈开始 =====")
        self._log(f"目标: {target}")
        threading.Thread(target=self._worker, args=(target, is_url, hosts, False,
                                                    self.deep_var.get(), self.render_var.get(),
                                                    self.user_data.get().strip(),
                                                    self.cdp.get().strip(), exploit),
                         daemon=True).start()

    def _worker(self, target, is_url, hosts, allow_private, deep, render,
                user_data="", cdp="", exploit=False):
        try:
            from .autopilot.orchestrator import AutoPilot
            pilot = AutoPilot(allow_private=allow_private, allow_hosts=hosts,
                              deep=deep, render=render, log=self._log,
                              user_data=user_data, cdp=cdp, exploit=exploit)
            res = pilot.run_url(target) if is_url else pilot.run_file(target)
            self._q.put(("done", res))
        except Exception:
            self._q.put(("error", traceback.format_exc()))

    # ------------------------------------------------------------------
    def _drain(self):
        try:
            for _ in range(60):
                kind, val = self._q.get_nowait()
                if kind == "log":
                    self._append(self.log_box, val + "\n")
                elif kind == "done":
                    self._result = val
                    self._render_result(val)
                    self._running = False
                    self.run_btn.configure(state="normal")
                    ok = bool(val.get("success"))
                    self.status.configure(text="完成：命中 flag" if ok else "完成：未命中高置信 flag",
                                          text_color=theme.SUCCESS if ok else theme.WARNING)
                elif kind == "error":
                    self._append(self.log_box, "\n[!] 运行异常\n" + val + "\n")
                    self._running = False
                    self.run_btn.configure(state="normal")
                    self.status.configure(text="运行失败", text_color=theme.DANGER)
        except queue.Empty:
            pass
        except Exception:
            pass
        self.after(150, self._drain)

    def _append(self, box, text):
        box.insert("end", text[-20000:])
        lines = int(box.index("end-1c").split(".")[0])
        if lines > 2500:
            box.delete("1.0", f"{lines - 2000}.0")
        box.see("end")

    def _render_result(self, res):
        lines = [
            "========== 结论 ==========",
            f"工作区: {res.get('workdir')}",
            f"类型: {res.get('kind')} / {res.get('category', 'web')}",
            f"结论: {'命中强候选 flag' if res.get('success') else '未得到高置信 flag'}",
            "",
            "候选:",
        ]
        cands = res.get("candidates") or []
        if cands:
            for c in cands[:12]:
                tag = "FLAG" if c.get("confidence", 0) >= 0.8 else "候选"
                lines.append(f"  [{tag} {c.get('confidence'):.2f}] {c.get('value')}")
                lines.append(f"       来源 {c.get('source')} | {c.get('reason')}")
        else:
            lines.append("  （无）")
        if res.get("suspicious"):
            lines += ["", "Web 可疑点:"]
            for s in res["suspicious"][:12]:
                lines.append(f"  [{s.get('type')}] {s.get('url')}")
                lines.append(f"       {s.get('evidence')}")
        exploit = res.get("exploit") or {}
        if exploit:
            lines += ["", "Web 利用（声明闸门 + 双校验 + 审计）:"]
            lines.append("  请求 %s/%s | 审计 %s 条 | 发现 %s 项 | 样本 %s 个" % (
                exploit.get("requests"), exploit.get("budget"),
                (exploit.get("audit") or {}).get("entries"),
                len(exploit.get("findings") or []),
                len(exploit.get("artifacts") or [])))
            for f in (exploit.get("findings") or [])[:16]:
                lines.append(f"  [{f.get('type')}] {f.get('url')}")
                lines.append(f"       {f.get('evidence')}")
            if exploit.get("artifacts"):
                lines.append("  验证样本: " + "; ".join(
                    os.path.basename(p) for p in exploit["artifacts"][:8]))
        if res.get("next_steps"):
            lines += ["", "下一步:"]
            lines += [f"  - {s}" for s in res["next_steps"][:10]]
        if res.get("notes"):
            lines += ["", "限制/提示:"]
            lines += [f"  - {s}" for s in res["notes"][:12]]
        self.result_box.delete("1.0", "end")
        self._append(self.result_box, "\n".join(lines))
