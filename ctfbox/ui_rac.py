# -*- coding: utf-8 -*-
"""RAC 自动化中心 GUI（v2.4 新增标签页）。

五个子页：
  1. 题目流水线   —— Recognize→Assemble→Command 全自动解题（核心）
  2. 侦察自动化   —— 端口扫描 / HTTP 指纹 / 目录探测批量收集
  3. 远程执行     —— SSH 主机清单批量执行命令
  4. Oracle RAC   —— Oracle RAC 集群只读巡检（SSH 命令集）
  5. RPA 会话     —— 步骤表驱动 HTTP 会话（自动登录/自动提交）

所有长任务跑在后台线程，日志经 queue 回主线程渲染；停止按钮全链路生效。
仅用于 CTF 比赛、靶场与已授权目标。
"""
import json
import queue
import threading
import traceback

import customtkinter as ctk

from .rac.pipeline import RacPipeline
from .rac import recon, remoteexec, oracle_rac, rpa
from . import ui_theme as theme


class RACTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self.q = queue.Queue()
        self._stop = threading.Event()
        self._thread = None
        self._build()
        self.after(80, self._drain)

    # ------------------------------------------------------------------
    # 公共骨架
    # ------------------------------------------------------------------
    def _build(self):
        theme.notice(
            self, "RAC 自动化仅限 CTF 比赛 / 靶场 / 已授权目标使用。侦察与远程执行会对目标发起真实网络请求，"
                  "Oracle RAC 巡检为只读命令集，RPA 仅驱动你自己配置的会话步骤。",
            "warn", wrap=1180, padx=10, pady=(10, 4))

        self.sub = theme.tabview(self)
        self.sub.pack(fill="both", expand=True, padx=8, pady=(4, 8))
        self.sub.add("题目流水线")
        self.sub.add("侦察自动化")
        self.sub.add("远程执行")
        self.sub.add("Oracle RAC 巡检")
        self.sub.add("RPA 会话")
        self._build_pipeline(self.sub.tab("题目流水线"))
        self._build_recon(self.sub.tab("侦察自动化"))
        self._build_remote(self.sub.tab("远程执行"))
        self._build_oracle(self.sub.tab("Oracle RAC 巡检"))
        self._build_rpa(self.sub.tab("RPA 会话"))

    def _log(self, msg):
        self.q.put(("log", str(msg)))

    def _flag(self, msg):
        self.q.put(("flag", str(msg)))

    def _drain(self):
        try:
            while True:
                kind, msg = self.q.get_nowait()
                box = getattr(self, "_cur_box", None)
                if kind == "flag":
                    self.flag_box.configure(state="normal")
                    self.flag_box.insert("end", msg + "\n", "flagtag")
                    self.flag_box.see("end")
                    self.flag_box.configure(state="disabled")
                elif box is not None:
                    box.configure(state="normal")
                    box.insert("end", msg + "\n")
                    box.see("end")
                    box.configure(state="disabled")
        except queue.Empty:
            pass
        except Exception:
            pass
        self.after(80, self._drain)

    def _write(self, box, msg):
        box.configure(state="normal")
        box.insert("end", str(msg) + "\n")
        box.see("end")
        box.configure(state="disabled")

    def _start_worker(self, fn, logbox):
        if self._thread and self._thread.is_alive():
            self._write(logbox, "[!] 已有任务在运行，请先停止")
            return
        self._cur_box = logbox
        self._stop.clear()
        self.flag_box.configure(state="normal")
        self.flag_box.delete("1.0", "end")
        self.flag_box.configure(state="disabled")

        def run():
            try:
                fn()
            except Exception as e:
                self._log(f"[!] 任务异常: {e}")
                self._log(traceback.format_exc()[-1500:])

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def _stop_worker(self, logbox):
        self._stop.set()
        self._write(logbox, "[*] 停止信号已发送，等待当前步骤结束 ...")

    def _mklogbox(self, parent, height=200):
        return theme.textbox(parent, mono_font=True, size=12, height=height, wrap="word")

    def _seal(self, box):
        box.configure(state="disabled")

    # ------------------------------------------------------------------
    # 子页 1：题目流水线
    # ------------------------------------------------------------------
    def _build_pipeline(self, tab):
        theme.notice(tab, "流水线：粘贴题目描述（含 n/e/c、host:port、哈希等参数）＋ 附件（可选）→ 自动识别题型 → "
                          "从随包脚本库（scripts/library）评分匹配脚本 → 自动填参执行 → 运行时提取 flag。命中即止。",
                     "info", wrap=1150, padx=8, pady=(8, 4))

        body = theme.panel(tab)
        body.pack(fill="both", expand=True, padx=8, pady=4)
        left = theme.card(body, width=440)
        left.pack(side="left", fill="y", padx=(0, 8))
        left.pack_propagate(False)
        right = theme.card(body)
        right.pack(side="left", fill="both", expand=True)

        theme.section(left, "①  题目描述 / 已知参数", "支持整段粘贴", padx=12, pady=(10, 4))
        self.rac_desc = theme.textbox(left, mono_font=True, size=12, height=150, wrap="word")
        self.rac_desc.pack(fill="x", padx=12)
        self.rac_desc.insert("1.0", "示例：\nRSA 题，已知 n = 868... , e = 65537, c = 123...，求 flag\n"
                                    "或：nc 1.2.3.4 9999 栈溢出\n或粘贴题目全文，参数自动识别")

        theme.section(left, "②  附件", "可选，自动深度分析", padx=12, pady=(10, 4))
        bar = theme.panel(left)
        bar.pack(fill="x", padx=10)
        theme.button(bar, "添加附件", "subtle", width=92, height=28,
                     command=self._rac_pick).pack(side="left", padx=(0, 4), pady=2)
        theme.button(bar, "清空", "ghost", width=64, height=28,
                     command=self._rac_clear_att).pack(side="left", pady=2)
        self.rac_att_box = theme.textbox(left, mono_font=True, size=11, height=72, wrap="word")
        self.rac_att_box.pack(fill="x", padx=12, pady=(4, 0))
        self._rac_attachments = []

        theme.section(left, "③  参数", "自动识别，可手动补充覆盖", padx=12, pady=(10, 4))
        self.rac_extra = theme.entry(left, placeholder_text="如: n=12345 e=65537 或 host=1.2.3.4 port=9999")
        self.rac_extra.pack(fill="x", padx=12)

        opts = theme.panel(left)
        opts.pack(fill="x", padx=12, pady=(8, 2))
        ctk.CTkLabel(opts, text="候选数", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(2, 4))
        self.rac_topn = theme.option_menu(opts, values=["3", "5", "8", "10"], width=66)
        self.rac_topn.set("5")
        self.rac_topn.pack(side="left")
        ctk.CTkLabel(opts, text="单脚本限时(s)", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(12, 4))
        self.rac_tmo = theme.option_menu(opts, values=["60", "120", "180", "300"], width=70)
        self.rac_tmo.set("180")
        self.rac_tmo.pack(side="left")
        self.rac_deep = theme.checkbox(opts, "附件深度分析")
        self.rac_deep.select()
        self.rac_deep.pack(side="left", padx=(12, 2))

        btns = theme.panel(left)
        btns.pack(fill="x", padx=12, pady=(12, 10))
        self.rac_run = theme.button(btns, "▶  开始 RAC 流水线", "danger", width=160, height=32,
                                    command=self._rac_start)
        self.rac_run.pack(side="left")
        self.rac_stop = theme.button(btns, "■ 停止", "ghost", width=82, height=32,
                                     command=lambda: self._stop_worker(self.rac_log))
        self.rac_stop.pack(side="left", padx=(8, 0))

        theme.section(right, "RAC 执行日志", "实时输出", padx=12, pady=(10, 4))
        self.rac_log = self._mklogbox(right, height=200)
        self.rac_log.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        theme.section(right, "发现的 flag", "命中即高亮", padx=12, pady=(0, 4))
        self.flag_box = theme.textbox(right, mono_font=True, size=13, height=90, wrap="word")
        self.flag_box.pack(fill="x", padx=12, pady=(0, 12))
        try:
            self.flag_box.tag_config("flagtag", foreground=theme.TAGS["flag"])
        except Exception:
            self.flag_box._textbox.tag_config("flagtag", foreground=theme.TAGS["flag"])
        self._seal(self.rac_log)
        self._seal(self.flag_box)

    def _rac_pick(self):
        from tkinter import filedialog
        paths = filedialog.askopenfilenames(title="选择题目附件（可多选）")
        for p in paths:
            if p and p not in self._rac_attachments:
                self._rac_attachments.append(p)
                self._write(self.rac_att_box, p)

    def _rac_clear_att(self):
        self._rac_attachments = []
        self.rac_att_box.delete("1.0", "end")

    def _parse_extra_params(self, text):
        """手动补充参数：k=v 空格/逗号分隔。"""
        import re as _re
        out = {}
        for m in _re.finditer(r"([A-Za-z_][A-Za-z0-9_]{0,20})\s*[=:：]\s*([^\s,，;；]+)", text or ""):
            k = m.group(1).lower()
            v = m.group(2)
            try:
                v = int(v, 0)
            except Exception:
                pass
            out[k] = v
        return out

    def _rac_start(self):
        desc = self.rac_desc.get("1.0", "end").strip()
        extra = self._parse_extra_params(self.rac_extra.get())
        atts = list(self._rac_attachments)
        topn = int(self.rac_topn.get())
        tmo = int(self.rac_tmo.get())
        deep = bool(self.rac_deep.get())
        if not desc and not atts:
            self._write(self.rac_log, "[!] 请先填写题目描述或添加附件")
            return
        stop = self._stop
        logbox = self.rac_log

        def task():
            pipe = RacPipeline(log_cb=lambda m: self._log(m),
                               timeout_per_script=tmo, top_n=topn,
                               analyze_attachments=deep,
                               cancel_check=stop.is_set)
            res = pipe.run(desc, atts, extra_params=extra)
            for f in res.flags:
                self._flag(f)

        self._start_worker(task, logbox)

    # ------------------------------------------------------------------
    # 子页 2：侦察自动化
    # ------------------------------------------------------------------
    def _build_recon(self, tab):
        theme.notice(tab, "目标格式：IP / 域名 / URL / 网段（≤ /24），每行一个。端口留空则用内置 CTF 高频端口表。"
                          "仅用于已授权靶机。", "warn", wrap=1150, padx=8, pady=(8, 4))
        top = theme.toolbar(tab)
        top.pack(fill="x", padx=8, pady=4)
        ctk.CTkLabel(top, text="目标", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(12, 4))
        self.recon_targets = theme.entry(top, placeholder_text="192.168.56.0/24 或 target.example.com 或 http://1.2.3.4:8080")
        self.recon_targets.pack(side="left", fill="x", expand=True, padx=2, pady=8)
        ctk.CTkLabel(top, text="端口", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(10, 4))
        self.recon_ports = theme.entry(top, width=220, placeholder_text="留空=高频端口表（如 22,80,8000-8100）")
        self.recon_ports.pack(side="left", padx=2, pady=8)

        opts = theme.toolbar(tab)
        opts.pack(fill="x", padx=8, pady=(0, 4))
        self.recon_tcp = theme.checkbox(opts, "TCP 扫描")
        self.recon_tcp.select()
        self.recon_tcp.pack(side="left", padx=(12, 4), pady=7)
        self.recon_http = theme.checkbox(opts, "HTTP 探测")
        self.recon_http.select()
        self.recon_http.pack(side="left", padx=4)
        self.recon_dir = theme.checkbox(opts, "目录探测（慢）")
        self.recon_dir.pack(side="left", padx=4)
        ctk.CTkLabel(opts, text="超时(s)", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(12, 4))
        self.recon_tmo = theme.option_menu(opts, values=["1.0", "1.5", "2.5", "4.0"], width=68)
        self.recon_tmo.set("1.5")
        self.recon_tmo.pack(side="left")
        theme.button(opts, "▶  开始侦察", "danger", width=124, height=28,
                     command=self._recon_start).pack(side="left", padx=(16, 4))
        theme.button(opts, "■ 停止", "ghost", width=82, height=28,
                     command=lambda: self._stop_worker(self.recon_log)).pack(side="left")

        self.recon_log = self._mklogbox(tab)
        self.recon_log.pack(fill="both", expand=True, padx=8, pady=(6, 8))
        self._cur_box = self.recon_log

    def _recon_start(self):
        spec = self.recon_targets.get().strip()
        if not spec:
            self._write(self.recon_log, "[!] 请填写目标")
            return
        ports = self.recon_ports.get().strip()
        do_tcp, do_http, do_dir = (bool(self.recon_tcp.get()),
                                   bool(self.recon_http.get()), bool(self.recon_dir.get()))
        tmo = float(self.recon_tmo.get())
        stop = self._stop
        self._cur_box = self.recon_log

        def task():
            rep = recon.recon_run(spec, ports, do_tcp=do_tcp, do_http=do_http,
                                  do_dir=do_dir, timeout=tmo,
                                  log=lambda m: self._log(m),
                                  cancel_check=stop.is_set)
            txt = recon.report_text(rep)
            self._log("-" * 50)
            for ln in txt.splitlines():
                self._log(ln)

        self._start_worker(task, self.recon_log)

    # ------------------------------------------------------------------
    # 子页 3：远程执行
    # ------------------------------------------------------------------
    def _build_remote(self, tab):
        theme.notice(tab, "主机清单每行一台：host,port,user,password（port 可省）或 "
                          "host,port,user,key=私钥路径,passphrase=xxx。仅用于已授权主机。",
                     "warn", wrap=1150, padx=8, pady=(8, 4))
        top = theme.panel(tab)
        top.pack(fill="both", expand=False, padx=8, pady=4)
        leftc = theme.card(top)
        leftc.pack(side="left", fill="both", expand=True, padx=(0, 8))
        theme.section(leftc, "主机清单", padx=10, pady=(10, 4))
        self.rem_hosts = theme.textbox(leftc, mono_font=True, size=12, height=110, wrap="word")
        self.rem_hosts.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        rightc = theme.card(top)
        rightc.pack(side="left", fill="both", expand=True)
        theme.section(rightc, "要执行的命令", padx=10, pady=(10, 4))
        self.rem_cmd = theme.textbox(rightc, mono_font=True, size=12, height=110, wrap="word")
        self.rem_cmd.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.rem_cmd.insert("1.0", "uname -a && id")

        opts = theme.toolbar(tab)
        opts.pack(fill="x", padx=8, pady=(0, 4))
        ctk.CTkLabel(opts, text="并发", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(12, 4))
        self.rem_conc = theme.option_menu(opts, values=["1", "2", "5", "10", "20"], width=68)
        self.rem_conc.set("5")
        self.rem_conc.pack(side="left")
        ctk.CTkLabel(opts, text="超时(s)", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(12, 4))
        self.rem_tmo = theme.option_menu(opts, values=["15", "30", "60", "120"], width=68)
        self.rem_tmo.set("30")
        self.rem_tmo.pack(side="left")
        theme.button(opts, "▶  批量执行", "danger", width=124, height=28,
                     command=self._remote_start).pack(side="left", padx=(16, 4))
        theme.button(opts, "■ 停止", "ghost", width=82, height=28,
                     command=lambda: self._stop_worker(self.rem_log)).pack(side="left")

        self.rem_log = self._mklogbox(tab)
        self.rem_log.pack(fill="both", expand=True, padx=8, pady=(6, 8))

    def _remote_start(self):
        text = self.rem_hosts.get("1.0", "end").strip()
        cmd = self.rem_cmd.get("1.0", "end").strip()
        if not text or not cmd:
            self._write(self.rem_log, "[!] 请填写主机清单与命令")
            return
        hosts = remoteexec.parse_host_list(text)
        if not hosts:
            self._write(self.rem_log, "[!] 主机清单解析结果为空（检查格式）")
            return
        conc = int(self.rem_conc.get())
        tmo = float(self.rem_tmo.get())
        stop = self._stop
        self._cur_box = self.rem_log

        def task():
            self._log(f"[SSH] 批量执行 {cmd!r} → {len(hosts)} 台主机，并发 {conc}")
            results = remoteexec.run_batch(hosts, cmd, timeout=tmo,
                                           concurrency=conc,
                                           log=lambda m: self._log(m),
                                           cancel_check=stop.is_set)
            self._log("-" * 50)
            for ln in remoteexec.batch_report(results).splitlines():
                self._log(ln)

        self._start_worker(task, self.rem_log)

    # ------------------------------------------------------------------
    # 子页 4：Oracle RAC 巡检
    # ------------------------------------------------------------------
    def _build_oracle(self, tab):
        theme.notice(tab, "Oracle RAC 只读巡检：SSH 连到 RAC 节点执行 crsctl / srvctl / lsnrctl 等只读命令集并汇总报告。"
                          "节点清单格式与「远程执行」页相同（host,port,user,password 或 key=...）。",
                     "info", wrap=1150, padx=8, pady=(8, 4))
        top = theme.toolbar(tab)
        top.pack(fill="x", padx=8, pady=4)
        ctk.CTkLabel(top, text="节点清单", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(12, 4))
        self.orac_hosts = theme.entry(top, placeholder_text="host,port,user,password（可多行，多节点并发巡检）")
        self.orac_hosts.pack(side="left", fill="x", expand=True, padx=2, pady=8)
        ctk.CTkLabel(top, text="DB 名", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(10, 4))
        self.orac_db = theme.entry(top, width=122, placeholder_text="ORCL")
        self.orac_db.insert(0, "ORCL")
        self.orac_db.pack(side="left", padx=(0, 10), pady=8)

        card = theme.card(tab)
        card.pack(fill="x", padx=8, pady=(0, 4))
        grid = theme.panel(card)
        grid.pack(fill="x", padx=10, pady=10)
        self.orac_items = {}
        cols = [
            ("cluster", "集群状态"), ("database", "数据库/实例"),
            ("listener", "监听器"), ("asm", "ASM 存储"),
            ("interconnect", "私有网络"), ("system", "系统负载"),
            ("alertlog", "告警日志扫描"), ("backup", "备份线索"),
        ]
        for i, (key, label) in enumerate(cols):
            cb = theme.checkbox(grid, label)
            self.orac_items[key] = cb
            cb.grid(row=i // 4, column=i % 4, padx=6, pady=4, sticky="w")
            if key in ("cluster", "database", "listener", "system"):
                cb.select()
        theme.button(grid, "全选", "ghost", width=66, height=28,
                     command=lambda: [cb.select() for cb in self.orac_items.values()]).grid(
            row=0, column=4, padx=6)
        theme.button(grid, "▶  开始巡检", "danger", width=116, height=28,
                     command=self._oracle_start).grid(row=1, column=4, padx=6, pady=(4, 0))

        self.orac_log = self._mklogbox(tab)
        self.orac_log.pack(fill="both", expand=True, padx=8, pady=(6, 8))

    def _oracle_start(self):
        text = self.orac_hosts.get().strip()
        if not text:
            self._write(self.orac_log, "[!] 请填写节点清单")
            return
        hosts = remoteexec.parse_host_list(text)
        if not hosts:
            self._write(self.orac_log, "[!] 节点清单解析结果为空")
            return
        items = [k for k, cb in self.orac_items.items() if cb.get()]
        if not items:
            self._write(self.orac_log, "[!] 请至少选择一个巡检项")
            return
        db = self.orac_db.get().strip() or "ORCL"
        stop = self._stop
        self._cur_box = self.orac_log

        def task():
            self._log(f"[Oracle RAC] 巡检项: {', '.join(items)}  DB={db}  节点 {len(hosts)} 个")
            rep = oracle_rac.run_inspection_multi(
                hosts, items, db_name=db, timeout=45.0,
                log=lambda m: self._log(m))
            self._log("-" * 50)
            for ln in rep.splitlines()[:1200]:
                self._log(ln)

        self._start_worker(task, self.orac_log)

    # ------------------------------------------------------------------
    # 子页 5：RPA 会话
    # ------------------------------------------------------------------
    def _build_rpa(self, tab):
        theme.notice(tab, "步骤表驱动 HTTP 会话：自动登录 → 连续请求 → 自动提交 flag。变量占位 {name}；"
                          "响应中的 csrf / token 与 flag 形态串自动提取回填。仅用于已授权靶场。",
                     "warn", wrap=1150, padx=8, pady=(8, 4))
        top = theme.toolbar(tab)
        top.pack(fill="x", padx=8, pady=4)
        ctk.CTkLabel(top, text="Base URL", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(12, 4))
        self.rpa_base = theme.entry(top, placeholder_text="http://target.example.com:8080")
        self.rpa_base.pack(side="left", fill="x", expand=True, padx=2, pady=8)
        ctk.CTkLabel(top, text="变量 JSON", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(10, 4))
        self.rpa_vars = theme.entry(top, width=300, placeholder_text='{"user": "admin", "pass": "xxx"}')
        self.rpa_vars.pack(side="left", padx=(0, 10), pady=8)

        steps_card = theme.card(tab)
        steps_card.pack(fill="x", padx=8, pady=4)
        theme.section(steps_card, "步骤表", "JSON 数组", padx=12, pady=(10, 4))
        self.rpa_steps = theme.textbox(steps_card, mono_font=True, size=12, height=180, wrap="word")
        self.rpa_steps.pack(fill="x", padx=12, pady=(0, 10))
        self.rpa_steps.insert("1.0", json.dumps([
            {"action": "get", "url": "/login.php"},
            {"action": "post", "url": "/login.php",
             "data": {"username": "{user}", "password": "{pass}"}},
            {"action": "submit_flag", "url": "/submit.php", "data": {"flag": "{flag}"},
             "expect_flag": True},
        ], ensure_ascii=False, indent=2))

        btns = theme.panel(tab)
        btns.pack(fill="x", padx=10, pady=(4, 0))
        theme.button(btns, "▶  执行步骤表", "danger", width=124, height=30,
                     command=self._rpa_start).pack(side="left")
        theme.button(btns, "■ 停止", "ghost", width=82, height=30,
                     command=lambda: self._stop_worker(self.rpa_log)).pack(side="left", padx=(8, 0))

        self.rpa_log = self._mklogbox(tab)
        self.rpa_log.pack(fill="both", expand=True, padx=8, pady=(6, 8))

    def _rpa_start(self):
        base = self.rpa_base.get().strip()
        steps_text = self.rpa_steps.get("1.0", "end").strip()
        if not steps_text:
            self._write(self.rpa_log, "[!] 请填写步骤表")
            return
        try:
            steps = rpa.parse_steps(steps_text)
        except Exception as e:
            self._write(self.rpa_log, f"[!] 步骤表 JSON 解析失败: {e}")
            return
        try:
            vars = json.loads(self.rpa_vars.get().strip() or "{}")
        except Exception:
            vars = {}
            self._write(self.rpa_log, "[!] 变量 JSON 解析失败，按空变量执行")
        stop = self._stop
        self._cur_box = self.rpa_log

        def task():
            self._log(f"[RPA] 共 {len(steps)} 步  base={base or '(相对路径模式)'}")
            out = rpa.run_steps(base, steps, vars=vars,
                                log=lambda m: self._log(m),
                                cancel_check=stop.is_set)
            self._log("-" * 50)
            self._log(f"[RPA] 完成。变量: {json.dumps({k: str(v)[:60] for k, v in out['vars'].items()}, ensure_ascii=False)}")
            for f in out["flags"]:
                self._flag(f)

        self._start_worker(task, self.rpa_log)
