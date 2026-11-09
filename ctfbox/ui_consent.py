# -*- coding: utf-8 -*-
"""启动前的唯一闸门：软件责任说明。

必须逐条阅读并勾选同意才能进入主界面；拒绝或关闭直接退出。
不再按功能重复弹窗，责任与授权边界统一写在本说明中。
"""
import tkinter as tk

try:                                   # 版本号单一来源，禁止在此硬编码
    from .versioning import version_tag as _version_tag
    _FALLBACK_VERSION = _version_tag()
except Exception:                      # pragma: no cover
    _FALLBACK_VERSION = "v4.1.0"

try:
    from . import ui_theme as theme
except Exception:      # 极端情况（customtkinter 缺失）下仍要能弹出说明窗
    class _FallbackTheme:
        APP_NAME = "魔盒-CTF"
        APP_VERSION = _FALLBACK_VERSION
        BG_WINDOW = "#0d1117"
        BG_SURFACE = "#151b24"
        BG_SURFACE_2 = "#1a212c"
        BG_SURFACE_3 = "#222b38"
        BG_EDITOR = "#0b0f14"
        BORDER_SOFT = "#212a35"
        TEXT = "#e6edf3"
        TEXT_DIM = "#a8b6c6"
        TEXT_MUTE = "#7b8a9d"
        TEXT_DISABLED = "#5b6877"
        ACCENT = "#4c8dff"
        ACCENT_HOVER = "#6aa1ff"
        ACCENT_SOFT = "#1b2a44"
        INFO = "#6cb6ff"
        WARNING = "#e6a23c"
        DANGER = "#e5534b"
        DANGER_SOFT = "#2d1817"

        @staticmethod
        def ui_family_safe():
            return "Microsoft YaHei UI"

    theme = _FallbackTheme()


USAGE_TEXT = """魔盒-CTF 使用说明（摘要）

一、进入软件
启动时展示《软件责任说明》，必须勾选同意才能进入；不同意或关闭窗口直接退出。
责任说明是软件唯一的进入闸门，功能页不再重复询问授权。

二、一键梭哈
输入本地文件或 http(s):// 地址即可运行。文件模式按首层判型选择分析阶段与脚本；
Web 模式先做指纹与入口发现，按证据选择利用阶段。未知二进制默认只做静态分析。
结果、证据链与 WP 写入 workspace/tasks 的独立任务目录。

三、Web 检测与利用
Web 页提供请求记录、目录、源码泄露、SQLMap、XSS、深度全自动等步骤；
一键梭哈可启用 Web 利用模块，覆盖注入、上传、反序列化、SSRF/XXE/LFI、
XSS/CSRF/Cookie、JWT/IDOR/弱口令等验证。每个请求写入审计，
payload 只保存摘要；上传验证样本只写入任务 artifacts。

四、赛事专项与平台闭环
赛事专项覆盖内存取证、流量分析、APK、源码审计、安全基线、日志时间线、攻防验证；
平台闭环可登录 CTF 平台、开启实例、一键梭哈并提交 flag，输出固定格式 WP。

五、RAC 自动化
题目流水线自动识别题型、匹配脚本库并填参执行；侦察自动化可做端口/HTTP/目录探测；
远程执行与 Oracle 巡检通过 SSH 执行你配置的命令；RPA 按 JSON 步骤驱动 HTTP 会话。

六、工具与脚本
随包工具在“工具中心”管理；脚本库按白名单登记，一键梭哈与 RAC 会自动调用。
第三方工具各自遵循其许可证；外部工具需要自行配置可信发行包。

七、数据与排错
任务数据、日志与证据保存在 workspace；报告导出到 reports。
失败详情见界面日志与 workspace 任务目录；闪退记录见 workspace/crash.log。
"""


class ConsentDialog(tk.Tk):
    """启动前的软件责任说明窗。视觉与主界面共用一套深色令牌。"""

    def __init__(self):
        super().__init__()
        self.accepted = False
        self.title(f"{theme.APP_NAME} · 软件责任说明")
        self.geometry("780x620")
        self.resizable(False, False)
        self.configure(bg=theme.BG_WINDOW)
        self.protocol("WM_DELETE_WINDOW", self.reject)

        accent = tk.Frame(self, bg=theme.WARNING, height=3)
        accent.pack(fill="x")

        wrap = tk.Frame(self, bg=theme.BG_WINDOW)
        wrap.pack(fill="both", expand=True, padx=30, pady=(18, 16))

        head = tk.Frame(wrap, bg=theme.BG_WINDOW)
        head.pack(fill="x")
        tk.Label(head, text="软件责任说明", font=(theme.ui_family_safe(), 20, "bold"),
                 bg=theme.BG_WINDOW, fg=theme.TEXT).pack(side="left")
        tk.Label(head, text=theme.APP_VERSION, font=(theme.ui_family_safe(), 10),
                 bg=theme.ACCENT_SOFT, fg=theme.INFO, padx=6, pady=1).pack(side="left", padx=(10, 0))
        tk.Label(wrap, text="请逐条阅读；不同意将无法进入软件。", font=(theme.ui_family_safe(), 11),
                 bg=theme.BG_WINDOW, fg=theme.TEXT_MUTE).pack(anchor="w", pady=(4, 10))

        from tkinter.scrolledtext import ScrolledText
        from . import responsibility
        # height 必须显式收小：默认 24 行会把勾选框与按钮挤出 620 高的窗口，
        # 用户将无法同意进入；文本区靠 expand 自动占满剩余空间。
        text = ScrolledText(wrap, wrap="word", height=12, font=(theme.ui_family_safe(), 11),
                            bg=theme.BG_EDITOR, fg=theme.TEXT_DIM, insertbackground=theme.TEXT,
                            bd=0, highlightthickness=1, highlightbackground=theme.BORDER_SOFT,
                            padx=16, pady=14)
        text.pack(fill="both", expand=True)
        text.insert("1.0", responsibility.RESPONSIBILITY_TEXT)
        text.configure(state="disabled")

        self.confirmed = tk.BooleanVar(value=False)
        self.checkbox = tk.Checkbutton(
            wrap, variable=self.confirmed,
            text="我已逐条阅读并同意《软件责任说明》，对使用行为承担全部责任",
            command=self._update_state,
            bg=theme.BG_WINDOW, fg=theme.TEXT, selectcolor=theme.BG_SURFACE_2,
            activebackground=theme.BG_WINDOW, activeforeground=theme.TEXT,
            highlightthickness=0, bd=0, anchor="w",
            font=(theme.ui_family_safe(), 11))
        self.checkbox.pack(anchor="w", pady=(12, 4))

        buttons = tk.Frame(wrap, bg=theme.BG_WINDOW)
        buttons.pack(fill="x", pady=(10, 0))
        self.accept_button = self._button(buttons, "同意并进入", self.accept, "primary", 16)
        self.accept_button.configure(state="disabled")
        self.accept_button.pack(side="right")
        self._button(buttons, "拒绝并退出", self.reject, "danger", 12).pack(side="left")
        self._button(buttons, "阅读使用说明", self.show_usage, "ghost", 12).pack(side="left", padx=8)

        tk.Label(wrap, text="确认记录保存在本机 workspace/config/responsibility.json；"
                            "拒绝或关闭窗口将直接退出。",
                 font=(theme.ui_family_safe(), 9), bg=theme.BG_WINDOW,
                 fg=theme.TEXT_MUTE).pack(anchor="w", pady=(12, 0))
        self.bind("<Escape>", lambda event: self.reject())

    @staticmethod
    def _button(parent, text, command, kind="ghost", width=12):
        palette = {
            "primary": (theme.ACCENT, theme.ACCENT_HOVER, "#ffffff"),
            "danger": (theme.BG_SURFACE_2, theme.DANGER_SOFT, theme.DANGER),
            "ghost": (theme.BG_SURFACE_2, theme.BG_SURFACE_3, theme.TEXT_DIM),
        }
        bg, active_bg, fg = palette.get(kind, palette["ghost"])
        return tk.Button(parent, text=text, command=command, width=width,
                         font=(theme.ui_family_safe(), 11), bd=0, relief="flat",
                         cursor="hand2", padx=12, pady=6,
                         bg=bg, fg=fg, activebackground=active_bg,
                         activeforeground=theme.TEXT if kind != "danger" else "#ffffff",
                         disabledforeground=theme.TEXT_DISABLED)

    def show_usage(self):
        if getattr(self, "usage_window", None) and self.usage_window.winfo_exists():
            self.usage_window.focus()
            return
        from tkinter.scrolledtext import ScrolledText
        window = self.usage_window = tk.Toplevel(self)
        window.title("魔盒-CTF 使用说明")
        window.geometry("860x640")
        window.transient(self)
        window.configure(bg=theme.BG_WINDOW)
        tk.Label(window, text="魔盒-CTF 使用说明", font=(theme.ui_family_safe(), 14, "bold"),
                 bg=theme.BG_WINDOW, fg=theme.TEXT).pack(anchor="w", padx=16, pady=(14, 6))
        text = ScrolledText(window, wrap="word", font=(theme.ui_family_safe(), 11),
                            bg=theme.BG_EDITOR, fg=theme.TEXT, insertbackground=theme.TEXT,
                            bd=0, highlightthickness=1, highlightbackground=theme.BORDER_SOFT,
                            padx=16, pady=14)
        text.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        text.insert("1.0", USAGE_TEXT)
        text.configure(state="disabled")

    def _update_state(self):
        enabled = bool(self.confirmed.get())
        self.accept_button.configure(
            state="normal" if enabled else "disabled",
            bg=theme.ACCENT if enabled else theme.BG_SURFACE_2,
            activebackground=theme.ACCENT_HOVER,
            fg="#ffffff" if enabled else theme.TEXT_DISABLED)

    def accept(self):
        if not self.confirmed.get():
            return
        from . import responsibility
        responsibility.accept("gui", "启动责任说明勾选确认")
        self.accepted = True
        self.destroy()

    def reject(self):
        self.accepted = False
        self.destroy()


def confirm_ctf_use():
    """保留旧函数名供启动入口调用；实际语义为责任说明确认。"""
    dialog = ConsentDialog()
    dialog.mainloop()
    return dialog.accepted
