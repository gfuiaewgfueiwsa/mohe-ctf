import tkinter as tk

try:
    from . import ui_theme as theme
except Exception:      # 极端情况（customtkinter 缺失）下仍要能弹出确认窗
    class _FallbackTheme:
        APP_NAME = "魔盒-ctf"
        APP_VERSION = "v2.5"
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


USAGE_TEXT = """魔盒-ctf 使用说明

一、使用范围
本软件仅用于 CTF 比赛中已获明确授权的题目和靶机。每次启动均需主动勾选确认；关闭或拒绝即退出。确认不等于获得目标授权，不得测试未授权网站。

二、附件分析
将文件拖入主窗口，或选择文件后开始分析。支持中文路径和多文件排队；分析中再次拖入会追加，不覆盖正在处理的队列。文件分析在独立进程中进行，单个文件默认最多 300 秒；停止会结束该任务及其子进程，清空待处理队列，清理完成后可重新开始。异常文件不会作为程序执行。第三方解析器不是安全沙箱，未知附件仍建议在隔离环境中处理。
结果可导出到软件旁的 reports 目录；解包及中间文件在 workspace。不要直接运行来源不明的提取文件。大报告在界面限量显示，导出报告保留完整结果。

三、Web CTF 顺序检测
填写完整的 HTTP/HTTPS 题目网址，勾选“此目标是本次 CTF 授权靶机”，点击“开始测试”。默认依次进行 HTTP 请求记录、少量常见目录探测、Git 源码泄露线索、SQLMap 检测、XSS 反射线索。可取消不需要的步骤；SQLMap/XSS 需要带查询参数的页面，仅填写首页可能跳过，不代表没有漏洞。
任务逐项执行，每步最多 180 秒，可随时停止。缺少工具、无适用参数、超时和工具失败会明确记录，不会当作检测通过；“已执行”仅表示工具执行完成。JSON 报告保存在 reports。自动流程不整站爬取、不跟随重定向、不读取数据库内容、不执行系统命令，也不自动上传或连接 WebShell。
HTTP 步骤将本次 GET 请求与最多 64 KiB 响应导出为 HAR，可导入浏览器 Network 或兼容分析工具；不拦截浏览器其它流量，不等于系统实时抓包。响应 Cookie 脱敏，但网址和正文仍可能含题目凭据，报告只应保存在本机。
目录引擎可选内置、dirsearch 或 ffuf，使用小词表和限速。Git 只检查 .git/HEAD，不自动下载仓库。内置 XSS 只检测前五个参数是否反射未转义标记，不执行脚本，反射不等于可利用 XSS；深入确认请使用 XSStrike 或浏览器。

四、RAC 自动化（v2.4 新增）
"RAC 自动化"页提供五类自动化能力，全部只针对已授权目标：
题目流水线：粘贴题目描述与已知参数（n/e/c、host:port、哈希、密文等，自动识别），可选添加附件，软件自动判题型、从随包脚本库评分匹配脚本、自动填参、静默执行并在运行时提取 flag；未命中会保留完整过程与手动跟进建议，产物在 workspace/rac_runs。
侦察自动化：对授权靶机批量做 TCP 端口扫描、HTTP 探测（状态码/Server/标题）与目录探测；会对目标发起真实网络请求。
远程执行：按主机清单（host,port,user,password 或 key=私钥路径）批量 SSH 执行命令，请确认清单内均为授权主机。
Oracle RAC 巡检：SSH 连接 RAC 节点执行 crsctl/srvctl/lsnrctl 等只读巡检命令集并汇总报告，不修改任何集群或数据库状态。
RPA 会话：用 JSON 步骤表驱动 HTTP 会话（自动登录、连续请求、自动提交 flag），只执行你自己配置的步骤，不自动发现攻击面。

五、工具集成与限制
在 Web 页的工具管理中查看状态，选择本机工具入口文件（.py/.exe/.jar 等），再运行检测或打开手动工具。未配置不等于已安装；本软件不会偷偷下载或执行外部工具，Python 脚本所需依赖由工具环境提供。
SQLMap、dirsearch、ffuf：支持在授权单目标工作流中调用；XSStrike：手动专项入口，其原生 CLI 无可靠的禁止重定向开关，不纳入自动队列。
Burp Suite 社区版：手动代理、拦截和重放；社区版不包含专业版自动漏洞扫描器。浏览器代理、证书和 Burp Scope 需自行设置。
浏览器开发者工具：在浏览器按 F12 查看源码、JS、Cookie、网络；HackBar 是浏览器插件，需在浏览器中安装和使用，不能假装成桌面自动扫描器。
“JWT 离线解析”可直接解码题目令牌，不发网络请求、不保存令牌，也不验证签名。JWT_Tool 攻击需令牌与额外参数；SSRFmap 需请求文件、注入参数和模块；GitHack 需先确认源码泄露：这些保留为手动专项操作，不能仅凭一个网址自动利用。
“图片马 / 流量附件分析”选择本地图片或 pcap 等文件，转到已有的一键分析链进行只读检查，包括图片尾部脚本、元数据和 WebShell 通信特征；不生成或上传图片马。
AntSword：自备正版/可信发行包，在确认题目允许后手动连接；自动队列不上传或操作 WebShell。
CyberChef：优先打开本地离线镜像。file、binwalk、strings、ExifTool：用于附件识别、字符串和元数据分析，依赖可用的外部工具环境。

六、排错
闪退记录见 workspace/crash.log；文件分析失败和 Web 子进程退出码见界面日志。停止期间请等待“已停止/完成”后重试。Windows 下若从资源管理器无法拖入，请检查软件是否以管理员身份运行（普通资源管理器无法拖入高权限窗口）。
"""


class ConsentDialog(tk.Tk):
    """启动前的使用范围确认窗。视觉与主界面共用一套深色令牌。"""

    def __init__(self):
        super().__init__()
        self.accepted = False
        self.title(f"{theme.APP_NAME} · CTF 使用确认")
        self.geometry("700x470")
        self.resizable(False, False)
        self.configure(bg=theme.BG_WINDOW)
        self.protocol("WM_DELETE_WINDOW", self.reject)

        accent = tk.Frame(self, bg=theme.ACCENT, height=3)
        accent.pack(fill="x")

        wrap = tk.Frame(self, bg=theme.BG_WINDOW)
        wrap.pack(fill="both", expand=True, padx=32, pady=(22, 20))

        head = tk.Frame(wrap, bg=theme.BG_WINDOW)
        head.pack(fill="x")
        tk.Label(head, text="仅限 CTF 比赛使用", font=(theme.ui_family_safe(), 20, "bold"),
                 bg=theme.BG_WINDOW, fg=theme.TEXT).pack(side="left")
        tk.Label(head, text=theme.APP_VERSION, font=(theme.ui_family_safe(), 10),
                 bg=theme.ACCENT_SOFT, fg=theme.INFO, padx=6, pady=1).pack(side="left", padx=(10, 0))
        tk.Label(wrap, text="请在进入软件前阅读并确认使用范围", font=(theme.ui_family_safe(), 11),
                 bg=theme.BG_WINDOW, fg=theme.TEXT_MUTE).pack(anchor="w", pady=(4, 14))

        card = tk.Frame(wrap, bg=theme.BG_SURFACE, highlightthickness=1,
                        highlightbackground=theme.BORDER_SOFT)
        card.pack(fill="x")
        tk.Frame(card, bg=theme.WARNING, width=3, height=120).pack(side="left", fill="y")
        rules = tk.Frame(card, bg=theme.BG_SURFACE)
        rules.pack(side="left", fill="both", expand=True, padx=16, pady=14)
        for line in ("仅测试 CTF 比赛中明确授权给你的题目和靶机。",
                     "不得对未授权网站扫描、攻击或获取数据。",
                     "自动工具只提供线索，不保证发现漏洞或 flag。",
                     "软件内提供使用说明；外部工具需自行配置可信发行包。"):
            row = tk.Frame(rules, bg=theme.BG_SURFACE)
            row.pack(anchor="w", pady=3)
            tk.Label(row, text="·", font=(theme.ui_family_safe(), 11, "bold"),
                     bg=theme.BG_SURFACE, fg=theme.WARNING).pack(side="left", padx=(0, 6))
            tk.Label(row, text=line, font=(theme.ui_family_safe(), 11),
                     bg=theme.BG_SURFACE, fg=theme.TEXT_DIM).pack(side="left")

        self.confirmed = tk.BooleanVar(value=False)
        self.checkbox = tk.Checkbutton(
            wrap, variable=self.confirmed,
            text="我确认：仅在 CTF 比赛授权范围内使用本软件",
            command=self._update_state,
            bg=theme.BG_WINDOW, fg=theme.TEXT, selectcolor=theme.BG_SURFACE_2,
            activebackground=theme.BG_WINDOW, activeforeground=theme.TEXT,
            highlightthickness=0, bd=0, anchor="w",
            font=(theme.ui_family_safe(), 11))
        self.checkbox.pack(anchor="w", pady=(14, 6))

        buttons = tk.Frame(wrap, bg=theme.BG_WINDOW)
        buttons.pack(fill="x", pady=(10, 0))
        self.accept_button = self._button(buttons, "确认并进入", self.accept, "primary", 16)
        self.accept_button.configure(state="disabled")
        self.accept_button.pack(side="right")
        self._button(buttons, "拒绝并退出", self.reject, "danger", 12).pack(side="left")
        self._button(buttons, "阅读完整说明", self.show_usage, "ghost", 12).pack(side="left", padx=8)

        tk.Label(wrap, text="确认不等于获得目标授权；拒绝或关闭窗口将直接退出。",
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
        window.title("魔盒-ctf 使用说明")
        window.geometry("860x640")
        window.transient(self)
        window.configure(bg=theme.BG_WINDOW)
        tk.Label(window, text="魔盒-ctf 使用说明", font=(theme.ui_family_safe(), 14, "bold"),
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
        if self.confirmed.get():
            self.accepted = True
            self.destroy()

    def reject(self):
        self.accepted = False
        self.destroy()


def confirm_ctf_use():
    dialog = ConsentDialog()
    dialog.mainloop()
    return dialog.accepted
