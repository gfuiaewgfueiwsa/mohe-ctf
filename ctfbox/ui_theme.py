# -*- coding: utf-8 -*-
"""CTFToolbox 统一视觉主题（v2.4 界面美化用）。

原先配色、字号、圆角散落在 ui_main / ui_web / ui_media / ui_rac / ui_scripts /
ui_ssh / ui_consent 各页面里，同一语义（危险、成功、提示）在不同页面颜色不一致，
字号也有 11/12/13/14/15/16 多种来源。本模块把这些收拢成一套令牌，并提供常用
控件的工厂函数，页面只描述结构、不再重复写样式。

约束：仍使用 customtkinter（tkinter 之上的既有技术栈），不引入第三方 UI 库，
不联网拉字体；字体族按本机已安装字体择优回退。
"""
import customtkinter as ctk

# ======================================================================
# 颜色令牌
# ======================================================================
BG_WINDOW = "#0d1117"      # 主窗口底色
BG_SURFACE = "#151b24"     # 卡片 / 面板
BG_SURFACE_2 = "#1a212c"   # 输入框、工具条、次级容器
BG_SURFACE_3 = "#222b38"   # 悬停 / 选中
BG_EDITOR = "#0b0f14"      # 代码、日志、报告阅读区
BORDER = "#2a3441"
BORDER_SOFT = "#212a35"

TEXT = "#e6edf3"
TEXT_DIM = "#a8b6c6"
TEXT_MUTE = "#7b8a9d"
TEXT_DISABLED = "#5b6877"

ACCENT = "#4c8dff"
ACCENT_HOVER = "#6aa1ff"
ACCENT_SOFT = "#1b2a44"

SUCCESS = "#3ecf8e"
SUCCESS_HOVER = "#34b57c"
SUCCESS_SOFT = "#14291f"

WARNING = "#e6a23c"
WARNING_HOVER = "#c98a2c"
WARNING_SOFT = "#2b2115"

DANGER = "#e5534b"
DANGER_HOVER = "#c9433c"
DANGER_SOFT = "#2d1817"

INFO = "#6cb6ff"

# 报告 / 日志文字分级（tag 只能改颜色，字号由文本框统一）
TAGS = {
    "flag": "#ff7b72",
    "flag_d": "#ffaba6",
    "ok": "#4ade80",
    "ok_d": "#a7f3c0",
    "warn": "#f0b429",
    "warn_d": "#ffd888",
    "info": "#c9d4e2",
    "info_d": "#9fb0c2",
    "tool": "#7cc4ff",
    "title": "#7cc4ff",
    "dim": TEXT_MUTE,
}

# ======================================================================
# 尺寸令牌
# ======================================================================
RADIUS_CARD = 12
RADIUS_CTRL = 8
RADIUS_SMALL = 6

PAD_XS = 4
PAD_S = 8
PAD_M = 12
PAD_L = 16

HEADER_H = 30        # 常规按钮 / 输入框高度
ROW_H = 32           # 工具条行高
FONT_BODY = 12
FONT_SMALL = 11
FONT_TITLE = 14
FONT_H1 = 18

APP_NAME = "魔盒-ctf"
APP_VERSION = "v2.4"
APP_SUBTITLE = "万能 CTF 集合工具箱 · 附件分析 / 编码解码 / 隐写取证 / Web · Pwn / 自动化"

# ======================================================================
# 字体：按本机可用字体择优，避免缺字时回退成方框
# ======================================================================
_UI_CANDIDATES = ("Microsoft YaHei UI", "Microsoft YaHei", "微软雅黑",
                  "PingFang SC", "Noto Sans CJK SC", "Source Han Sans SC",
                  "Segoe UI", "Arial")
_MONO_CANDIDATES = ("Cascadia Mono", "Consolas", "JetBrains Mono",
                    "Source Code Pro", "DejaVu Sans Mono", "Courier New")

_cache = {"root": None, "ui": None, "mono": None, "fonts": {}, "mono_fonts": {}}


def _root_key():
    """字体对象绑定 Tk 根，根重建（确认框 -> 主窗口）后必须重建缓存。"""
    try:
        import tkinter as _tk
        root = _tk._default_root
        return id(root) if root is not None else None
    except Exception:
        return None


def _ensure_cache():
    key = _root_key()
    if _cache["root"] != key:
        _cache.update(root=key, ui=None, mono=None, fonts={}, mono_fonts={})


def _pick_family(candidates):
    try:
        import tkinter.font as tkfont
        installed = set(tkfont.families())
    except Exception:
        return candidates[0]
    for name in candidates:
        if name in installed:
            return name
    return candidates[0]


def ui_family():
    _ensure_cache()
    if not _cache["ui"]:
        _cache["ui"] = _pick_family(_UI_CANDIDATES)
    return _cache["ui"]


def mono_family():
    _ensure_cache()
    if not _cache["mono"]:
        _cache["mono"] = _pick_family(_MONO_CANDIDATES)
    return _cache["mono"]


def ui_family_safe():
    """给原生 tkinter 控件（Label/Button/Checkbutton）用的字体族名，取不到时回退首选。"""
    try:
        return ui_family()
    except Exception:
        return _UI_CANDIDATES[0]


def font(size=FONT_BODY, weight="normal"):
    """界面字体（缓存复用，避免同一字号反复创建 Tk 字体对象）。"""
    _ensure_cache()
    key = (size, weight)
    cached = _cache["fonts"].get(key)
    if cached is None:
        cached = ctk.CTkFont(family=ui_family(), size=size, weight=weight)
        _cache["fonts"][key] = cached
    return cached


def mono(size=FONT_BODY, weight="normal"):
    """等宽字体：代码、日志、哈希等需要对齐的内容。"""
    _ensure_cache()
    key = (size, weight)
    cached = _cache["mono_fonts"].get(key)
    if cached is None:
        cached = ctk.CTkFont(family=mono_family(), size=size, weight=weight)
        _cache["mono_fonts"][key] = cached
    return cached


# ======================================================================
# 初始化
# ======================================================================
def init(root=None):
    """设置外观模式与根窗口底色；应在 Tk 根创建之后调用一次。"""
    try:
        ctk.set_appearance_mode("dark")
    except Exception:
        pass
    if root is not None:
        apply_root(root)


def apply_root(root):
    try:
        root.configure(fg_color=BG_WINDOW)
    except Exception:
        pass


# ======================================================================
# 容器
# ======================================================================
def panel(master, **kw):
    """无色容器：只负责布局分组，不画背景。"""
    kw.setdefault("fg_color", "transparent")
    return ctk.CTkFrame(master, **kw)


def card(master, **kw):
    """带描边的卡片：一个功能区块。"""
    kw.setdefault("fg_color", BG_SURFACE)
    kw.setdefault("corner_radius", RADIUS_CARD)
    kw.setdefault("border_width", 1)
    kw.setdefault("border_color", BORDER_SOFT)
    return ctk.CTkFrame(master, **kw)


def toolbar(master, **kw):
    """工具条：比卡片浅一层的次级容器。"""
    kw.setdefault("fg_color", BG_SURFACE_2)
    kw.setdefault("corner_radius", RADIUS_CTRL)
    kw.setdefault("border_width", 1)
    kw.setdefault("border_color", BORDER_SOFT)
    return ctk.CTkFrame(master, **kw)


def scroll(master, **kw):
    kw.setdefault("fg_color", "transparent")
    kw.setdefault("corner_radius", RADIUS_CTRL)
    kw.setdefault("scrollbar_button_color", BORDER)
    kw.setdefault("scrollbar_button_hover_color", BG_SURFACE_3)
    return ctk.CTkScrollableFrame(master, **kw)


def divider(master, pady=(PAD_S, PAD_S)):
    line = ctk.CTkFrame(master, height=1, fg_color=BORDER_SOFT, corner_radius=0)
    line.pack(fill="x", pady=pady)
    return line


def section(master, title, hint=None, **pack_kw):
    """分区标题：左侧强调竖条 + 标题，右侧可选说明。"""
    row = panel(master)
    row.pack(fill="x", **pack_kw)
    mark = ctk.CTkFrame(row, width=3, height=15, fg_color=ACCENT, corner_radius=2)
    mark.pack(side="left", padx=(0, PAD_S))
    mark.pack_propagate(False)
    ctk.CTkLabel(row, text=title, font=font(FONT_TITLE, "bold"),
                 text_color=TEXT, anchor="w").pack(side="left")
    if hint:
        ctk.CTkLabel(row, text=hint, font=font(FONT_SMALL),
                     text_color=TEXT_MUTE, anchor="e").pack(side="right")
    return row


def toolbar_label(master, text):
    return ctk.CTkLabel(master, text=text, font=font(FONT_SMALL),
                        text_color=TEXT_MUTE, anchor="w")


def field_label(master, text, hint_text=None, **pack_kw):
    """输入区标题：主标题 + 灰色补注，减少“输入（……）”这种长句噪音。"""
    row = panel(master)
    pack_kw.setdefault("fill", "x")
    pack_kw.setdefault("padx", PAD_L)
    pack_kw.setdefault("pady", (PAD_S, PAD_XS))
    row.pack(**pack_kw)
    ctk.CTkLabel(row, text=text, font=font(FONT_BODY, "bold"),
                 text_color=TEXT_DIM, anchor="w").pack(side="left")
    if hint_text:
        ctk.CTkLabel(row, text="  " + hint_text, font=font(FONT_SMALL),
                     text_color=TEXT_MUTE, anchor="w").pack(side="left")
    return row


def hint(master, text, wrap=0, color=TEXT_MUTE, **pack_kw):
    label = ctk.CTkLabel(master, text=text, font=font(FONT_SMALL), text_color=color,
                         anchor="w", justify="left", wraplength=wrap)
    if "side" in pack_kw:
        label.pack(**pack_kw)
    else:
        pack_kw.setdefault("fill", "x")
        label.pack(**pack_kw)
    return label


def notice(master, text, kind="warn", wrap=0, **pack_kw):
    """整行提示条：左侧彩色竖条 + 文案，避免把警示写成普通 Label 混在按钮里。"""
    colors = {"warn": (WARNING, WARNING_SOFT),
              "danger": (DANGER, DANGER_SOFT),
              "info": (ACCENT, ACCENT_SOFT),
              "ok": (SUCCESS, SUCCESS_SOFT)}
    accent, soft = colors.get(kind, colors["info"])
    box = ctk.CTkFrame(master, fg_color=soft, corner_radius=RADIUS_CTRL,
                       border_width=1, border_color=BORDER_SOFT)
    pack_kw.setdefault("fill", "x")
    box.pack(**pack_kw)
    bar = ctk.CTkFrame(box, width=3, height=1, fg_color=accent, corner_radius=2)
    bar.pack(side="left", fill="y", padx=(0, PAD_S))
    bar.pack_propagate(False)
    ctk.CTkLabel(box, text=text, font=font(FONT_SMALL), text_color=TEXT_DIM,
                 anchor="w", justify="left", wraplength=wrap).pack(
        side="left", fill="x", expand=True, padx=(0, PAD_M), pady=6)
    return box


def chip(master, text, kind="info"):
    """状态胶囊：就绪 / 运行中 / 未连接等短状态。"""
    colors = {"ok": (SUCCESS, SUCCESS_SOFT), "warn": (WARNING, WARNING_SOFT),
              "danger": (DANGER, DANGER_SOFT), "info": (INFO, ACCENT_SOFT),
              "mute": (TEXT_MUTE, BG_SURFACE_2)}
    fg, bg = colors.get(kind, colors["info"])
    return ctk.CTkLabel(master, text=text, font=font(FONT_SMALL),
                        text_color=fg, fg_color=bg, corner_radius=10,
                        padx=8, height=20)


# ======================================================================
# 控件
# ======================================================================
_BUTTON_KINDS = {
    "primary": (ACCENT, ACCENT_HOVER, "#ffffff", BORDER_SOFT),
    "success": (SUCCESS, SUCCESS_HOVER, "#08130d", BORDER_SOFT),
    "warn": (WARNING, WARNING_HOVER, "#1a1206", BORDER_SOFT),
    "danger": (DANGER, DANGER_HOVER, "#ffffff", BORDER_SOFT),
    "subtle": (BG_SURFACE_2, BG_SURFACE_3, TEXT, BORDER),
    "ghost": ("transparent", BG_SURFACE_3, TEXT_DIM, BORDER_SOFT),
}


def button(master, text, kind="subtle", **kw):
    fg, hover, tcolor, border = _BUTTON_KINDS.get(kind, _BUTTON_KINDS["subtle"])
    kw.setdefault("height", HEADER_H)
    kw.setdefault("corner_radius", RADIUS_CTRL)
    kw.setdefault("font", font(FONT_BODY))
    kw.setdefault("text_color", tcolor)
    kw.setdefault("fg_color", fg)
    kw.setdefault("hover_color", hover)
    kw.setdefault("border_width", 1 if border else 0)
    kw.setdefault("border_color", border)
    return ctk.CTkButton(master, text=text, **kw)


def entry(master, **kw):
    kw.setdefault("height", HEADER_H)
    kw.setdefault("corner_radius", RADIUS_CTRL)
    kw.setdefault("fg_color", BG_SURFACE_2)
    kw.setdefault("border_color", BORDER)
    kw.setdefault("text_color", TEXT)
    kw.setdefault("placeholder_text_color", TEXT_MUTE)
    kw.setdefault("font", font(FONT_BODY))
    return ctk.CTkEntry(master, **kw)


def option_menu(master, values, **kw):
    kw.setdefault("height", HEADER_H)
    kw.setdefault("corner_radius", RADIUS_CTRL)
    kw.setdefault("fg_color", BG_SURFACE_2)
    kw.setdefault("button_color", BG_SURFACE_3)
    kw.setdefault("button_hover_color", BORDER)
    kw.setdefault("text_color", TEXT)
    kw.setdefault("dropdown_fg_color", BG_SURFACE)
    kw.setdefault("dropdown_hover_color", BG_SURFACE_3)
    kw.setdefault("dropdown_text_color", TEXT)
    kw.setdefault("font", font(FONT_BODY))
    kw.setdefault("dropdown_font", font(FONT_BODY))
    return ctk.CTkOptionMenu(master, values=values, **kw)


def checkbox(master, text, variable=None, **kw):
    kw.setdefault("font", font(FONT_BODY))
    kw.setdefault("text_color", TEXT_DIM)
    kw.setdefault("fg_color", ACCENT)
    kw.setdefault("hover_color", ACCENT_HOVER)
    kw.setdefault("border_color", BORDER)
    kw.setdefault("checkmark_color", "#ffffff")
    kw.setdefault("checkbox_width", 18)
    kw.setdefault("checkbox_height", 18)
    return ctk.CTkCheckBox(master, text=text, variable=variable, **kw)


def switch(master, text, **kw):
    kw.setdefault("font", font(FONT_SMALL))
    kw.setdefault("text_color", TEXT_DIM)
    kw.setdefault("progress_color", ACCENT)
    kw.setdefault("button_color", ACCENT)
    kw.setdefault("button_hover_color", ACCENT_HOVER)
    return ctk.CTkSwitch(master, text=text, **kw)


def textbox(master, mono_font=False, size=FONT_BODY, **kw):
    kw.setdefault("corner_radius", RADIUS_CTRL)
    kw.setdefault("border_width", 1)
    kw.setdefault("border_color", BORDER_SOFT)
    kw.setdefault("fg_color", BG_EDITOR)
    kw.setdefault("text_color", TEXT)
    kw.setdefault("scrollbar_button_color", BORDER)
    kw.setdefault("scrollbar_button_hover_color", BG_SURFACE_3)
    if mono_font:
        kw.setdefault("font", mono(size))
    else:
        kw.setdefault("font", font(size))
    return ctk.CTkTextbox(master, **kw)


def progress(master, **kw):
    kw.setdefault("height", 4)
    kw.setdefault("corner_radius", 2)
    kw.setdefault("fg_color", BG_SURFACE_2)
    kw.setdefault("progress_color", ACCENT)
    return ctk.CTkProgressBar(master, **kw)


def tabview(master, **kw):
    """标签页：选中页用强调色，未选中页融进面板底色。"""
    kw.setdefault("fg_color", BG_SURFACE)
    kw.setdefault("border_width", 0)
    kw.setdefault("border_color", BORDER_SOFT)
    kw.setdefault("corner_radius", RADIUS_CARD)
    kw.setdefault("anchor", "w")            # 标签从左侧起排，避免长条居中留白
    kw.setdefault("segmented_button_fg_color", BG_SURFACE_2)
    kw.setdefault("segmented_button_selected_color", ACCENT)
    kw.setdefault("segmented_button_selected_hover_color", ACCENT_HOVER)
    kw.setdefault("segmented_button_unselected_color", BG_SURFACE_2)
    kw.setdefault("segmented_button_unselected_hover_color", BG_SURFACE_3)
    kw.setdefault("segmented_button_font", font(FONT_BODY))
    kw.setdefault("text_color", TEXT)
    return ctk.CTkTabview(master, **kw)


# ======================================================================
# 文本框 tag
# ======================================================================
def apply_tags(box):
    """统一报告/日志里的等级配色；tag 不支持 font（与缩放冲突），只设颜色。"""
    for name, color in TAGS.items():
        try:
            box.tag_config(name, foreground=color)
        except Exception:
            pass
