# -*- coding: utf-8 -*-
"""脚本库标签页：按方向分类展示内置 CTF 脚本，支持搜索、查看、复制、另存与自测。

脚本以纯文本形式内置在 scripts/library/<方向>/ 下，每个脚本头部注释包含
「脚本名称 / 方向 / 简介 / 用法 / 依赖」等字段，本页解析后按名字排列展示。
"""
import os
import sys
import subprocess

import customtkinter as ctk
from tkinter import filedialog, messagebox

from .common import APP_DIR, IS_FROZEN, CREATE_NEW_CONSOLE, external_python
from . import ui_theme as theme

CATEGORY_LABELS = [
    ("all", "全部方向"),
    ("crypto", "Crypto 密码学"),
    ("misc", "Misc 杂项"),
    ("web", "Web 安全"),
    ("pwn", "Pwn 二进制"),
    ("reverse", "Reverse 逆向"),
    ("forensics", "Forensics 取证"),
    ("utils", "Utils 实用工具"),
]
LABEL_BY_CAT = dict(CATEGORY_LABELS)

# 各扩展名对应的注释前缀清理
_COMMENT_PREFIX = ("#", "//", "/*", "*", "*/", "--", "<%--", "--%>", "%", "<", ">")


def library_root():
    """定位脚本库目录：打包后 exe 同级 -> _MEIPASS -> 开发态工程根。"""
    candidates = []
    if IS_FROZEN:
        candidates.append(os.path.join(APP_DIR, "scripts", "library"))
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(os.path.join(meipass, "scripts", "library"))
    else:
        candidates.append(os.path.join(APP_DIR, "scripts", "library"))
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(os.path.join(meipass, "scripts", "library"))
    for c in candidates:
        if os.path.isdir(c):
            return c
    return candidates[0]


def _clean_comment(line):
    """去掉一行开头的注释符号，返回纯文本。"""
    s = line.rstrip("\r\n")
    s = s.lstrip()
    changed = True
    while changed:
        changed = False
        for pre in ("<%--", "--%>", "/*", "*/", "//", "#", "*", "-", "<", ">", "%"):
            if s.startswith(pre):
                s = s[len(pre):].lstrip()
                changed = True
    return s.strip()


def parse_meta(path):
    """从脚本头部注释提取元数据。返回 dict(name/cat/intro/usage/dep/ref)。"""
    name = os.path.basename(path)
    meta = {"name": name, "cat": os.path.basename(os.path.dirname(path)),
            "intro": "", "usage": "", "dep": "", "ref": ""}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            head = [next(f, "") for _ in range(60)]
    except Exception:
        return meta
    ext = os.path.splitext(path)[1].lower()

    if ext in (".txt", ".md"):
        lines = [l.strip() for l in head]
        # 速查手册格式：=== 标题行 ===
        for i, l in enumerate(lines):
            if set(l) == {"="} and len(l) > 10 and i + 1 < len(lines):
                meta["name"] = lines[i + 1].strip() or name
                break
        for l in lines[3:]:
            if l and not set(l) <= {"="}:
                meta["intro"] = l[:80]
                break
        return meta

    for raw in head:
        text = _clean_comment(raw)
        if not text:
            continue
        if text.startswith("脚本名称"):
            meta["name"] = text.split(":", 1)[-1].split("：", 1)[-1].strip() or name
        elif text.startswith("方向"):
            v = text.split(":", 1)[-1].split("：", 1)[-1].strip()
            if v:
                meta["cat"] = v
        elif text.startswith("简介"):
            v = text.split(":", 1)[-1].split("：", 1)[-1].strip()
            meta["intro"] = v
        elif text.startswith("依赖"):
            meta["dep"] = text.split(":", 1)[-1].split("：", 1)[-1].strip()
        elif text.startswith("参考") or text.startswith("引用"):
            meta["ref"] = text.split(":", 1)[-1].split("：", 1)[-1].strip()
    # 简介可能跨多行，补抓
    if not meta["intro"]:
        grab = False
        buf = []
        for raw in head:
            text = _clean_comment(raw)
            if text.startswith("简介"):
                first = text.split(":", 1)[-1].split("：", 1)[-1].strip()
                if first:
                    buf.append(first)
                grab = True
                continue
            if grab:
                if text.startswith(("用法", "依赖", "参考", "方向", "脚本名称")):
                    break
                if text:
                    buf.append(text)
        meta["intro"] = " ".join(buf)[:100]
    return meta


class ScriptsLibraryFrame(ctk.CTkFrame):
    def __init__(self, master, **kw):
        kw.setdefault("fg_color", "transparent")
        super().__init__(master, **kw)
        self.root_dir = library_root()
        self.items = []          # [(cat, path, meta)]
        self.current_path = None
        self._build()
        self.scan()

    # ------------------------------------------------------------------
    def _build(self):
        top = theme.toolbar(self)
        top.pack(fill="x", padx=8, pady=(10, 6))

        ctk.CTkLabel(top, text="脚本库", font=theme.font(16, "bold"),
                     text_color=theme.TEXT).pack(side="left", padx=(12, 10), pady=8)
        self.cat_var = ctk.StringVar(value=LABEL_BY_CAT["all"])
        self.cat_menu = theme.option_menu(
            top, values=[lbl for _, lbl in CATEGORY_LABELS], width=152,
            command=self._on_filter)
        self.cat_menu.pack(side="left", padx=(0, 8), pady=8)

        self.search = theme.entry(top, placeholder_text="搜索脚本名 / 简介 / 内容关键字…", width=280)
        self.search.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.search.bind("<KeyRelease>", lambda e: self._on_filter())

        theme.button(top, "刷新", "ghost", width=66, command=self.scan).pack(side="left", padx=(0, 6))
        theme.button(top, "打开库目录", "ghost", width=100,
                     command=self._open_root).pack(side="right", padx=(0, 10))

        # 主体：左列表 + 右内容
        body = theme.panel(self)
        body.pack(fill="both", expand=True, padx=8, pady=(0, 10))

        left = theme.card(body, width=380)
        left.pack(side="left", fill="y", padx=(0, 8))
        left.pack_propagate(False)
        self.count_label = ctk.CTkLabel(left, text="", anchor="w",
                                        font=theme.font(theme.FONT_SMALL),
                                        text_color=theme.TEXT_MUTE)
        self.count_label.pack(fill="x", padx=12, pady=(10, 4))
        self.list_scroll = theme.scroll(left, width=350)
        self.list_scroll.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        right = theme.card(body)
        right.pack(side="left", fill="both", expand=True, padx=8)

        rbar = theme.panel(right)
        rbar.pack(fill="x", padx=12, pady=(10, 4))
        self.title_label = ctk.CTkLabel(rbar, text="请选择左侧脚本",
                                        font=theme.font(15, "bold"),
                                        text_color=theme.TEXT, anchor="w")
        self.title_label.pack(side="left", fill="x", expand=True, padx=(0, 6))
        theme.button(rbar, "复制全部", "ghost", width=82, height=28,
                     command=self._copy_all).pack(side="right", padx=(6, 0))
        theme.button(rbar, "另存为…", "primary", width=82, height=28,
                     command=self._save_as).pack(side="right", padx=(6, 0))
        theme.button(rbar, "打开所在目录", "ghost", width=104, height=28,
                     command=self._open_current_dir).pack(side="right", padx=(6, 0))
        self.selftest_btn = theme.button(rbar, "运行自测", "ghost", width=92, height=28,
                                         command=self._run_selftest)
        self.selftest_btn.pack(side="right")

        self.meta_label = ctk.CTkLabel(right, text="", anchor="w", justify="left",
                                       text_color=theme.TEXT_MUTE,
                                       font=theme.font(theme.FONT_SMALL))
        self.meta_label.pack(fill="x", padx=14, pady=(2, 0))

        self.code_box = theme.textbox(right, mono_font=True, size=12)
        self.code_box.pack(fill="both", expand=True, padx=12, pady=(6, 12))
        self.code_box.configure(state="disabled")

    # ------------------------------------------------------------------
    def scan(self):
        self.items = []
        if os.path.isdir(self.root_dir):
            for cat in sorted(os.listdir(self.root_dir)):
                cdir = os.path.join(self.root_dir, cat)
                if not os.path.isdir(cdir) or cat.startswith(("__", ".")):
                    continue
                for fn in sorted(os.listdir(cdir)):
                    p = os.path.join(cdir, fn)
                    if os.path.isfile(p) and not fn.endswith((".pyc", ".pyo")):
                        self.items.append((cat, p, parse_meta(p)))
        self._on_filter()

    def _selected_cat(self):
        lbl = self.cat_menu.get()
        for cat, name in CATEGORY_LABELS:
            if name == lbl:
                return cat
        return "all"

    def _on_filter(self, *_):
        cat = self._selected_cat()
        kw = self.search.get().strip().lower()
        for w in self.list_scroll.winfo_children():
            w.destroy()
        shown = 0
        for c, p, meta in self.items:
            if cat != "all" and c != cat:
                continue
            hay = (meta["name"] + " " + os.path.basename(p) + " " + meta["intro"]).lower()
            if kw and kw not in hay:
                # 再搜正文（大文件只读一次）
                if not self._content_contains(p, kw):
                    continue
            self._make_list_row(c, p, meta)
            shown += 1
        self.count_label.configure(text=f"共 {shown} 个脚本（库：{self.root_dir}）")

    @staticmethod
    def _content_contains(path, kw):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return kw in f.read(80000).lower()
        except Exception:
            return False

    def _make_list_row(self, cat, path, meta):
        """两行式列表行：名字加粗、简介自动换行，整行可点击/整行悬停高亮。"""
        title = meta["name"]
        intro = meta["intro"] or LABEL_BY_CAT.get(cat, cat)
        if len(intro) > 52:
            intro = intro[:52] + "…"
        row = ctk.CTkFrame(self.list_scroll, fg_color="transparent",
                           corner_radius=theme.RADIUS_SMALL)
        row.pack(fill="x", pady=1, padx=2)
        name_label = ctk.CTkLabel(row, text=title, anchor="w", justify="left",
                                  font=theme.font(theme.FONT_BODY, "bold"),
                                  text_color=theme.TEXT, wraplength=306)
        name_label.pack(fill="x", padx=9, pady=(5, 0))
        intro_label = ctk.CTkLabel(row, text=intro, anchor="w", justify="left",
                                   font=theme.font(theme.FONT_SMALL),
                                   text_color=theme.TEXT_DIM, wraplength=306)
        intro_label.pack(fill="x", padx=9, pady=(0, 5))

        def enter(_event):
            row.configure(fg_color=theme.BG_SURFACE_3)

        def leave(_event):
            row.configure(fg_color="transparent")

        def open_it(_event):
            self.show(path)

        for widget in (row, name_label, intro_label):
            widget.bind("<Button-1>", open_it)
            widget.bind("<Enter>", enter)
        row.bind("<Leave>", leave)

    # ------------------------------------------------------------------
    def show(self, path):
        self.current_path = path
        meta = parse_meta(path)
        try:
            content = open(path, "r", encoding="utf-8", errors="replace").read()
        except Exception as e:
            content = f"[读取失败] {e}"
        self.title_label.configure(text=meta["name"])
        dep = f"依赖：{meta['dep']}" if meta["dep"] else "依赖：无（标准库）"
        ref = f"\n参考：{meta['ref']}" if meta["ref"] else ""
        self.meta_label.configure(
            text=f"文件：{os.path.basename(path)}（{LABEL_BY_CAT.get(meta['cat'], meta['cat'])}）    {dep}{ref}")
        self.code_box.configure(state="normal")
        self.code_box.delete("1.0", "end")
        self.code_box.insert("1.0", content)
        self.code_box.configure(state="disabled")
        self.selftest_btn.configure(state="normal" if path.endswith(".py") else "disabled")

    def _copy_all(self):
        if not self.current_path:
            return
        content = self.code_box.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(content)
        messagebox.showinfo("脚本库", "完整脚本已复制到剪贴板。")

    def _save_as(self):
        if not self.current_path:
            return
        default = os.path.basename(self.current_path)
        dst = filedialog.asksaveasfilename(initialfile=default)
        if dst:
            with open(dst, "wb") as f:
                f.write(open(self.current_path, "rb").read())
            messagebox.showinfo("脚本库", f"已保存：{dst}")

    def _open_root(self):
        os.startfile(self.root_dir) if os.path.isdir(self.root_dir) else None

    def _open_current_dir(self):
        if self.current_path:
            os.startfile(os.path.dirname(self.current_path))

    def _run_selftest(self):
        if not self.current_path or not self.current_path.endswith(".py"):
            return
        py = external_python()
        if not py:
            messagebox.showwarning("脚本库", "未找到外部 Python，请到工具中心配置或安装 Python。")
            return
        try:
            subprocess.Popen([py, self.current_path, "--selftest"],
                             cwd=os.path.dirname(self.current_path),
                             creationflags=CREATE_NEW_CONSOLE)
        except Exception as e:
            messagebox.showerror("脚本库", f"运行失败：{e}")

    # ------------------------------------------------------------------
    def select_category(self, cat):
        """供其他解题页跳转：切到指定方向、清空搜索并刷新过滤。"""
        lbl = LABEL_BY_CAT.get(cat)
        if lbl:
            self.cat_menu.set(lbl)
            self.search.delete(0, "end")
            self._on_filter()
