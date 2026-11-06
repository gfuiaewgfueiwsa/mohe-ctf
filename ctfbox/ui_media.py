# -*- coding: utf-8 -*-
"""媒体中心：增强图片查看器 + 逐帧视频播放器 + 音频隐写工作台。

图片：缩放/适应/旋转/翻转、RGBA 通道与位平面、反相、亮度对比度饱和度伽马、
      直方图、EXIF、格式转换、GIF 逐帧与导出、条码/二维码识别、LSB 增强图、送隐写分析。
视频：播放暂停/停止、逐帧进退、±1s/±10s 跳转、快捷键、0.25~4x 倍速、进度拖动、循环、
      画面旋转/灰度、截图、抽帧、提取音频、导出 GIF、当前帧送隐写分析；带声音调用 ffplay。
      播放渲染使用 OpenCV 高速缩放并按实际解码耗时调度，长视频/大窗口不卡顿。
音频：WAV/MP3/FLAC/OGG/M4A 等全套隐写分析（多位面 LSB、语谱图、波形、DTMF、摩斯、
      FSK、元数据、中置/侧置、反转音频、尾部附加），语谱图/波形直接内嵌预览。
所有导出默认落在软件目录 exports\\ 下，后台处理静默执行不弹黑窗。
"""
import os
import time
import shutil
import threading
import tkinter as tk
from tkinter import filedialog

import customtkinter as ctk

from .common import WORKSPACE, EXPORTS_DIR, safe_name
from . import toolsmgr
from . import ui_theme as theme

try:
    from PIL import Image, ImageSequence, ImageOps, ImageEnhance, ImageTk, ImageFilter
    import numpy as np
except Exception:
    Image = None
    np = None

IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff", ".tif", ".ico")
VIDEO_EXTS = (".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".ts",
              ".3gp", ".mpg", ".mpeg", ".m2ts", ".ogv")
AUDIO_EXTS = (".wav", ".mp3", ".flac", ".ogg", ".m4a", ".aac", ".wma", ".amr",
              ".opus", ".aif", ".aiff", ".au", ".ape", ".mka", ".oga")


def _ffmpeg():
    exe = toolsmgr.get_tool("ffmpeg")
    if exe:
        return exe
    return shutil.which("ffmpeg") or shutil.which("ffmpeg.exe")


def _ffplay():
    ff = _ffmpeg()
    if ff:
        cand = os.path.join(os.path.dirname(ff), "ffplay.exe")
        if os.path.exists(cand):
            return cand
    return shutil.which("ffplay") or shutil.which("ffplay.exe")


class MediaFrame(ctk.CTkFrame):
    def __init__(self, master, **kw):
        kw.setdefault("fg_color", "transparent")
        super().__init__(master, **kw)
        if Image is None:
            ctk.CTkLabel(self, text="Pillow/numpy 未安装，媒体中心不可用",
                         font=theme.font(13), text_color=theme.WARNING).pack(pady=40)
            return
        self.tabs = theme.tabview(self)
        self.tabs.pack(fill="both", expand=True, padx=8, pady=8)
        self.t_img = self.tabs.add("图片查看器")
        self.t_vid = self.tabs.add("视频播放器")
        self.t_aud = self.tabs.add("音频隐写")
        self._build_image()
        self._build_video()
        self._build_audio()

    def _ui(self, fn):
        """线程安全的 UI 回填：工作线程关闭窗口/主循环未就绪时静默丢弃回调。"""
        def _safe():
            try:
                fn()
            except Exception:
                pass
        try:
            self.after(0, _safe)
        except Exception:
            # RuntimeError: main thread is not in main loop；TclError: 窗口已销毁
            pass

    # ======================================================================
    # 图片查看器
    # ======================================================================
    def _build_image(self):
        tools = theme.toolbar(self.t_img)
        tools.pack(fill="x", padx=8, pady=(10, 6))
        ctk.CTkLabel(tools, text="查看", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(12, 6))
        for text, cmd, width in (("打开图片", self.img_open, 88), ("放大 +", lambda: self.img_zoom(1.25), 68),
                                 ("缩小 -", lambda: self.img_zoom(0.8), 68), ("适应", self.img_fit, 62),
                                 ("1:1", lambda: self.img_set_zoom(1.0), 54), ("↺ 90", lambda: self.img_rot(90), 58),
                                 ("↻ 90", lambda: self.img_rot(-90), 58), ("水平翻转", lambda: self.img_flip(0), 80),
                                 ("垂直翻转", lambda: self.img_flip(1), 80), ("反相", self.img_invert, 60),
                                 ("重置", self.img_reset, 60)):
            theme.button(tools, text, "subtle", width=width, height=28,
                         command=cmd).pack(side="left", padx=2, pady=6)

        analysis = theme.toolbar(self.t_img)
        analysis.pack(fill="x", padx=8, pady=(0, 6))
        ctk.CTkLabel(analysis, text="通道", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(12, 4))
        self.img_channel = theme.option_menu(
            analysis, width=112,
            values=["正常", "R 红", "G 绿", "B 蓝", "A 透明", "灰度", "位平面R", "位平面G", "位平面B"],
            command=lambda _=None: self.img_render())
        self.img_channel.pack(side="left", pady=6)
        for text, cmd, width, kind in (
                ("直方图", self.img_histogram, 66, "subtle"), ("EXIF", self.img_exif, 62, "subtle"),
                ("条码/二维码", self.img_barcode, 94, "subtle"),
                ("LSB 彩图", lambda: self.img_lsb_quick("combo"), 78, "subtle"),
                ("随机色图", lambda: self.img_lsb_quick("random"), 78, "subtle"),
                ("另存 / 转换", self.img_saveas, 84, "subtle"),
                ("导出 GIF 全部帧", self.img_gif_export, 114, "ghost"),
                ("送隐写分析", self.img_analyze, 94, "primary")):
            theme.button(analysis, text, kind, width=width, height=28,
                         command=cmd).pack(side="left", padx=3, pady=6)

        # 调节滑块
        bar3 = theme.panel(self.t_img)
        bar3.pack(fill="x", padx=10, pady=(0, 2))
        self.img_bri = self._slider(bar3, "亮度", 0, self.img_render, default=1.0, span=(0.2, 2.0))
        self.img_con = self._slider(bar3, "对比", 1, self.img_render, default=1.0, span=(0.2, 2.0))
        self.img_sat = self._slider(bar3, "饱和", 2, self.img_render, default=1.0, span=(0.0, 2.0))
        self.img_gam = self._slider(bar3, "伽马", 3, self.img_render, default=1.0, span=(0.2, 3.0))

        body = theme.card(self.t_img)
        body.pack(fill="both", expand=True, padx=8, pady=(4, 6))
        self.img_canvas = tk.Canvas(body, bg=theme.BG_EDITOR, highlightthickness=0)
        vsb = ctk.CTkScrollbar(body, orientation="vertical", command=self.img_canvas.yview,
                               button_color=theme.BORDER, button_hover_color=theme.BG_SURFACE_3)
        hsb = ctk.CTkScrollbar(body, orientation="horizontal", command=self.img_canvas.xview,
                               button_color=theme.BORDER, button_hover_color=theme.BG_SURFACE_3)
        self.img_canvas.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.img_canvas.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns", padx=(0, 2), pady=2)
        hsb.grid(row=1, column=0, sticky="ew", padx=2)
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)
        self.img_canvas.bind("<MouseWheel>", lambda e: self.img_canvas.yview_scroll(int(-e.delta / 120), "units"))
        self.img_canvas.bind("<Configure>", lambda e: self._img_on_configure())

        self.img_status = ctk.CTkLabel(self.t_img, text="未打开图片", anchor="w",
                                       font=theme.font(theme.FONT_SMALL), text_color=theme.TEXT_MUTE)
        self.img_status.pack(fill="x", padx=12, pady=(0, 4))

        # GIF 帧条
        self.gif_bar = theme.toolbar(self.t_img)
        self.gif_idx = 0
        theme.button(self.gif_bar, "◀ 上一帧", "ghost", width=84, height=26,
                     command=lambda: self.img_gif_step(-1)).pack(side="left", padx=(10, 3), pady=4)
        self.gif_label = ctk.CTkLabel(self.gif_bar, text="0/0", font=theme.font(theme.FONT_SMALL),
                                      text_color=theme.TEXT_DIM)
        self.gif_label.pack(side="left", padx=6)
        theme.button(self.gif_bar, "下一帧 ▶", "ghost", width=84, height=26,
                     command=lambda: self.img_gif_step(1)).pack(side="left", padx=3)
        self.gif_playing = False
        self.gif_play_btn = theme.button(self.gif_bar, "播放 GIF", "subtle", width=84, height=26,
                                         command=self.img_gif_play)
        self.gif_play_btn.pack(side="left", padx=3)
        self.gif_bar.pack_forget()

        # 状态
        self.img_orig = None          # 当前帧原始 RGBA Image
        self.img_base = None          # 打开的 Image（可能是动画）
        self.img_nframes = 1
        self.img_zoomv = 1.0
        self.img_rotv = 0
        self.img_flipv = [False, False]
        self.img_invert_v = False
        self.img_fit_on_resize = True
        self.img_path = None
        self._img_photo = None

    def _slider(self, parent, name, idx, callback, default=1.0, span=(0.0, 2.0)):
        ctk.CTkLabel(parent, text=name, font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(12 if idx == 0 else 6, 3))
        var = tk.DoubleVar(value=default)

        def on(v):
            callback()

        s = ctk.CTkSlider(parent, from_=span[0], to=span[1], variable=var, width=110, command=on,
                          bg_color="transparent", fg_color=theme.BG_SURFACE_3,
                          progress_color=theme.ACCENT, button_color=theme.ACCENT,
                          button_hover_color=theme.ACCENT_HOVER, height=16)
        s.pack(side="left", pady=6)
        return var

    # ---------- 图片：打开/渲染 ----------
    def img_open(self, path=None):
        if not path:
            path = filedialog.askopenfilename(
                title="选择图片",
                filetypes=[("图片", " ".join("*" + e for e in IMAGE_EXTS)), ("所有文件", "*.*")])
        if not path:
            return
        try:
            self.img_base = Image.open(path)
            self.img_path = path
            self.img_nframes = getattr(self.img_base, "n_frames", 1)
            self.gif_idx = 0
            self.img_reset(render=False)
            if self.img_nframes > 1:
                self.gif_bar.pack(fill="x", padx=6, pady=2)
                self.gif_label.configure(text=f"1/{self.img_nframes}")
            else:
                self.gif_bar.pack_forget()
            self.after(50, self.img_fit)
            self.img_status.configure(text=f"{os.path.basename(path)}  {self.img_base.width}x{self.img_base.height} "
                                           f"{self.img_base.format} {self.img_base.mode} 帧数={self.img_nframes}")
        except Exception as e:
            self.img_status.configure(text=f"打开失败: {e}")

    def _load_frame(self):
        if self.img_nframes > 1:
            self.img_base.seek(self.gif_idx)
        self.img_orig = self.img_base.convert("RGBA")

    def img_reset(self, render=True):
        self.img_rotv = 0
        self.img_flipv = [False, False]
        self.img_invert_v = False
        self.img_channel.set("正常")
        self.img_bri.set(1.0); self.img_con.set(1.0); self.img_sat.set(1.0); self.img_gam.set(1.0)
        if render:
            self.img_fit()

    def _processed(self):
        self._load_frame()
        im = self.img_orig
        ch = self.img_channel.get()
        arr = np.array(im)
        if ch.startswith("位平面"):
            cm = {"位平面R": 0, "位平面G": 1, "位平面B": 2}[ch]
            plane = ((arr[:, :, cm] & 1) * 255).astype("uint8")
            im = Image.fromarray(plane).convert("RGBA")
        elif ch in ("R 红", "G 绿", "B 蓝"):
            ci = {"R 红": 0, "G 绿": 1, "B 蓝": 2}[ch]
            z = np.zeros_like(arr[:, :, :3]); z[:, :, ci] = arr[:, :, ci]
            im = Image.fromarray(np.dstack([z, arr[:, :, 3]])).convert("RGBA")
        elif ch == "A 透明":
            a = arr[:, :, 3]
            im = Image.fromarray(np.dstack([a, a, a, np.full_like(a, 255)])).convert("RGBA")
        elif ch == "灰度":
            im = ImageOps.grayscale(im).convert("RGBA")
        if self.img_invert_v:
            rgb = np.array(im.convert("RGB"))
            im = Image.fromarray(255 - rgb).convert("RGBA")
        if self.img_flipv[0]:
            im = ImageOps.mirror(im)
        if self.img_flipv[1]:
            im = ImageOps.flip(im)
        if self.img_rotv:
            im = im.rotate(self.img_rotv, expand=True)
        # 亮度/对比/饱和（作用于 RGB）
        rgb = im.convert("RGB")
        if abs(self.img_bri.get() - 1) > 0.01:
            rgb = ImageEnhance.Brightness(rgb).enhance(self.img_bri.get())
        if abs(self.img_con.get() - 1) > 0.01:
            rgb = ImageEnhance.Contrast(rgb).enhance(self.img_con.get())
        if abs(self.img_sat.get() - 1) > 0.01:
            rgb = ImageEnhance.Color(rgb).enhance(self.img_sat.get())
        if abs(self.img_gam.get() - 1) > 0.01:
            g = self.img_gam.get()
            lut = [min(255, int(255 * ((i / 255) ** (1.0 / g)))) for i in range(256)]
            rgb = rgb.point(lut * 3)
        return rgb

    def img_render(self, *_):
        if self.img_orig is None:
            return
        try:
            im = self._processed()
            w = max(1, int(im.width * self.img_zoomv))
            h = max(1, int(im.height * self.img_zoomv))
            disp = im.resize((w, h), Image.LANCZOS)
            self._img_photo = ImageTk.PhotoImage(disp)
            self.img_canvas.delete("all")
            self.img_canvas.create_image(0, 0, anchor="nw", image=self._img_photo)
            self.img_canvas.configure(scrollregion=(0, 0, w, h))
        except Exception as e:
            self.img_status.configure(text=f"渲染失败: {e}")

    def _img_on_configure(self):
        if self.img_fit_on_resize and self.img_orig is not None:
            self.img_fit()

    def img_fit(self):
        if self.img_orig is None:
            return
        self._load_frame()
        cw = max(100, self.img_canvas.winfo_width() - 4)
        ch = max(100, self.img_canvas.winfo_height() - 4)
        proc = self._processed()
        iw, ih = proc.size
        self.img_zoomv = min(cw / iw, ch / ih, 8.0)
        self.img_render()

    def img_set_zoom(self, z):
        self.img_fit_on_resize = False
        self.img_zoomv = z
        self.img_render()

    def img_zoom(self, factor):
        self.img_fit_on_resize = False
        self.img_zoomv = min(16.0, max(0.02, self.img_zoomv * factor))
        self.img_render()

    def img_rot(self, deg):
        self.img_rotv = (self.img_rotv + deg) % 360
        self.img_render()

    def img_flip(self, axis):
        self.img_flipv[axis] = not self.img_flipv[axis]
        self.img_render()

    def img_invert(self):
        self.img_invert_v = not self.img_invert_v
        self.img_render()

    # ---------- 图片：功能 ----------
    def img_histogram(self):
        if self.img_orig is None:
            return
        im = self._processed()
        hist = im.histogram()
        win = ctk.CTkToplevel(self)
        win.title("直方图 (R/G/B)")
        win.geometry("520x320")
        cv = tk.Canvas(win, bg="#111", highlightthickness=0)
        cv.pack(fill="both", expand=True)
        self.after(120, lambda: self._draw_hist(cv, hist))

    def _draw_hist(self, cv, hist):
        cv.delete("all")
        W, H = cv.winfo_width(), cv.winfo_height()
        for base, color, name in ((0, "#ff5555", "R"), (256, "#55ff55", "G"), (512, "#5599ff", "B")):
            vals = hist[base:base + 256]
            m = max(vals) or 1
            pts = []
            for x in range(0, 256, 2):
                px = int(x / 255 * W)
                py = H - int(vals[x] / m * (H - 20)) - 10
                pts += [px, py]
            cv.create_line(pts, fill=color, width=1)
        cv.create_text(30, 12, fill="#aaa", text="亮度分布 0-255（红/绿/蓝）")

    def img_exif(self):
        if self.img_base is None:
            return
        lines = [f"文件: {self.img_path}", f"格式: {self.img_base.format}  尺寸: {self.img_base.width}x{self.img_base.height}  模式: {self.img_base.mode}", ""]
        try:
            from PIL.ExifTags import TAGS
            exif = self.img_base.getexif()
            if exif:
                for tid, val in exif.items():
                    lines.append(f"{TAGS.get(tid, tid)}: {val}")
            else:
                lines.append("（无 EXIF）")
            for k, v in self.img_base.info.items():
                if isinstance(v, str):
                    lines.append(f"info[{k}]: {str(v)[:300]}")
        except Exception as e:
            lines.append(f"读取失败: {e}")
        self._popup_text("EXIF / 元信息", "\n".join(map(str, lines)))

    def img_barcode(self):
        if self.img_orig is None:
            return
        out = []
        try:
            import cv2
            arr = np.array(self.img_orig.convert("RGB"))[:, :, ::-1].copy()
            qr = cv2.QRCodeDetector()
            txt, _, _ = qr.detectAndDecode(arr)
            if txt:
                out.append("QR二维码: " + txt)
            try:
                bd = cv2.barcode.BarcodeDetector()
                ok, decoded, dtype, _ = bd.detectAndDecode(arr)
                if ok:
                    for d, t in zip(decoded, dtype):
                        if d:
                            out.append(f"{t}: {d}")
            except Exception:
                pass
        except Exception as e:
            out.append("识别失败: " + str(e))
        self._popup_text("条码 / 二维码识别", "\n".join(out) if out else "未识别到条码/二维码")

    def img_lsb_quick(self, mode):
        """生成 LSB 低位合成彩图 / 随机色映射图，保存到软件 exports 并载入查看。"""
        if self.img_orig is None:
            return
        try:
            arr = np.array(self.img_orig.convert("RGBA"))
            if mode == "combo":
                out = np.zeros((arr.shape[0], arr.shape[1], 3), dtype=np.uint8)
                for ci in range(3):
                    out[:, :, ci] = ((arr[:, :, ci] & 1) * 255).astype("uint8")
                im = Image.fromarray(out)
                name = "lsb_rgb_combo_view.png"
            else:
                rng = np.random.RandomState(0x5EED)
                pal0 = rng.integers(0, 255, 3)
                pal1 = rng.integers(0, 255, 3)
                m = (arr[:, :, 0] & 1).astype(bool)
                out = np.where(m[:, :, None], pal1, pal0).astype(np.uint8)
                im = Image.fromarray(out)
                name = "lsb_random_colormap_view.png"
            os.makedirs(EXPORTS_DIR, exist_ok=True)
            fp = os.path.join(EXPORTS_DIR, name)
            im.save(fp)
            self.img_open(fp)
            self.img_status.configure(text="已生成并载入 LSB 增强图: " + fp)
        except Exception as e:
            self.img_status.configure(text=f"LSB 增强图生成失败: {e}")

    def img_saveas(self):
        if self.img_orig is None:
            return
        os.makedirs(EXPORTS_DIR, exist_ok=True)
        im = self._processed()
        path = filedialog.asksaveasfilename(
            title="另存为（默认软件 exports 目录）", defaultextension=".png",
            initialdir=EXPORTS_DIR, initialfile="ctfbox_image.png",
            filetypes=[("PNG", "*.png"), ("JPEG", "*.jpg"), ("BMP", "*.bmp"), ("WEBP", "*.webp")])
        if not path:
            return
        if path.lower().endswith((".jpg", ".jpeg")):
            im.convert("RGB").save(path, quality=95)
        else:
            im.save(path)
        self.img_status.configure(text=f"已保存: {path}")

    def img_gif_step(self, d):
        if self.img_nframes <= 1:
            return
        self.gif_idx = (self.gif_idx + d) % self.img_nframes
        self.gif_label.configure(text=f"{self.gif_idx + 1}/{self.img_nframes}")
        self.img_render()

    def img_gif_play(self):
        self.gif_playing = not self.gif_playing
        self.gif_play_btn.configure(text="停止" if self.gif_playing else "播放GIF")
        if self.gif_playing:
            self._gif_tick()

    def _gif_tick(self):
        if not self.gif_playing or self.img_nframes <= 1:
            return
        self.img_gif_step(1)
        delay = self.img_base.info.get("duration", 100) or 100
        self.after(int(delay), self._gif_tick)

    def img_gif_export(self):
        if self.img_base is None:
            return
        # 静默导出到软件 exports 目录，不再连续弹目录选择窗
        base = safe_name(os.path.splitext(os.path.basename(self.img_path or "image"))[0])
        d = os.path.join(EXPORTS_DIR, f"gif_{base}_frames")
        os.makedirs(d, exist_ok=True)
        n = 0
        for fr in ImageSequence.Iterator(self.img_base):
            fr.convert("RGBA").save(os.path.join(d, f"frame_{n:04d}.png"))
            n += 1
        self.img_status.configure(text=f"已导出 {n} 帧到 {d}")

    def img_analyze(self):
        if not self.img_path:
            return
        self._run_analysis(self.img_path, "图片")

    # ======================================================================
    # 视频播放器
    # ======================================================================
    def _build_video(self):
        bar = theme.toolbar(self.t_vid)
        bar.pack(fill="x", padx=8, pady=(10, 6))
        theme.button(bar, "打开视频", "subtle", width=88, height=28,
                     command=self.vid_open).pack(side="left", padx=(10, 3), pady=6)
        self.vid_play_btn = theme.button(bar, "▶ 播放", "primary", width=78, height=28,
                                         command=self.vid_toggle)
        self.vid_play_btn.pack(side="left", padx=3, pady=6)
        theme.button(bar, "■ 停止", "ghost", width=64, height=28,
                     command=self.vid_stop).pack(side="left", padx=2, pady=6)
        for text, cmd, width in (("⏮ 帧", lambda: self.vid_step(-1), 54), ("帧 ⏭", lambda: self.vid_step(1), 54),
                                 ("-1s", lambda: self.vid_jump(-1), 50), ("+1s", lambda: self.vid_jump(1), 50),
                                 ("-10s", lambda: self.vid_jump(-10), 56), ("+10s", lambda: self.vid_jump(10), 56)):
            theme.button(bar, text, "ghost", width=width, height=28,
                         command=cmd).pack(side="left", padx=2, pady=6)
        ctk.CTkLabel(bar, text="倍速", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(10, 3))
        self.vid_speed = theme.option_menu(bar, width=82,
                                           values=["0.25", "0.5", "0.75", "1.0", "1.25", "1.5", "2.0", "4.0"],
                                           command=lambda _=None: None)
        self.vid_speed.set("1.0")
        self.vid_speed.pack(side="left", pady=6)
        self.vid_loop = theme.switch(bar, "循环")
        self.vid_loop.pack(side="left", padx=8)
        ctk.CTkLabel(bar, text="画面", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(6, 3))
        self.vid_rot = theme.option_menu(bar, width=82, values=["0°", "90°", "180°", "270°"],
                                         command=lambda _=None: self.vid_show_frame())
        self.vid_rot.pack(side="left", pady=6)
        self.vid_gray = theme.switch(bar, "灰度", command=lambda: self.vid_show_frame())
        self.vid_gray.pack(side="left", padx=8)

        bar2 = theme.toolbar(self.t_vid)
        bar2.pack(fill="x", padx=8, pady=(0, 6))
        for i, (text, cmd, width, kind) in enumerate((
                ("截图当前帧", self.vid_snapshot, 92, "subtle"),
                ("抽帧（到软件目录）", self.vid_extract_frames, 132, "subtle"),
                ("提取音频", self.vid_extract_audio, 82, "subtle"),
                ("导出 GIF", self.vid_export_gif, 82, "subtle"),
                ("带声音播放（ffplay）", self.vid_ffplay, 142, "primary"),
                ("当前帧送分析", self.vid_frame_analyze, 112, "subtle"),
                ("打开导出目录", lambda: os.startfile(EXPORTS_DIR), 112, "ghost"))):
            theme.button(bar2, text, kind, width=width, height=28,
                         command=cmd).pack(side="left", padx=(10 if i == 0 else 3, 0), pady=6)
        ctk.CTkLabel(bar2, text="音量(ffplay)", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(10, 3))
        self.vid_vol = tk.IntVar(value=80)
        ctk.CTkSlider(bar2, from_=0, to=100, variable=self.vid_vol, width=100, height=16,
                      fg_color=theme.BG_SURFACE_3, progress_color=theme.ACCENT,
                      button_color=theme.ACCENT, button_hover_color=theme.ACCENT_HOVER).pack(
            side="left", pady=6)

        stage = theme.card(self.t_vid)
        stage.pack(fill="both", expand=True, padx=8, pady=(0, 6))
        self.vid_label = ctk.CTkLabel(stage, text_color=theme.TEXT_MUTE,
                                      font=theme.font(theme.FONT_SMALL),
                                      text="打开视频后在此逐帧播放（内置播放器为无声分析画面；带声音点 ffplay）")
        self.vid_label.pack(fill="both", expand=True, pady=12)
        self._vid_photo = None

        ctl = theme.panel(self.t_vid)
        ctl.pack(fill="x", padx=10)
        self.vid_time = ctk.CTkLabel(ctl, text="00:00 / 00:00", width=150,
                                     font=theme.mono(11), text_color=theme.TEXT_DIM)
        self.vid_time.pack(side="left", padx=4)
        self.vid_seek = ctk.CTkSlider(ctl, from_=0, to=1000, command=self.vid_seek, height=16,
                                      fg_color=theme.BG_SURFACE_3, progress_color=theme.ACCENT,
                                      button_color=theme.ACCENT, button_hover_color=theme.ACCENT_HOVER)
        self.vid_seek.pack(side="left", fill="x", expand=True, padx=6, pady=4)
        self.vid_status = ctk.CTkLabel(self.t_vid, text="就绪", anchor="w",
                                       font=theme.font(theme.FONT_SMALL), text_color=theme.TEXT_MUTE)
        self.vid_status.pack(fill="x", padx=12, pady=(0, 6))

        self.vid_cap = None
        self.vid_path = None
        self.vid_playing = False
        self.vid_frames = 0
        self.vid_fps = 25.0
        self.vid_cur = 0
        self.vid_after = None
        self._vid_stage = (0, 0)
        self.vid_label.bind("<Configure>", self._vid_on_configure)
        self._vid_bind_keys()

    def _vid_bind_keys(self):
        # 快捷键：空格 播放/暂停，←/→ 逐帧，Shift+方向 ±1s，Ctrl/上下 ±10s
        for w in (self.vid_label, self.t_vid):
            try:
                w.bind("<space>", lambda e: (self.vid_toggle(), "break"))
                w.bind("<Left>", lambda e: (self.vid_step(-1), "break"))
                w.bind("<Right>", lambda e: (self.vid_step(1), "break"))
                w.bind("<Shift-Left>", lambda e: (self.vid_jump(-1), "break"))
                w.bind("<Shift-Right>", lambda e: (self.vid_jump(1), "break"))
                w.bind("<Control-Left>", lambda e: (self.vid_jump(-10), "break"))
                w.bind("<Control-Right>", lambda e: (self.vid_jump(10), "break"))
                w.bind("<Up>", lambda e: (self.vid_jump(10), "break"))
                w.bind("<Down>", lambda e: (self.vid_jump(-10), "break"))
                w.bind("<Home>", lambda e: (self.vid_stop(), "break"))
            except Exception:
                pass

    def _vid_on_configure(self, e=None):
        size = (self.vid_label.winfo_width(), self.vid_label.winfo_height())
        if size != self._vid_stage and size[0] > 20 and size[1] > 20:
            self._vid_stage = size
            if self.vid_cap is not None:
                self.vid_show_frame()

    def vid_open(self, path=None):
        if not path:
            path = filedialog.askopenfilename(
                title="选择视频",
                filetypes=[("视频", " ".join("*" + e for e in VIDEO_EXTS)), ("所有文件", "*.*")])
        if not path:
            return
        try:
            import cv2
        except Exception:
            self.vid_status.configure(text="OpenCV 未安装，无法播放")
            return
        self.vid_stop()
        self.vid_cap = cv2.VideoCapture(path)
        if not self.vid_cap.isOpened():
            self.vid_status.configure(text="无法打开（解码器缺失？请在工具中心预置 ffmpeg）: " + path)
            return
        self.vid_path = path
        self.vid_frames = int(self.vid_cap.get(cv2.CAP_PROP_FRAME_COUNT)) or 0
        fps = self.vid_cap.get(cv2.CAP_PROP_FPS) or 25.0
        self.vid_fps = fps if 0 < fps <= 240 else 25.0
        self.vid_cur = 0
        self.vid_seek.set(0)
        self.vid_status.configure(text=f"{os.path.basename(path)}  {int(self.vid_cap.get(3))}x{int(self.vid_cap.get(4))} "
                                       f"{self.vid_fps:.2f}fps  {self.vid_frames}帧  "
                                       f"快捷键: 空格播放 ←→逐帧 Shift±1s Ctrl±10s")
        self.vid_show_frame()
        try:
            self.vid_label.focus_set()
        except Exception:
            pass

    def _vid_transform(self, frame):
        import cv2
        rot = self.vid_rot.get()
        if rot == "90°":
            frame = cv2.rotate(frame, cv2.ROTATE_90_CLOCKWISE)
        elif rot == "180°":
            frame = cv2.rotate(frame, cv2.ROTATE_180)
        elif rot == "270°":
            frame = cv2.rotate(frame, cv2.ROTATE_90_COUNTERCLOCKWISE)
        if self.vid_gray.get():
            frame = cv2.cvtColor(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY), cv2.COLOR_GRAY2BGR)
        return frame

    def _vid_render(self, frame):
        """高速渲染：OpenCV 缩放到舞台尺寸（远快于逐帧 PIL LANCZOS）。"""
        import cv2
        frame = self._vid_transform(frame)
        h, w = frame.shape[:2]
        mw = max(160, self.vid_label.winfo_width() - 4)
        mh = max(120, self.vid_label.winfo_height() - 4)
        scale = min(mw / w, mh / h, 8.0)
        dw, dh = max(1, int(w * scale)), max(1, int(h * scale))
        interp = cv2.INTER_AREA if scale < 1 else cv2.INTER_LINEAR
        small = cv2.resize(frame, (dw, dh), interpolation=interp)
        rgb = cv2.cvtColor(small, cv2.COLOR_BGR2RGB)
        self._vid_photo = ImageTk.PhotoImage(Image.fromarray(rgb))
        self.vid_label.configure(image=self._vid_photo, text="")
        cur_t = self.vid_cur / self.vid_fps
        tot_t = self.vid_frames / self.vid_fps if self.vid_frames else 0
        self.vid_time.configure(text=f"{self._ts(cur_t)} / {self._ts(tot_t)}  [{self.vid_cur+1}/{self.vid_frames or '?'}]")
        if self.vid_frames:
            self.vid_seek.set(self.vid_cur / self.vid_frames * 1000)

    def vid_show_frame(self):
        if self.vid_cap is None:
            return
        import cv2
        self.vid_cap.set(cv2.CAP_PROP_POS_FRAMES, max(0, self.vid_cur))
        ok, frame = self.vid_cap.read()
        if not ok:
            return
        self.vid_cur = int(self.vid_cap.get(cv2.CAP_PROP_POS_FRAMES)) - 1
        self._vid_render(frame)

    @staticmethod
    def _ts(s):
        s = int(s)
        h, s = divmod(s, 3600)
        m, s = divmod(s, 60)
        return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"

    def vid_toggle(self):
        if self.vid_cap is None:
            return
        self.vid_playing = not self.vid_playing
        self.vid_play_btn.configure(text="⏸暂停" if self.vid_playing else "▶播放")
        if self.vid_playing:
            self._vid_tick()

    def _vid_tick(self):
        if not self.vid_playing or self.vid_cap is None:
            return
        import cv2
        t0 = time.perf_counter()
        ok, frame = self.vid_cap.read()
        if not ok:
            if self.vid_loop.get():
                self.vid_cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
                self.vid_cur = 0
                ok, frame = self.vid_cap.read()
            else:
                self.vid_playing = False
                self.vid_play_btn.configure(text="▶播放")
                return
        if ok:
            self.vid_cur = int(self.vid_cap.get(cv2.CAP_PROP_POS_FRAMES)) - 1
            self._vid_render(frame)
        # 目标帧间隔减去实际解码/渲染耗时，避免累积漂移导致慢放/卡顿
        interval = 1000.0 / self.vid_fps / float(self.vid_speed.get())
        elapsed = (time.perf_counter() - t0) * 1000.0
        delay = max(1, int(interval - elapsed))
        self.vid_after = self.after(delay, self._vid_tick)

    def vid_stop(self):
        self.vid_playing = False
        if self.vid_after:
            try:
                self.after_cancel(self.vid_after)
            except Exception:
                pass
            self.vid_after = None
        if self.vid_cap is not None:
            import cv2
            self.vid_cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
            self.vid_cur = 0
            try:
                self.vid_play_btn.configure(text="▶播放")
                self.vid_show_frame()
            except Exception:
                pass

    def vid_step(self, d):
        if self.vid_cap is None:
            return
        import cv2
        self.vid_playing = False
        self.vid_play_btn.configure(text="▶播放")
        if self.vid_after:
            try:
                self.after_cancel(self.vid_after)
            except Exception:
                pass
        self.vid_cur = max(0, min(max(0, self.vid_frames - 1), self.vid_cur + d))
        self.vid_cap.set(cv2.CAP_PROP_POS_FRAMES, self.vid_cur)
        self.vid_show_frame()

    def vid_jump(self, seconds):
        if self.vid_cap is None:
            return
        import cv2
        self.vid_cur = max(0, min(max(0, self.vid_frames - 1),
                                  int(self.vid_cur + seconds * self.vid_fps)))
        if not self.vid_playing:
            self.vid_cap.set(cv2.CAP_PROP_POS_FRAMES, self.vid_cur)
            self.vid_show_frame()

    def vid_seek(self, val):
        if self.vid_cap is None or not self.vid_frames:
            return
        import cv2
        self.vid_cur = int(float(val) / 1000 * self.vid_frames)
        self.vid_cap.set(cv2.CAP_PROP_POS_FRAMES, self.vid_cur)
        if not self.vid_playing:
            self.vid_show_frame()

    def _snapshot_path(self):
        d = os.path.join(EXPORTS_DIR, "snapshots")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, f"frame_{self.vid_cur:06d}.png")

    def vid_snapshot(self):
        if self.vid_cap is None:
            return
        import cv2
        self.vid_cap.set(cv2.CAP_PROP_POS_FRAMES, self.vid_cur)
        ok, frame = self.vid_cap.read()
        if not ok:
            return
        fp = self._snapshot_path()
        cv2.imwrite(fp, frame)
        self.vid_status.configure(text="截图已保存: " + fp)

    def _vid_outdir(self, sub):
        base = safe_name(os.path.splitext(os.path.basename(self.vid_path))[0])
        d = os.path.join(EXPORTS_DIR, sub + "_" + base)
        os.makedirs(d, exist_ok=True)
        return d

    def vid_extract_frames(self):
        if not self.vid_path:
            return
        ff = _ffmpeg()
        if not ff:
            self.vid_status.configure(text="未找到 ffmpeg，请先在工具中心预置")
            return
        d = self._vid_outdir("frames")
        out = os.path.join(d, "frame_%05d.png")
        self._run_ffmpeg([ff, "-y", "-i", self.vid_path, "-vf", "fps=1", out],
                         "每秒抽帧完成: " + d)

    def vid_extract_audio(self):
        if not self.vid_path:
            return
        ff = _ffmpeg()
        if not ff:
            self.vid_status.configure(text="未找到 ffmpeg，请先在工具中心预置")
            return
        d = self._vid_outdir("audio")
        base = safe_name(os.path.splitext(os.path.basename(self.vid_path))[0])
        out = os.path.join(d, base + "_audio.mp3")
        self._run_ffmpeg([ff, "-y", "-i", self.vid_path, "-vn", "-b:a", "192k", out],
                         "音频提取完成: " + out)

    def vid_export_gif(self):
        """ffmpeg 两遍调色板法导出高质量 GIF（默认前 10 秒，fps=10，宽 480）。"""
        if not self.vid_path:
            return
        ff = _ffmpeg()
        if not ff:
            self.vid_status.configure(text="未找到 ffmpeg，请先在工具中心预置")
            return
        d = self._vid_outdir("gif")
        pal = os.path.join(d, "palette.png")
        base = safe_name(os.path.splitext(os.path.basename(self.vid_path))[0])
        out = os.path.join(d, base + ".gif")
        vf = "fps=10,scale=480:-1:flags=lanczos"

        def work():
            import subprocess
            self._ui(lambda: self.vid_status.configure(text="GIF 调色板生成中…"))
            r1 = subprocess.run([ff, "-y", "-t", "10", "-i", self.vid_path,
                                 "-vf", vf + ",palettegen", pal], capture_output=True)
            if r1.returncode != 0 or not os.path.exists(pal):
                self._ui(lambda: self.vid_status.configure(text="GIF 生成失败: " + r1.stderr.decode("utf-8", "replace")[-200:]))
                return
            r2 = subprocess.run([ff, "-y", "-t", "10", "-i", self.vid_path, "-i", pal,
                                 "-lavfi", vf + " [x]; [x][1:v] paletteuse", out], capture_output=True)
            msg = "GIF 导出完成: " + out if r2.returncode == 0 and os.path.exists(out) else \
                "GIF 合成失败: " + r2.stderr.decode("utf-8", "replace")[-200:]
            self._ui(lambda: self.vid_status.configure(text=msg))

        threading.Thread(target=work, daemon=True).start()

    def vid_ffplay(self):
        if not self.vid_path:
            return
        fp = _ffplay()
        if not fp:
            self.vid_status.configure(text="便携 ffplay 未就绪（随 ffmpeg GPL 版预置），可先用内置逐帧播放器")
            return
        import subprocess
        cmd = [fp, "-volume", str(self.vid_vol.get())]
        if self.vid_loop.get():
            cmd += ["-loop", "999"]
        spd = float(self.vid_speed.get())
        if abs(spd - 1.0) > 0.01:
            cmd += ["-vf", f"setpts={1 / spd:.4f}*PTS", "-af", f"atempo={spd:.3f}"]
        cmd += [self.vid_path]
        threading.Thread(target=lambda: subprocess.run(cmd, capture_output=True), daemon=True).start()
        self.vid_status.configure(text="已启动 ffplay 带声音播放窗口")

    def vid_frame_analyze(self):
        if self.vid_cap is None:
            return
        self.vid_snapshot()
        fp = self._snapshot_path()
        if os.path.exists(fp):
            self._run_analysis(fp, "视频帧")

    def _run_ffmpeg(self, cmd, done_msg):
        self.vid_status.configure(text="ffmpeg 处理中…（后台静默执行）")

        def work():
            import subprocess
            r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
            msg = done_msg if r.returncode == 0 else "ffmpeg 失败: " + r.stderr[-300:]
            self._ui(lambda: self.vid_status.configure(text=msg))

        threading.Thread(target=work, daemon=True).start()

    # ======================================================================
    # 音频隐写工作台
    # ======================================================================
    def _build_audio(self):
        bar = theme.toolbar(self.t_aud)
        bar.pack(fill="x", padx=8, pady=(10, 6))
        theme.button(bar, "打开音频", "subtle", width=88, height=28,
                     command=self.aud_open).pack(side="left", padx=(10, 3), pady=6)
        theme.button(bar, "完整隐写分析", "primary", width=116, height=28,
                     command=self.aud_analyze).pack(side="left", padx=3, pady=6)
        theme.button(bar, "播放（ffplay）", "subtle", width=104, height=28,
                     command=self.aud_play).pack(side="left", padx=3, pady=6)
        theme.button(bar, "打开输出目录", "ghost", width=112, height=28,
                     command=lambda: os.path.isdir(self.aud_outdir) and os.startfile(self.aud_outdir)).pack(
            side="left", padx=3, pady=6)

        bar2 = theme.toolbar(self.t_aud)
        bar2.pack(fill="x", padx=8, pady=(0, 6))
        ctk.CTkLabel(bar2, text="查看图", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(12, 4))
        for text, cmd, width in (("全频语谱图", lambda: self.aud_show("audio_spectrogram.png"), 96),
                                 ("低频放大", lambda: self.aud_show("audio_spectrogram_low.png"), 82),
                                 ("侧声道谱", lambda: self.aud_show("audio_spectrogram_side.png"), 82),
                                 ("波形图", lambda: self.aud_show("audio_waveform.png"), 72),
                                 ("反转音频", lambda: self.aud_play_file("audio_reversed.wav"), 82),
                                 ("侧声道", lambda: self.aud_play_file("audio_side.wav"), 72)):
            theme.button(bar2, text, "ghost", width=width, height=28,
                         command=cmd).pack(side="left", padx=3, pady=6)

        stage = theme.card(self.t_aud)
        stage.pack(fill="both", expand=True, padx=8, pady=(0, 6))
        self.aud_label = ctk.CTkLabel(stage, text_color=theme.TEXT_MUTE,
                                      font=theme.font(theme.FONT_SMALL),
                                      text="打开 WAV/MP3/FLAC/OGG/M4A 等音频后，点“完整隐写分析”，语谱图在此显示")
        self.aud_label.pack(fill="both", expand=True, pady=12)
        self._aud_photo = None
        self.aud_path = None
        self.aud_outdir = os.path.join(EXPORTS_DIR, "audio")
        os.makedirs(self.aud_outdir, exist_ok=True)
        self.aud_status = ctk.CTkLabel(self.t_aud, text="就绪", anchor="w",
                                       font=theme.font(theme.FONT_SMALL), text_color=theme.TEXT_MUTE)
        self.aud_status.pack(fill="x", padx=12, pady=(0, 2))
        self.aud_box = theme.textbox(self.t_aud, mono_font=True, size=12, height=170)
        self.aud_box.pack(fill="x", padx=8, pady=(0, 10))

    def aud_open(self, path=None):
        if not path:
            path = filedialog.askopenfilename(
                title="选择音频",
                filetypes=[("音频", " ".join("*" + e for e in AUDIO_EXTS)), ("所有文件", "*.*")])
        if not path:
            return
        self.aud_path = path
        base = safe_name(os.path.splitext(os.path.basename(path))[0])
        self.aud_outdir = os.path.join(EXPORTS_DIR, "audio_" + base)
        os.makedirs(self.aud_outdir, exist_ok=True)
        self.aud_status.configure(text="已选择: " + path)
        self.aud_box.delete("1.0", "end")
        self.aud_analyze()

    def aud_analyze(self):
        if not self.aud_path:
            return
        self.aud_status.configure(text="音频隐写分析中…（后台静默执行）")
        path, outdir = self.aud_path, self.aud_outdir

        def work():
            try:
                from .common import Report
                from . import modules_audio, modules_carve
                rep = Report(path=path)
                modules_audio.analyze(path, rep, outdir, do_carve=True)
                lines = []
                for fnd in rep.findings:
                    lines.append(f"({fnd.level}) {fnd.title}")
                    if fnd.detail:
                        for ln in str(fnd.detail).splitlines()[:12]:
                            lines.append("      " + ln)
                text = "\n".join(lines)
            except Exception as e:
                import traceback
                text = "分析失败: " + repr(e) + "\n" + traceback.format_exc()
            self._ui(lambda: self._aud_done(text))

        threading.Thread(target=work, daemon=True).start()

    def _aud_done(self, text):
        self.aud_box.delete("1.0", "end")
        self.aud_box.insert("1.0", text)
        self.aud_status.configure(text="分析完成，输出目录: " + self.aud_outdir)
        self.aud_show("audio_spectrogram.png")

    def aud_show(self, name):
        fp = os.path.join(self.aud_outdir, name)
        if not os.path.exists(fp):
            self.aud_status.configure(text=f"尚未生成 {name}，请先点“完整隐写分析”")
            return
        try:
            im = Image.open(fp)
            mw = max(200, self.aud_label.winfo_width() - 8)
            mh = max(160, self.aud_label.winfo_height() - 8)
            im.thumbnail((mw, mh), Image.LANCZOS)
            self._aud_photo = ImageTk.PhotoImage(im)
            self.aud_label.configure(image=self._aud_photo, text="")
            self.aud_status.configure(text="已显示: " + fp)
        except Exception as e:
            self.aud_status.configure(text=f"图像显示失败: {e}")

    def aud_play(self):
        if not self.aud_path:
            return
        fp = _ffplay()
        if not fp:
            self.aud_status.configure(text="便携 ffplay 未就绪")
            return
        import subprocess
        threading.Thread(target=lambda: subprocess.run([fp, self.aud_path], capture_output=True),
                         daemon=True).start()
        self.aud_status.configure(text="已启动 ffplay 播放: " + self.aud_path)

    def aud_play_file(self, name):
        fp = os.path.join(self.aud_outdir, name)
        if not os.path.exists(fp):
            self.aud_status.configure(text=f"尚未生成 {name}，请先点“完整隐写分析”")
            return
        player = _ffplay()
        if not player:
            os.startfile(fp)
            return
        import subprocess
        threading.Thread(target=lambda: subprocess.run([player, fp], capture_output=True),
                         daemon=True).start()
        self.aud_status.configure(text="正在播放: " + fp)

    # ======================================================================
    # 通用：分析弹窗
    # ======================================================================
    def _run_analysis(self, path, kind):
        win = ctk.CTkToplevel(self)
        win.title(f"{kind}隐写分析 - {os.path.basename(path)}")
        win.geometry("760x560")
        theme.apply_root(win)
        box = theme.textbox(win, mono_font=True, size=12)
        box.pack(fill="both", expand=True, padx=12, pady=12)
        box.insert("1.0", "分析中，请稍候…\n")

        def work():
            try:
                from .dispatcher import Dispatcher
                rep = Dispatcher(max_depth=3).run(path)
                lines = []

                def walk(r, d=0):
                    lines.append("  " * d + f"[{r.ftype}] {os.path.basename(r.path)}")
                    for fnd in r.findings:
                        lines.append("  " * d + f"  ({fnd.level}) {fnd.title}")
                        if fnd.detail:
                            for ln in str(fnd.detail).splitlines()[:60]:
                                lines.append("  " * d + f"      {ln}")
                    for c in r.children:
                        walk(c, d + 1)
                walk(rep)
                text = "\n".join(lines)
            except Exception as e:
                import traceback
                text = "分析失败: " + repr(e) + "\n" + traceback.format_exc()
            self._ui(lambda: (box.delete("1.0", "end"), box.insert("1.0", text)))

        threading.Thread(target=work, daemon=True).start()

    def _popup_text(self, title, text):
        win = ctk.CTkToplevel(self)
        win.title(title)
        win.geometry("560x420")
        theme.apply_root(win)
        box = theme.textbox(win, mono_font=True, size=12)
        box.pack(fill="both", expand=True, padx=12, pady=12)
        box.insert("1.0", text)
