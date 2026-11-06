# -*- coding: utf-8 -*-
"""SSH 终端标签页（paramiko 实现，替代 Xshell 的核心连接需求）。"""
import os
import queue
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox

from . import ui_theme as theme

try:
    import paramiko
except Exception:
    paramiko = None


class SSHTab(ctk.CTkFrame):
    def __init__(self, master, **kw):
        kw.setdefault("fg_color", "transparent")
        super().__init__(master, **kw)
        self.client = None
        self.shell = None
        self.sftp = None
        self.q = queue.Queue()
        self._build()
        self.after(80, self._drain)

    def _build(self):
        bar = theme.toolbar(self)
        bar.pack(fill="x", padx=8, pady=(10, 6))
        ctk.CTkLabel(bar, text="主机", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(12, 4))
        self.host = theme.entry(bar, width=152, placeholder_text="192.168.1.1")
        self.host.pack(side="left", pady=8)
        self.host.insert(0, "192.168.1.1")
        ctk.CTkLabel(bar, text="端口", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(10, 4))
        self.port = theme.entry(bar, width=64)
        self.port.pack(side="left")
        self.port.insert(0, "22")
        ctk.CTkLabel(bar, text="用户", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(10, 4))
        self.user = theme.entry(bar, width=104, placeholder_text="root")
        self.user.pack(side="left")
        self.user.insert(0, "root")
        ctk.CTkLabel(bar, text="密码", font=theme.font(theme.FONT_SMALL),
                     text_color=theme.TEXT_MUTE).pack(side="left", padx=(10, 4))
        self.pwd = theme.entry(bar, width=132, show="*")
        self.pwd.pack(side="left")
        self.key_btn = theme.button(bar, "选择私钥（可选）", "ghost", width=124,
                                    command=self._pick_key)
        self.key_btn.pack(side="left", padx=(10, 0))
        self.disconnect_btn = theme.button(bar, "断开", "subtle", width=80,
                                           state="disabled", command=self._disconnect)
        self.disconnect_btn.pack(side="right", padx=(0, 10), pady=8)
        self.connect_btn = theme.button(bar, "连接", "primary", width=84, command=self._connect)
        self.connect_btn.pack(side="right", padx=(0, 6), pady=8)
        self.key_path = None

        bar2 = theme.toolbar(self)
        bar2.pack(fill="x", padx=8, pady=(0, 6))
        theme.button(bar2, "SFTP 上传文件…", "subtle", width=134,
                     command=self._sftp_up).pack(side="left", padx=(10, 0), pady=6)
        theme.button(bar2, "SFTP 下载远程文件…", "subtle", width=156,
                     command=self._sftp_down).pack(side="left", padx=6, pady=6)
        theme.button(bar2, "用 MobaXterm 打开（Xshell 平替）", "primary", width=224,
                     command=self._open_mobaxterm).pack(side="left", padx=6, pady=6)
        self.remote_path = theme.entry(bar2, width=260, placeholder_text="远程路径（下载用）如 /home/root/flag.txt")
        self.remote_path.pack(side="left", padx=6)
        self.status = ctk.CTkLabel(bar2, text="未连接", text_color=theme.WARNING,
                                   font=theme.font(theme.FONT_SMALL, "bold"))
        self.status.pack(side="right", padx=12)

        self.screen = theme.textbox(self, mono_font=True, size=13)
        self.screen.pack(fill="both", expand=True, padx=8, pady=(0, 6))
        self.screen.configure(state="disabled")

        sendbar = theme.toolbar(self)
        sendbar.pack(fill="x", padx=8, pady=(0, 10))
        theme.hint(sendbar, "命令", side="left", padx=(12, 6), pady=7)
        self.cmd = theme.entry(sendbar, placeholder_text="输入命令后回车（连接状态下直接键入也可）")
        self.cmd.pack(side="left", fill="x", expand=True, padx=(0, 10), pady=6)
        self.cmd.bind("<Return>", lambda e: self._send_line())
        self.screen.bind("<Key>", self._type_key)

    def _pick_key(self):
        p = filedialog.askopenfilename(title="选择私钥文件")
        if p:
            self.key_path = p
            self.key_btn.configure(text=os.path.basename(p))

    def _open_mobaxterm(self):
        """启动便携 MobaXterm Home（Xshell 免费平替）；未下载时引导到工具中心一键安装。"""
        import subprocess
        from . import toolsmgr
        exe = toolsmgr.detect_one("mobaxterm")
        if not exe:
            messagebox.showinfo(
                "未安装 MobaXterm",
                "尚未下载便携 MobaXterm Home。\n请前往「工具中心」找到 MobaXterm Home 点击一键安装"
                "（约 44MB，官方免费便携版，解压即用）。")
            return
        host = self.host.get().strip() or "192.168.1.1"
        user = self.user.get().strip() or "root"
        try:
            port = int(self.port.get().strip())
        except ValueError:
            port = 22
        try:
            # 便携版可执行名随版本变化；直接启动主程序（其内置多标签 SSH/SFTP/串口/X11）
            subprocess.Popen([exe], cwd=os.path.dirname(exe))
            tip = f"\n*** 已启动 MobaXterm Home：{exe}\n"
            tip += f"*** 可在 MobaXterm 中新建 SSH 会话：{user}@{host}:{port}"
            tip += "（也可继续使用本页内置 paramiko 终端直连）\n"
            self._write_screen(tip)
        except Exception as e:
            messagebox.showerror("启动失败", str(e))

    def _write_screen(self, text):
        self.screen.configure(state="normal")
        self.screen.insert("end", text)
        self.screen.see("end")
        self.screen.configure(state="disabled")

    def _connect(self):
        if paramiko is None:
            messagebox.showerror("错误", "paramiko 未安装")
            return
        host = self.host.get().strip()
        try:
            port = int(self.port.get().strip())
        except ValueError:
            port = 22
        user = self.user.get().strip()
        pwd = self.pwd.get()
        self._write_screen(f"\n*** 正在连接 {user}@{host}:{port} ...\n")

        def work():
            try:
                cli = paramiko.SSHClient()
                cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                kw = dict(port=port, username=user, timeout=12,
                          look_for_keys=False, allow_agent=False)
                if self.key_path:
                    kw["key_filename"] = self.key_path
                    if pwd:
                        kw["passphrase"] = pwd
                else:
                    kw["password"] = pwd
                cli.connect(host, **kw)
                self.client = cli
                self.shell = cli.invoke_shell(width=160, height=48)
                try:
                    self.sftp = cli.open_sftp()
                except Exception:
                    self.sftp = None
                self.q.put(("status", "已连接"))
                threading.Thread(target=self._reader, daemon=True).start()
            except Exception as e:
                self.q.put(("text", f"*** 连接失败: {e}\n"))

        threading.Thread(target=work, daemon=True).start()

    def _reader(self):
        try:
            while self.shell and not self.shell.closed:
                data = self.shell.recv(4096)
                if not data:
                    break
                self.q.put(("text", data.decode("utf-8", errors="replace")))
        except Exception:
            pass
        self.q.put(("text", "\n*** 连接已关闭 ***\n"))
        self.q.put(("status", "未连接"))

    def _drain(self):
        try:
            while True:
                kind, val = self.q.get_nowait()
                if kind == "text":
                    self._write_screen(val)
                elif kind == "status":
                    self.status.configure(text=val,
                                          text_color=theme.SUCCESS if val == "已连接" else theme.WARNING)
                    self.connect_btn.configure(state="normal" if val != "已连接" else "disabled")
                    self.disconnect_btn.configure(state="normal" if val == "已连接" else "disabled")
        except queue.Empty:
            pass
        self.after(80, self._drain)

    def _send_line(self):
        if self.shell and not self.shell.closed:
            self.shell.send(self.cmd.get().encode() + b"\n")
            self.cmd.delete(0, "end")

    def _type_key(self, event):
        """终端内直接键入（支持可见字符、回车、退格、Ctrl+C）。"""
        if not self.shell or self.shell.closed:
            return
        if event.keysym == "Return":
            self.shell.send(b"\r")
        elif event.keysym == "BackSpace":
            self.shell.send(b"\x7f")
        elif event.keysym == "Tab":
            self.shell.send(b"\t")
            return "break"
        elif event.keysym == "c" and (event.state & 0x4):
            self.shell.send(b"\x03")
        elif event.char and len(event.char) == 1:
            self.shell.send(event.char.encode())

    def _sftp_up(self):
        if not self.sftp:
            messagebox.showinfo("提示", "请先建立连接")
            return
        p = filedialog.askopenfilename(title="选择要上传的本地文件")
        if not p:
            return
        try:
            remote = "/tmp/" + os.path.basename(p)
            self.sftp.put(p, remote)
            self._write_screen(f"\n*** 已上传 {p} -> {remote}\n")
        except Exception as e:
            messagebox.showerror("上传失败", str(e))

    def _sftp_down(self):
        if not self.sftp:
            messagebox.showinfo("提示", "请先建立连接")
            return
        rp = self.remote_path.get().strip()
        if not rp:
            messagebox.showinfo("提示", "请填写远程文件路径")
            return
        p = filedialog.asksaveasfilename(initialfile=os.path.basename(rp))
        if not p:
            return
        try:
            self.sftp.get(rp, p)
            self._write_screen(f"\n*** 已下载 {rp} -> {p}\n")
        except Exception as e:
            messagebox.showerror("下载失败", str(e))

    def _disconnect(self):
        try:
            if self.shell:
                self.shell.close()
            if self.client:
                self.client.close()
        except Exception:
            pass
        self.shell, self.client, self.sftp = None, None, None
        self.status.configure(text="未连接", text_color=theme.WARNING)
