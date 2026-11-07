# -*- coding: utf-8 -*-
# 脚本名称: 音频语谱图/波形图生成（肉眼看 flag）
# 方向: Misc（音频隐写）
# 简介: Misc 音频题最常见套路是把 flag 画进语谱图（频谱随时间变化）。
#       本脚本把任意 ffmpeg 可解码音频（mp3/wav/flac/ogg/m4a）转成：
#       全频语谱图、低频放大图、左右声道差（中置消除）图与波形图，
#       生成后自动打开图片目录。
# 用法:
#   python audio_spectrogram.py secret.mp3
#   python audio_spectrogram.py secret.wav --out out_dir --nfft 4096
#   python audio_spectrogram.py --selftest
# 依赖: pip install numpy matplotlib pillow；非 WAV 还需 ffmpeg（软件 tools/portable/ffmpeg 自带）
import argparse
import os
import subprocess
import shutil
import wave
import numpy as np


def decode_to_wav(path, outdir):
    if path.lower().endswith(".wav"):
        return path
    out = os.path.join(outdir, "decoded.wav")
    ff = shutil.which("ffmpeg")
    if not ff:
        for cand in (r"D:\工具合集软件\魔盒-ctf\tools\portable\ffmpeg\ffmpeg.exe",):
            if os.path.exists(cand):
                ff = cand
    if not ff:
        raise RuntimeError("非 WAV 需要 ffmpeg，请在工具中心预置或自行安装")
    subprocess.run([ff, "-y", "-i", path, "-ac", "1", "-ar", "44100", out],
                   capture_output=True)
    return out


def read_wav(path):
    with wave.open(path, "rb") as w:
        nch, sw, fr, n = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
        raw = w.readframes(n)
    if sw == 1:
        data = np.frombuffer(raw, np.uint8).astype(np.float32) - 128
    elif sw == 2:
        data = np.frombuffer(raw, np.int16).astype(np.float32)
    elif sw == 4:
        data = np.frombuffer(raw, np.int32).astype(np.float32)
    else:
        raise RuntimeError(f"不支持采样宽度 {sw}")
    if nch > 1:
        data = data.reshape(-1, nch)
        mono = data.mean(axis=1)
        side = (data[:, 0] - data[:, 1]) / 2
        return fr, mono, side
    return fr, data, None


def save_spec(sig, fr, out, nfft, title):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(16, 6))
    ax.specgram(sig, NFFT=nfft, Fs=fr, noverlap=nfft * 3 // 4, cmap="gray")
    ax.set_xlabel("Time (s)"); ax.set_ylabel("Freq (Hz)"); ax.set_title(title)
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("[+]", out)


def run(path, outdir, nfft=2048):
    os.makedirs(outdir, exist_ok=True)
    wav = decode_to_wav(path, outdir)
    fr, mono, side = read_wav(wav)
    save_spec(mono, fr, os.path.join(outdir, "spectrogram_full.png"), nfft, "Full spectrogram")
    save_spec(mono, fr, os.path.join(outdir, "spectrogram_low.png"), nfft * 2, "Low frequency (0-4k)")
    if side is not None:
        save_spec(side, fr, os.path.join(outdir, "spectrogram_side.png"), nfft, "Side channel (L-R)")
    # 波形
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(16, 3))
    ax.plot(mono[:fr * 30], linewidth=0.4)
    fig.savefig(os.path.join(outdir, "waveform.png"), dpi=120, bbox_inches="tight")
    plt.close(fig)
    print("[+] 波形图已生成；若图中出现字符即为 flag（可尝试反相/反色查看）")
    os.startfile(outdir) if os.name == "nt" else None


def selftest():
    d = os.path.join(os.environ.get("TEMP", "."), "spec_self")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "t.wav")
    fr = 22050
    t = np.linspace(0, 2, fr * 2, endpoint=False)
    sig = (0.3 * np.sin(2 * np.pi * 440 * t) * (np.sin(2 * np.pi * 3 * t) > 0)).astype(np.float32)
    import struct
    frames = b"".join(struct.pack("<h", int(max(-32767, min(32767, x * 32767)))) for x in sig)
    with wave.open(p, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(fr); w.writeframes(frames)
    run(p, os.path.join(d, "out"))
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="音频语谱图")
    ap.add_argument("audio", nargs="?")
    ap.add_argument("--out")
    ap.add_argument("--nfft", type=int, default=2048)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.audio:
        print("[!] 用法: python audio_spectrogram.py secret.mp3"); return
    out = a.out or os.path.join(os.path.dirname(a.audio) or ".",
                                os.path.splitext(os.path.basename(a.audio))[0] + "_spec")
    run(a.audio, out, a.nfft)


if __name__ == "__main__":
    main()
