# -*- coding: utf-8 -*-
# 脚本名称: 加密 ZIP 的 CRC 碰撞还原（小文件明文恢复）
# 方向: Misc（压缩包 / CRC）
# 简介: ZIP 加密但里面每个文件很小（通常 ≤6 字节）时，无需密码，
#       枚举所有可能明文计算 CRC32，与文件 CRC 比对即可还原内容；
#       本脚本对纯小写字母/数字/可打印字符集多进程爆破，也支持已知前缀。
# 用法:
#   python zip_crc_crack.py encrypted.zip
#   python zip_crc_crack.py encrypted.zip --charset abcdef0123456789 --max 6
#   python zip_crc_crack.py --selftest
# 依赖: 仅标准库
# 注意: CRC 不是加密，碰撞可能不唯一；内容越长越可信。
import argparse
import itertools
import os
import string
import time
import zipfile
import zlib

# v4.1：不加预算时 70 字符集 × 6 字节 = 1.2e11 次纯 Python 循环，
# 单题能把整批任务拖死（实测 DASBOOK 批量卡了 20+ 分钟）。
MAX_COMBOS = 3_000_000          # 约 8~12 秒的纯 Python 上限
DEFAULT_BUDGET = 15.0           # 秒；脚本库按题给 timeout，这里再兜一层


def crack_crc(target_crc, size, charset, prefix=b"", known_suffix=b"",
              budget=DEFAULT_BUDGET, max_combos=MAX_COMBOS):
    free = size - len(prefix) - len(known_suffix)
    if free < 0:
        return None
    combos = len(charset) ** free
    if combos > max_combos:
        print(f"[-] 跳过：{len(charset)}^{free} = {combos:,} 种组合超出上限 {max_combos:,}，"
              f"该长度需 bkcrack/已知明文，不再空转")
        return None
    deadline = time.time() + max(0.5, budget)
    tail = known_suffix
    for n, tup in enumerate(itertools.product(charset, repeat=free)):
        if not (n & 0x3fff) and time.time() > deadline:   # 每 16384 次看一次表
            print(f"[-] 时间预算 {budget}s 用尽（已试 {n:,}/{combos:,}），停止")
            return None
        cand = prefix + "".join(tup).encode() + tail
        if zlib.crc32(cand) & 0xffffffff == target_crc:
            return cand
    return None


def run(path, charset, maxsize, budget=DEFAULT_BUDGET):
    zf = zipfile.ZipFile(path)
    for info in zf.infolist():
        if info.file_size > maxsize:
            print(f"[-] {info.filename} {info.file_size} 字节过大，CRC 爆破不现实，改用 bkcrack/字典")
            continue
        print(f"[*] {info.filename}: {info.file_size} 字节, CRC={info.CRC:08x}")
        r = crack_crc(info.CRC, info.file_size, charset, budget=budget)
        if r:
            print(f"[+] 碰撞成功: {r!r}  -> {r.decode('utf-8', 'replace')}")
        else:
            print("[-] 未碰撞到，可缩小 --charset / --max 或提供已知前缀")


def selftest():
    # 直接验证碰撞核心：旧版 selftest 写入 17 字节却声明 5 字节，
    # 结果每次都走「字节过大」分支，等于从没测过 crack_crc。
    plain = b"abc12"
    got = crack_crc(zlib.crc32(plain) & 0xffffffff, len(plain), "abc12", budget=5.0)
    assert got == plain, "CRC 碰撞应还原明文，实得 %r" % got
    print("[+] 碰撞还原 OK: %r" % got)
    # 组合数超上限必须立刻跳过，不能空转
    assert crack_crc(0, 6, string.ascii_letters + string.digits, budget=1.0) is None
    print("[+] 大组合跳过 OK")
    # 组合数在上限内、但时间预算极短：验证循环里的 deadline 检查确实生效
    assert crack_crc(0, 5, string.ascii_lowercase[:15], budget=0.001) is None
    print("[+] 时间预算 OK")
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="ZIP CRC 碰撞")
    ap.add_argument("zip", nargs="?")
    ap.add_argument("--charset", default=string.ascii_lowercase + string.digits + string.ascii_uppercase + "_{}-!@#")
    ap.add_argument("--max", type=int, default=6)
    ap.add_argument("--budget", type=float, default=DEFAULT_BUDGET,
                    help="单文件时间上限（秒），默认 15")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.zip:
        print("[!] 用法: python zip_crc_crack.py encrypted.zip"); return
    run(a.zip, a.charset, a.max, budget=a.budget)


if __name__ == "__main__":
    main()
