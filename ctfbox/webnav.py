# -*- coding: utf-8 -*-
"""网页工具导航：离线镜像优先（tools/webtools），不可用时打开在线官网。

DATA 结构: {分类: [(显示名, 在线URL, 离线manifest的key或None, 说明)]}
离线 key 对应 _mirror_webtools.py 生成的 manifest.json 中的 offline 键。
"""
import os
import json

from .common import TOOLS_DIR

WEB_DIR = os.path.join(TOOLS_DIR, "webtools")

# key -> 在线URL（用于与离线 manifest 关联）
OFFLINE_KEYS = {
    "CyberChef": "https://gchq.github.io/CyberChef/",
    "pcmoe_roar": "https://hi.pcmoe.net/roar.html",
    "pcmoe_bear": "https://hi.pcmoe.net/bear.html",
    "pcmoe_buddha": "https://hi.pcmoe.net/buddha.html",
    "zero-width": "https://yuanfux.github.io/zero-width-web/",
    "qrazybox": "https://merri.cx/qrazybox/",
    "jwt": "offline://jwt",
    "base64_conv": "offline://base64_conv",
}

DATA = {
    "离线网页工具（已镜像到软件目录，断网可用）": [
        ("CyberChef 瑞士军刀", "https://gchq.github.io/CyberChef/", "CyberChef",
         "编码/解码/加密/压缩/数据处理一站式，完全离线"),
        ("JWT 解码器", "offline://jwt", "jwt", "本地 JWT Header/Payload/签名解码"),
        ("进制/Base64 转换", "offline://base64_conv", "base64_conv", "文本↔Hex/Base64/十进制/八进制"),
        ("兽音译者(嗷呜啊呀)", "https://hi.pcmoe.net/roar.html", "pcmoe_roar", "兽音加密离线页"),
        ("与熊论道/熊曰", "https://hi.pcmoe.net/bear.html", "pcmoe_bear", "熊语佛曰系编码离线页"),
        ("新约佛论禅", "https://hi.pcmoe.net/buddha.html", "pcmoe_buddha", "佛论禅离线页"),
        ("零宽字符隐写", "https://yuanfux.github.io/zero-width-web/", "zero-width", "零宽字符加解密离线页"),
        ("QRazyBox 二维码重构", "https://merri.cx/qrazybox/", "qrazybox", "损坏二维码手动修复/解码离线页"),
    ],
    "编码 / 密码 / 哈希 在线工具": [
        ("CyberChef 在线版", "https://gchq.github.io/CyberChef/", None, "离线版不可用时的在线官方版"),
        ("dCode 密码百科", "https://www.dcode.fr/en", None, "大量古典/现代密码识别与解码"),
        ("quipqiup 替换密码", "https://www.quipqiup.com/", None, "单表替换/凯撒自动求解"),
        ("CrackStation 哈希查询", "https://crackstation.net/", None, "大规模彩虹表在线查哈希"),
        ("hashes.com 哈希解密", "https://hashes.com/en/decrypt/hash", None, "多算法哈希在线碰撞"),
        ("在线条码识别 Inlite", "https://online-barcode-reader.inliteresearch.com/", None, "一维/二维条码在线识别"),
        ("URL 编码/格式化 等", "https://www.sojson.com/", None, "JSON/时间戳/编码等常用工具集合"),
    ],
    "文件 / 多媒体在线处理": [
        ("extract.me 在线解包", "https://extract.me/", None, "上百种压缩包在线解压（含分卷/带密码提示）"),
        ("aconvert 格式转换", "https://www.aconvert.com/cn/", None, "图片/文档/音视频/电子书格式互转"),
        ("VirusTotal 文件查杀", "https://www.virustotal.com/", None, "样本多引擎检测（勿传含 flag 敏感件）"),
    ],
    "CTF 做题平台 / 题库（需自行注册登录）": [
        ("BUUCTF / BUUOJ", "https://buuoj.cn/challenges", None, "题目最全的入门平台，Misc/Crypto/Web/Pwn"),
        ("攻防世界 XCTF", "https://adworld.xctf.org.cn/", None, "新手区+高手区，适合系统刷题"),
        ("CTFShow", "https://ctf.show/", None, "Web/Misc 题量大，有签到与通关路线"),
        ("CTFHub", "https://www.ctfhub.com/", None, "技能树+赛事+题库，入门体系化"),
        ("NSSCTF", "https://www.nssctf.cn/problem", None, "题目与比赛回放，社区活跃"),
        ("Bugku CTF", "https://ctf.bugku.com/", None, "老牌入门题库+在线工具"),
        ("青少年 CTF", "https://www.qsnctf.com/", None, "面向新手/赛事的中文平台"),
    ],
    "学习资料 / 检索": [
        ("CTF Wiki", "https://ctf-wiki.org/", None, "CTF 各方向知识库（可离线 clone）"),
        ("GTFOBins", "https://gtfobins.github.io/", None, "Linux 合法二进制提权/绕过集合"),
        ("LOLBAS (Windows)", "https://lolbas-project.github.io/", None, "Windows 原生程序滥用集合"),
        ("FOFA 网络空间测绘", "https://fofa.info/", None, "资产检索（仅授权目标）"),
        ("dirsearch 目录扫描", "https://github.com/maurosoria/dirsearch", None, "Web 目录爆破开源工具"),
        ("crontab 表达式", "https://crontab.guru/", None, "cron 时间表达式可视化"),
        ("PortSwigger Web 学院", "https://portswigger.net/web-security", None, "免费 Web 安全实验场"),
    ],
}


def load_offline_manifest():
    """返回 {key: 本地绝对路径}；文件不存在时返回空 dict。
    新版 manifest 存相对路径（软件文件夹可整体改名/搬迁），旧版绝对路径兼容。"""
    fp = os.path.join(WEB_DIR, "manifest.json")
    try:
        with open(fp, "r", encoding="utf-8") as f:
            m = json.load(f)
        out = {}
        for k, v in m.get("offline", {}).items():
            if not os.path.isabs(v):
                v = os.path.normpath(os.path.join(WEB_DIR, v))
            out[k] = v
        return out
    except Exception:
        return {}


def offline_path(key):
    if not key:
        return None
    p = load_offline_manifest().get(key)
    if p and os.path.exists(p):
        return p
    # 容错：目录存在但 manifest 缺失时，猜测常见入口
    if key:
        d = os.path.join(WEB_DIR, key)
        if os.path.isdir(d):
            for guess in ("index.html", "roar.html", "bear.html", "buddha.html"):
                gp = os.path.join(d, guess)
                if os.path.exists(gp):
                    return gp
    return None
