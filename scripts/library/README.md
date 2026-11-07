# 魔盒-ctf 内置 CTF 脚本库（v2.5）

共 **88** 个文件，按 7 个方向分类，已集成到软件「📚 脚本库」标签页。
所有 `.py` 脚本均为**单文件自包含**（不依赖同目录其他脚本，可直接复制到 Kali / 题目环境运行）；
文件头注释统一包含：脚本名称 / 方向 / 简介 / 用法 / 依赖 / 参考；绝大多数支持 `--selftest` 自测。

运行约定：

```bash
python 脚本.py --selftest          # 自测（无需题目环境）
python 脚本.py -h                  # 查看参数
```

> 说明：Pwn 类脚本的自测需 Linux（gcc 生成 ELF），Windows 下会自动跳过；
> `misc/audio_spectrogram.py` 需 matplotlib + ffmpeg（建议在 Kali/外部 Python 使用）；
> `reverse/angr_solver_template.py` 需 angr；`web/webshell_python.py` 需 flask。
> 所有脚本仅限 CTF 比赛、靶场与授权测试使用。

---

## Crypto 密码学（22）

| 脚本 | 简介 |
|---|---|
| rsa_wiener_attack.py | Wiener 小公钥指数（d 连续分数）攻击 |
| rsa_common_modulus.py | 共模攻击（同 N 不同 e） |
| rsa_small_exponent.py | 低指数 e=3 直接开方 / Hastad 广播 CRT |
| rsa_fermat.py | Fermat 相邻素数分解 |
| rsa_dp_leak.py | 已知 dp（或 dq）泄露恢复明文 |
| rsa_batch_gcd.py | 批量 GCD / cofactor 分解（多个 N 共享素数） |
| pollard_rho_factor.py | Pollard rho（Brent 优化）整数分解 |
| rsa_decrypt.py | 已知 p/q/d 等参数的 RSA 解密通用工具 |
| rsa_lsb_oracle.py | LSB 奇偶预言机逐位解密（含二分/邻域 flag 搜索） |
| rsa_all_in_one.py | RSA 攻击全家桶入口（自动判别可利用条件） |
| xor_single_byte.py | 单字节 XOR 爆破（英文评分） |
| xor_repeating_key.py | 多字节重复密钥 XOR 破解（全密钥长度评分） |
| rc4.py | RC4 加解密（RFC6229 测试向量自测） |
| aes_cbc_padding_oracle.py | AES-CBC Padding Oracle（含本地靶场） |
| base_family_decode.py | Base16/32/58/64/85/91 全家桶（内置 base91） |
| classical_crack.py | 凯撒/ROT/仿射/栅栏/摩斯/键盘密码等古典密码 |
| vigenere_crack.py | 维吉尼亚密码破解（密钥长度遍历+重合指数/评分） |
| hash_dict_crack.py | 哈希字典爆破（MD5/SHA 系列） |
| jwt_crack.py | JWT 弱密钥爆破 / none 算法 / 解码 |
| flask_session_tool.py | Flask session 伪造与解码（itsdangerous） |
| ecdsa_nonce_reuse.py | ECDSA nonce 复用恢复私钥（secp256k1/P-256） |
| tea_xtea_xxtea.py | TEA/XTEA/XXTEA 加解密 |

## Misc 杂项 / 隐写（18）

| 脚本 | 简介 |
|---|---|
| lsb_stego_png.py | PNG LSB 隐写提取/写入（RGB 位平面） |
| png_ihdr_fix.py | PNG IHDR 宽高被改的修复（CRC 爆破真实尺寸） |
| gif_split_frames.py | GIF 逐帧拆分 |
| image_tile_montage.py | 图片切片拼图/九宫格还原 |
| pixel_matrix_qr.py | 像素矩阵二维码重建（按模块放大输出 PNG） |
| qrcode_decode.py | 二维码/条形码识别 |
| file_carver.py | 文件签名雕刻（头尾匹配提取内嵌文件） |
| zip_crc_crack.py | ZIP 小文件 CRC 碰撞还原明文 |
| zip_unlock_dict.py | ZIP 字典爆破 + 伪加密修复 |
| zero_width_stego.py | 零宽字符隐写提取（ZWC/零宽空格映射） |
| exif_dump.py | EXIF/XMP/注释元数据查看 |
| docx_hidden_extract.py | docx/xlsx/pptx 内部 XML 与隐藏内容提取 |
| pdf_hidden_extract.py | PDF 对象流/隐藏文字/附件提取 |
| audio_lsb_wav.py | WAV LSB 音频隐写提取 |
| audio_spectrogram.py | 音频频谱图隐写（需 matplotlib/ffmpeg，外部环境用） |
| fake_header_fix.py | 文件头损坏修复（按签名库） |
| strings_enhanced.py | 增强版 strings（ASCII/UTF-16、最小长度、编码统计） |
| entropy_map.py | 文件熵分布图/分段熵定位加密压缩块 |

## Web 安全（15）

| 文件 | 简介 |
|---|---|
| dirscan.py | 多线程目录扫描（内置字典/状态码过滤） |
| backup_scan.py | 备份文件/源码泄露扫描（.git/.svn/.bak/www.zip 等） |
| subdomain_brute.py | 子域名字典爆破 |
| http_probe.py | HTTP 存活探测（标题/Server/证书/跳转） |
| reverse_shell_gen.py | 19 种反弹 shell payload 生成（bash/py/php/nc/powershell…） |
| webshell_php.php | PHP 一句话 WebShell（带口令与落地自检） |
| webshell_python.py | Flask 版 Python WebShell（需 flask） |
| webshell_jsp.jsp | JSP 命令执行 WebShell（Tomcat） |
| webshell_aspx.aspx | ASP.NET(C#) 命令执行 WebShell（IIS） |
| sqlmap_cheatsheet.txt | sqlmap 常用参数/绕过/Tamper 速查 |
| lfi_path_traversal_cheatsheet.txt | 文件包含/目录穿越 payload 速查 |
| ssti_payloads.txt | SSTI 模板注入 payload（Jinja2/Twig/Freemarker/Velocity…） |
| ssrf_payloads.txt | SSRF payload（云元数据/协议/内网地址） |
| xss_payloads.txt | XSS payload 与过滤绕过合集 |
| command_injection_cheatsheet.txt | 命令注入分隔符/绕过/无回显速查 |

## Pwn 二进制（9）

| 文件 | 简介 |
|---|---|
| pwntools_exp_template.py | pwntools 标准 EXP 模板（本地/远程切换、调试钩子） |
| ret2text.py | ret2text（返回 .text 后门函数） |
| ret2shellcode.py | ret2shellcode（shellcode 写入可执行段） |
| ret2syscall_rop.py | ret2syscall / ROP（静态编译 int 0x80 链） |
| format_string.py | 格式化字符串任意读写（pwntools fmtstr） |
| canary_leak_bypass.py | Canary 泄露 + 栈溢出绕过 |
| heap_uaf_fastbin_template.py | fastbin UAF/double free 堆利用模板 |
| checksec_binary.py | 二进制保护检查（NX/Canary/PIE/RELRO） |
| gdb_pwndbg_cheatsheet.txt | gdb+pwndbg 调试命令速查 |

> Pwn 脚本自测需 Linux gcc 环境，Windows 下自动跳过；脚本本身可直接在 Kali/WSL 使用。

## Reverse 逆向（8）

| 文件 | 简介 |
|---|---|
| pe_elf_patch.py | PE/ELF 补丁（按偏移/特征码改字节，自动修复校验） |
| pyc_magic_repair.py | pyc magic/头部损坏修复（重建 16 字节头） |
| angr_solver_template.py | angr 符号执行解题模板（需 angr） |
| xor_obfuscation_decrypt.py | 逆向常见 XOR 混淆（单字节爆破/已知明文/多字节） |
| upx_unpack_guide.txt | UPX 脱壳与手动脱壳指南 |
| ida_ghidra_cheatsheet.txt | IDA/Ghidra 常用操作与快捷键速查 |
| android_apk_reverse_guide.txt | Android APK 逆向流程（jadx/frida/so） |
| dotnet_reverse_guide.txt | .NET 逆向（dnSpy/IL 补丁/反混淆） |

## Forensics 取证（8）

| 文件 | 简介 |
|---|---|
| pcap_http_extract.py | pcap HTTP 对象还原（请求/响应/上传文件提取） |
| pcap_dns_exfil.py | DNS 隧道/外带数据分析（子域名编码还原） |
| usb_hid_keylog.py | USB HID 键盘流量还原按键 |
| evtx_deep_parse.py | Windows EVTX 事件日志深度解析 |
| registry_hive_parse.py | 注册表 hive（SAM/SYSTEM/NTUSER）解析 |
| volatility_cheatsheet.txt | Volatility 内存取证命令速查 |
| wpa_handshake_guide.txt | WiFi WPA 握手包提取与破解流程 |
| disk_forensics_cheatsheet.txt | 磁盘镜像取证（TSK/雕刻/NTFS/加密容器/固件） |

## Utils 实用工具（8）

| 文件 | 简介 |
|---|---|
| hash_identify.py | 哈希类型识别（含 hashcat/john 模式号）+ 哈希计算 |
| encode_decode_hub.py | 16 种编码自动识别解码/编码（Base 全家桶/Morse/URL…） |
| port_scan.py | 多线程端口扫描（内置 CTF 高频端口与服务指纹） |
| ssh_brute.py | SSH 弱口令爆破（paramiko，仅授权测试） |
| binary_diff.py | 二进制/文本差异对比（偏移定位+滑动重同步） |
| file_hash_batch.py | 批量文件哈希清单/完整性校验/找重复 |
| linux_privesc_cheatsheet.txt | Linux 提权/后渗透信息收集速查 |
| windows_privesc_cheatsheet.txt | Windows 提权/后渗透速查 |

---

## 参考来源（clean-room 实现依据）

- CTF Wiki（密码学/Pwn/Misc/Reverse/取证各专题公式与流程）
- RFC 官方测试向量（RC4 RFC6229、AES FIPS-197、各类编码 RFC）
- Cryptopals Crypto Challenges（XOR / Padding Oracle / RSA 系列）
- PayloadsAllTheThings、GTFOBins/LOLBAS、HackTricks（payload 与提权清单）
- pwntools 官方文档、Volatility 官方手册、The Sleuth Kit 文档

脚本均为依据公开算法/公式独立编写的自包含实现，未复制第三方代码。
