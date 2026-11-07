# -*- coding: utf-8 -*-
"""攻防验证：WAF / NGFW 策略检查清单、检测用例与加固前后报告模板。

安全边界：
- 只生成清单、用例和模板，不向任何地址发送请求；
- 用例使用无害 canary / 不存在路径 / 回环关闭端口，目标是验证「是否拦截/告警」，
  不包含绕过、免杀、持久化或真实利用链；
- 必须由使用者在自有 staging / 授权资产上人工执行并留存日志。
"""
import csv
import json
import os
import time

from . import util

WAF_CHECKS = [
    {"id": "waf-deploy", "severity": "high", "category": "部署",
     "title": "WAF 部署位置与流量覆盖",
     "requirement": "所有对外 HTTP(S) 入口（含备用域名、CDN 回源、API 网关）均经过同一 WAF 策略；确认旁路/直连 IP 已封堵。",
     "evidence": "网络拓扑、负载均衡转发链、CDN 回源白名单、WAF 节点清单。",
     "remediation": "补齐旁路入口；回源仅允许 WAF 回源 IP；定期对比 DNS 解析与 WAF 资产清单。"},
    {"id": "waf-mode", "severity": "high", "category": "部署",
     "title": "防护模式与阻断策略",
     "requirement": "生产环境为阻断模式而非仅告警；灰度期可先告警，但必须有明确的转阻断时间点和责任人。",
     "evidence": "WAF 控制台策略模式截图、变更单、转阻断时间记录。",
     "remediation": "按业务白名单完成误报收敛后切阻断；保留紧急降级开关与审批流程。"},
    {"id": "waf-crs", "severity": "medium", "category": "规则",
     "title": "基础规则集与版本",
     "requirement": "启用 OWASP CRS 或厂商等效规则集，版本可查且近 90 天有更新记录；关闭规则需逐条登记原因。",
     "evidence": "规则集版本号、更新日志、禁用规则清单及审批记录。",
     "remediation": "建立月度规则更新窗口；对禁用规则做季度复核。"},
    {"id": "waf-sqli", "severity": "high", "category": "规则",
     "title": "SQL 注入防护",
     "requirement": "URL、表单、JSON、Cookie、Header 全通道启用 SQLi 检测；对报错/布尔/时间/堆叠注入均有关键规则。",
     "evidence": "规则命中测试记录；参数化查询覆盖情况；数据库错误页已关闭。",
     "remediation": "开启全通道检查；后端统一参数化查询，WAF 只作纵深防御。"},
    {"id": "waf-xss", "severity": "high", "category": "规则",
     "title": "XSS 防护",
     "requirement": "反射型、存储型、DOM 型场景均有检测；上传的 HTML/SVG 响应带 Content-Disposition 或独立域。",
     "evidence": "规则命中记录、CSP/HttpOnly/SameSite 配置、上传目录响应头。",
     "remediation": "启用 XSS 规则与响应头加固；富文本使用白名单过滤。"},
    {"id": "waf-rce", "severity": "high", "category": "规则",
     "title": "命令注入 / 代码执行防护",
     "requirement": "对参数中的 shell 元字符、反引号、编码变形启用检测；禁止将用户输入传入 system/exec/eval。",
     "evidence": "规则集清单、代码审计报告、命令执行白名单。",
     "remediation": "后端改为参数数组调用/安全 API；WAF 规则覆盖编码与分块传输。"},
    {"id": "waf-lfi", "severity": "high", "category": "规则",
     "title": "路径穿越 / 文件包含防护",
     "requirement": "对 ../、编码穿越、绝对路径、文件协议（file://、php://）启用检测；上传目录禁止脚本执行。",
     "evidence": "规则命中记录、Nginx/Apache 上传目录配置、文件包含白名单。",
     "remediation": "上传目录关闭脚本解析；文件读取使用 ID 映射而非路径。"},
    {"id": "waf-ssrf", "severity": "high", "category": "规则",
     "title": "SSRF 防护",
     "requirement": "对用户可控 URL 做协议/域名/IP 白名单；阻断回环、内网段、云元数据地址；出站流量有审计。",
     "evidence": "URL 白名单、出站 ACL、云元数据访问日志。",
     "remediation": "强制白名单与 DNS 解析后校验；禁止跟随重定向到内网。"},
    {"id": "waf-xxe", "severity": "high", "category": "规则",
     "title": "XXE 防护",
     "requirement": "阻断带 DOCTYPE/外部实体的 XML；后端解析器禁用外部实体与 DTD。",
     "evidence": "WAF 规则命中、XML 解析器安全配置。",
     "remediation": "统一使用禁用外部实体的解析配置；非必要不接收 XML。"},
    {"id": "waf-deser", "severity": "high", "category": "规则",
     "title": "反序列化特征防护",
     "requirement": "对 Java 序列化魔数、PHP serialized、pickle、ViewState 等异常内容有检测；业务不应接收原生序列化数据。",
     "evidence": "Content-Type 白名单、规则命中记录、反序列化白名单过滤器。",
     "remediation": "改用 JSON/Protobuf；必须反序列化时启用类白名单与签名。"},
    {"id": "waf-upload", "severity": "high", "category": "规则",
     "title": "文件上传策略",
     "requirement": "按扩展名 + MIME + 文件头三重校验；禁止可执行脚本；图片二次渲染；上传目录独立域名/不可执行。",
     "evidence": "上传接口配置、文件头校验代码、上传目录权限与响应头。",
     "remediation": "服务端强制白名单与重命名；对象存储禁止脚本解析。"},
    {"id": "waf-webshell", "severity": "medium", "category": "规则",
     "title": "Webshell 检测与告警",
     "requirement": "对常见一句话/冰蝎/哥斯拉流量与落地文件有检测；告警能进入 SIEM 并有人值守。",
     "evidence": "检测规则、告警工单、应急响应演练记录。",
     "remediation": "开启文件完整性监控与出站审计；定期复盘告警闭环。"},
    {"id": "waf-api", "severity": "medium", "category": "规则",
     "title": "API 与 JSON 深度检测",
     "requirement": "JSON body、GraphQL、multipart、WebSocket 均在检测范围；按 OpenAPI schema 做参数校验。",
     "evidence": "API 网关配置、schema 校验开关、WAF 解析模式。",
     "remediation": "开启 JSON 解析与 schema 校验；限制 GraphQL 深度与批量查询。"},
    {"id": "waf-ratelimit", "severity": "medium", "category": "访问控制",
     "title": "限速与暴力破解防护",
     "requirement": "登录、短信、查询接口有 IP/账号/设备维度限速与锁定；阈值经过压测，误伤可控。",
     "evidence": "限速策略、压测报告、账号锁定日志。",
     "remediation": "按接口分级限速；登录失败计数与验证码联动。"},
    {"id": "waf-bot", "severity": "medium", "category": "访问控制",
     "title": "Bot 管理与爬虫治理",
     "requirement": "识别恶意爬虫/扫描器；搜索引擎白名单需验证；扫描器 UA 与高频目录探测有告警。",
     "evidence": "Bot 策略、UA/IP 信誉规则、扫描告警记录。",
     "remediation": "启用 JS 挑战或行为分析；对扫描行为限速并封禁。"},
    {"id": "waf-iprep", "severity": "medium", "category": "访问控制",
     "title": "IP 信誉与威胁情报",
     "requirement": "接入 IP/域名信誉库并定期更新；对 Tor/代理/云扫描源有策略；封禁名单可审计。",
     "evidence": "情报源订阅、封禁名单、误封申诉流程。",
     "remediation": "建立情报更新与误报复核机制；关键业务不依赖单一情报源。"},
    {"id": "waf-tls", "severity": "medium", "category": "传输",
     "title": "TLS 与协议合规",
     "requirement": "禁用 TLS 1.0/1.1、弱套件与压缩；HSTS 开启；证书有效期与链完整。",
     "evidence": "SSL Labs/内部扫描报告、HSTS 响应头、证书清单。",
     "remediation": "统一 TLS 1.2+ 与强套件；自动化证书续期与到期告警。"},
    {"id": "waf-hosts", "severity": "medium", "category": "传输",
     "title": "Host 头与虚拟主机防护",
     "requirement": "校验 Host/X-Forwarded-Host；默认虚拟主机拒绝未知域名；禁止 IP 直连绕过。",
     "evidence": "Nginx server_name 配置、WAF Host 规则、DNS 解析清单。",
     "remediation": "默认站点返回 444/403；回源校验 Host 与 SNI。"},
    {"id": "waf-log", "severity": "high", "category": "运营",
     "title": "日志留存与告警闭环",
     "requirement": "请求体（脱敏）、命中规则、源 IP、处置动作留存 >= 180 天；高危规则实时告警并关联 SIEM。",
     "evidence": "日志字段样例、留存周期配置、SIEM 告警工单。",
     "remediation": "补齐日志字段与时钟同步；建立高危告警 15 分钟响应 SLA。"},
    {"id": "waf-fp", "severity": "medium", "category": "运营",
     "title": "误报治理与例外管理",
     "requirement": "例外规则有 owner、到期时间、影响范围；每季度复核并清理过期例外。",
     "evidence": "例外清单、审批记录、复核报告。",
     "remediation": "例外最小化到 URL+参数；优先修业务而非长期关规则。"},
    {"id": "waf-vpatch", "severity": "medium", "category": "运营",
     "title": "虚拟补丁与应急响应",
     "requirement": "高危漏洞在官方补丁前有虚拟补丁流程；补丁上线后及时下线临时规则。",
     "evidence": "漏洞通告、虚拟补丁变更单、下线记录。",
     "remediation": "建立漏洞-规则映射表与演练机制。"},
    {"id": "waf-bypass", "severity": "medium", "category": "运营",
     "title": "绕过面自查",
     "requirement": "检查分块传输、编码、超长参数、multipart、HTTP/2 降级、WebSocket 等解析差异；确认 WAF 与后端理解一致。",
     "evidence": "解析一致性测试报告、WAF 厂商加固建议。",
     "remediation": "统一规范化与解析顺序；对歧义请求直接拒绝。"},
    {"id": "waf-ha", "severity": "medium", "category": "可用性",
     "title": "高可用与故障降级",
     "requirement": "WAF 集群跨可用区；故障时默认拒绝而非旁路；策略同步一致。",
     "evidence": "HA 拓扑、故障演练报告、策略同步状态。",
     "remediation": "定期切换演练；禁止故障自动 bypass。"},
    {"id": "waf-change", "severity": "low", "category": "运营",
     "title": "变更与回滚",
     "requirement": "策略变更走审批与灰度；有配置备份和一键回滚；变更后验证关键业务。",
     "evidence": "变更单、备份文件、回滚演练记录。",
     "remediation": "使用配置即代码管理策略；变更窗口内监控误报率。"},
]

NGFW_CHECKS = [
    {"id": "ngfw-default", "severity": "high", "category": "策略",
     "title": "默认拒绝与最小权限",
     "requirement": "入站/出站/跨区默认拒绝；仅放行必要源、目的、端口、应用；规则有 owner 与到期时间。",
     "evidence": "防火墙策略导出、规则命中计数、业务授权单。",
     "remediation": "清理 any-any 与宽泛网段；按业务收紧五元组。"},
    {"id": "ngfw-app", "severity": "high", "category": "策略",
     "title": "应用识别与控制",
     "requirement": "启用应用识别，禁止高风险应用（P2P、远程控制、匿名代理）；加密流量按策略分类。",
     "evidence": "应用控制策略、应用识别日志、阻断统计。",
     "remediation": "先监控后阻断；对业务必需应用建立白名单。"},
    {"id": "ngfw-ips", "severity": "high", "category": "检测",
     "title": "IPS 签名与更新",
     "requirement": "IPS 签名库近 7 天更新；高危签名阻断；性能余量 >= 30%。",
     "evidence": "签名版本、更新时间、设备 CPU/会话利用率。",
     "remediation": "自动化签名更新与失败告警；扩容或优化策略。"},
    {"id": "ngfw-ti", "severity": "medium", "category": "检测",
     "title": "威胁情报联动",
     "requirement": "接入恶意 IP/域名/URL 情报；支持自动封禁与人工复核；误报可快速解封。",
     "evidence": "情报源订阅、联动策略、封禁/解封记录。",
     "remediation": "设置情报置信度阈值；关键业务加白名单。"},
    {"id": "ngfw-egress", "severity": "high", "category": "策略",
     "title": "出站管控与 C2 阻断",
     "requirement": "服务器区出站按域名/端口白名单；阻断常见 C2 端口与匿名隧道；DNS 出站经内部解析器。",
     "evidence": "出站策略、DNS 架构图、C2 告警记录。",
     "remediation": "默认拒绝服务器出站；仅放行更新源与业务依赖。"},
    {"id": "ngfw-dns", "severity": "medium", "category": "检测",
     "title": "DNS 安全",
     "requirement": "启用 DNS 隧道检测、恶意域名拦截、DGA 检测；内部解析器只向外部可信解析转发。",
     "evidence": "DNS 安全策略、拦截日志、解析器配置。",
     "remediation": "部署 DNS sinkhole；对超长/高熵域名告警。"},
    {"id": "ngfw-seg", "severity": "high", "category": "架构",
     "title": "网络分区与横向移动",
     "requirement": "办公/生产/测试/管理网分区；数据库与管理面不对办公网开放；关键区之间默认拒绝。",
     "evidence": "网络分区图、ACL、东西向流量日志。",
     "remediation": "按业务域建立微隔离；管理面走堡垒机与双因素。"},
    {"id": "ngfw-ddos", "severity": "medium", "category": "可用性",
     "title": "DDoS 与连接数防护",
     "requirement": "SYN Flood、UDP Flood、连接数/新建速率限制已配置；清洗阈值与运营商联动。",
     "evidence": "抗 D 策略、清洗记录、压测报告。",
     "remediation": "设置基线阈值并演练；关键业务接入云清洗。"},
    {"id": "ngfw-ssl", "severity": "medium", "category": "检测",
     "title": "SSL 解密范围与合规",
     "requirement": "明确解密范围（入站/出站/豁免）；证书与私钥受控；遵守隐私与合规要求。",
     "evidence": "解密策略、证书管理记录、合规评估。",
     "remediation": "最小化解密范围；豁免名单定期复核。"},
    {"id": "ngfw-vpn", "severity": "high", "category": "访问",
     "title": "VPN 与远程访问",
     "requirement": "VPN 强制 MFA；账号与设备绑定；离职即时禁用；暴露面最小化。",
     "evidence": "VPN 配置、MFA 记录、账号生命周期流程。",
     "remediation": "启用 MFA 与设备合规检查；收敛公网暴露。"},
    {"id": "ngfw-mgmt", "severity": "high", "category": "管理",
     "title": "管理面安全",
     "requirement": "管理口不暴露公网；仅堡垒机/管理网访问；强口令 + MFA；配置备份加密。",
     "evidence": "管理 ACL、堡垒机日志、配置备份策略。",
     "remediation": "关闭公网管理；启用集中认证与命令审计。"},
    {"id": "ngfw-log", "severity": "high", "category": "运营",
     "title": "日志与 NetFlow",
     "requirement": "会话/威胁/策略日志外送 SIEM，留存 >= 180 天；NTP 同步；关键事件可回溯。",
     "evidence": "日志外送配置、留存策略、时间同步状态。",
     "remediation": "补齐日志字段与容量；建立告警分级。"},
    {"id": "ngfw-rule", "severity": "medium", "category": "运营",
     "title": "规则生命周期",
     "requirement": "规则有命名规范、注释、owner、到期时间；每季度清理未命中规则；变更可回滚。",
     "evidence": "规则清单、命中统计、变更记录。",
     "remediation": "建立规则台账与自动过期提醒；灰度发布。"},
    {"id": "ngfw-asset", "severity": "medium", "category": "运营",
     "title": "资产与策略对齐",
     "requirement": "防火墙策略覆盖全部已知资产；影子资产、临时开放端口有台账和回收机制。",
     "evidence": "CMDB、端口开放台账、回收记录。",
     "remediation": "定期资产扫描与策略比对；临时开放自动到期。"},
    {"id": "ngfw-backup", "severity": "medium", "category": "可用性",
     "title": "配置备份与灾难恢复",
     "requirement": "配置每日自动备份并异地保存；恢复演练每半年一次；HA 切换验证。",
     "evidence": "备份记录、恢复演练报告、HA 状态。",
     "remediation": "自动化备份校验；定期演练 RTO/RPO。"},
    {"id": "ngfw-zt", "severity": "low", "category": "架构",
     "title": "零信任与身份联动",
     "requirement": "关键业务访问结合身份/设备状态动态授权；不再仅依赖 IP 信任。",
     "evidence": "IAM/NAC 集成、动态授权策略。",
     "remediation": "从高价值系统开始试点零信任访问。"},
]

# 无害 canary：用例只验证是否被拦截/告警，不包含绕过与真实利用。
PROBES = [
    {"id": "sqli-bool", "category": "SQL 注入", "method": "GET",
     "path": "/search?q=1%27%20AND%20%271%27%3D%271%27%20--%20{{canary}}",
     "headers": {}, "body": "",
     "expected": "拦截或告警（403/406/自定义拦截页）",
     "risk": "若未拦截，可能暴露 SQL 注入面；本用例不读取数据。"},
    {"id": "sqli-union", "category": "SQL 注入", "method": "GET",
     "path": "/item?id=1%20UNION%20SELECT%20%27{{canary}}%27--%20",
     "headers": {}, "body": "",
     "expected": "拦截或告警",
     "risk": "若未拦截，可能暴露 UNION 注入面；本用例不读取真实数据。"},
    {"id": "xss-reflect", "category": "XSS", "method": "GET",
     "path": "/search?q=%3Cscript%3Ealert(%27{{canary}}%27)%3C%2Fscript%3E",
     "headers": {}, "body": "",
     "expected": "拦截或告警；响应中不得原样回显脚本",
     "risk": "若未拦截，可能造成反射型 XSS。"},
    {"id": "xss-attr", "category": "XSS", "method": "GET",
     "path": "/profile?name=%22%20onmouseover%3D%22alert(%27{{canary}}%27)",
     "headers": {}, "body": "",
     "expected": "拦截或告警",
     "risk": "若未拦截，可能造成属性注入 XSS。"},
    {"id": "traversal", "category": "路径穿越", "method": "GET",
     "path": "/download?file=..%2F..%2F..%2F..%2Fmohe-waf-{{canary}}.txt",
     "headers": {}, "body": "",
     "expected": "拦截或告警",
     "risk": "目标文件不存在；若未拦截，说明穿越特征未被识别。"},
    {"id": "cmdi-canary", "category": "命令注入", "method": "GET",
     "path": "/ping?host=127.0.0.1%3Becho%20{{canary}}",
     "headers": {}, "body": "",
     "expected": "拦截或告警",
     "risk": "若未拦截且后端存在命令拼接，只会输出 canary，不执行其他命令。"},
    {"id": "ssrf-loopback", "category": "SSRF", "method": "POST",
     "path": "/fetch", "headers": {"Content-Type": "application/x-www-form-urlencoded"},
     "body": "url=http%3A%2F%2F127.0.0.1%3A1%2Fmohe-{{canary}}",
     "expected": "拦截或告警",
     "risk": "目标端口 1 无服务；不访问云元数据与内网业务。"},
    {"id": "xxe-doctype", "category": "XXE", "method": "POST",
     "path": "/xml", "headers": {"Content-Type": "application/xml"},
     "body": "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///mohe-{{canary}}\">]><r>&x;</r>",
     "expected": "拦截或告警",
     "risk": "实体指向不存在的文件；不读取真实系统文件。"},
    {"id": "jndi-ua", "category": "JNDI / Log4Shell", "method": "GET",
     "path": "/", "headers": {"User-Agent": "${jndi:ldap://127.0.0.1:1/{{canary}}}"},
     "body": "",
     "expected": "拦截或告警",
     "risk": "LDAP 目标为回环关闭端口；不连接外部服务器。"},
    {"id": "upload-txt", "category": "文件上传", "method": "POST",
     "path": "/upload", "headers": {"Content-Type": "multipart/form-data; boundary=MoHeBoundary"},
     "body": "--MoHeBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"mohe-{{canary}}.txt\"\r\nContent-Type: text/plain\r\n\r\nMoHe harmless WAF probe {{canary}}\r\n--MoHeBoundary--\r\n",
     "expected": "拒绝可执行脚本，允许/隔离无害文本并记录",
     "risk": "上传内容为纯文本，不含可执行代码。"},
    {"id": "webshell-echo", "category": "Webshell 检测", "method": "POST",
     "path": "/upload", "headers": {"Content-Type": "multipart/form-data; boundary=MoHeBoundary"},
     "body": "--MoHeBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"mohe-{{canary}}.php.txt\"\r\nContent-Type: text/plain\r\n\r\n<?php echo '{{canary}}'; ?>\r\n--MoHeBoundary--\r\n",
     "expected": "拦截或隔离；上传目录禁止脚本执行",
     "risk": "仅为回显 canary 的检测样本，不执行系统命令。"},
    {"id": "api-role", "category": "API 越权", "method": "POST",
     "path": "/api/user", "headers": {"Content-Type": "application/json"},
     "body": "{\"role\":\"admin\",\"canary\":\"{{canary}}\"}",
     "expected": "拒绝批量赋值/越权字段，记录告警",
     "risk": "只提交无意义 canary 字段，不修改真实账户。"},
    {"id": "scanner-ua", "category": "扫描器识别", "method": "GET",
     "path": "/", "headers": {"User-Agent": "MoHe-WAF-Canary/1.0 ({{canary}})"},
     "body": "",
     "expected": "识别为测试/扫描 UA 并告警，不误封常规浏览器",
     "risk": "单次请求，不进行目录扫描。"},
    {"id": "host-header", "category": "Host 头", "method": "GET",
     "path": "/", "headers": {"Host": "mohe-{{canary}}.invalid", "X-Forwarded-Host": "mohe-{{canary}}.invalid"},
     "body": "",
     "expected": "拒绝未知 Host 或返回默认站点拦截",
     "risk": ".invalid 为保留域名，不解析到真实目标。"},
]

NGFW_PROBES = [
    {"id": "mgmt-exposure", "category": "管理面", "target": "授权 staging 防火墙管理地址",
     "check": "从非管理网发起管理端口连接，预期被拒绝；管理口仅堡垒机可达。",
     "expected": "拒绝并记录", "risk": "仅在自有测试环境执行。"},
    {"id": "cleartext-port", "category": "明文服务", "target": "授权 staging 主机",
     "check": "对 23/telnet、21/ftp 的测试连接，预期被策略拒绝。",
     "expected": "拒绝并记录", "risk": "目标端口应为关闭或测试监听；不进行认证尝试。"},
    {"id": "egress-deny", "category": "出站", "target": "授权 staging 服务器",
     "check": "从服务器区访问文档保留地址 203.0.113.10:443 与 mohe-<canary>.invalid，预期被出站策略拒绝或告警。",
     "expected": "拒绝/告警", "risk": "使用 RFC 5737 文档地址与 .invalid 域名，不访问真实外部系统。"},
    {"id": "dns-canary", "category": "DNS", "target": "内部 DNS 解析器",
     "check": "查询 mohe-<canary>.invalid，预期 NXDOMAIN 且 DNS 安全日志可见。",
     "expected": "NXDOMAIN + 日志", "risk": "仅查询保留域名，不做隧道传输。"},
    {"id": "ips-test", "category": "IPS", "target": "授权 staging 测试网段",
     "check": "使用厂商/开源测试工具的内置无害签名样例（如 testmyids 文本），确认告警链路。",
     "expected": "IPS 告警进入 SIEM", "risk": "只使用公开无害测试串，不发送真实攻击载荷。"},
]

BEFORE_AFTER_TEMPLATE = """# 加固前后对比报告（模板）

> 本模板由魔盒-ctf v3.7.0 生成，仅提供结构与占位符；请填入真实证据后归档。

## 1. 基本信息
- 系统 / 业务：
- 环境（生产 / 预发 / 演练）：
- 加固窗口：
- 操作人 / 复核人：
- 变更单号：
- 回滚脚本位置：

## 2. 范围与目标
- 加固对象（主机 / 中间件 / 数据库 / WAF / NGFW）：
- 不在范围内：
- 目标（可量化）：
  - 高危基线项清零：
  - 暴露面收敛：
  - 告警闭环时间：

## 3. 加固前证据
| 检查项 | 状态 | 证据（命令输出/截图/文件） | 风险说明 |
| --- | --- | --- | --- |
|  |  |  |  |

- 基线报告：`before/result.json`、`before/report.md`
- 采集命令与时间：
- 已知误报/例外：

## 4. 变更清单
| 序号 | 变更内容 | 影响范围 | 风险 | 回滚方式 | 验证人 |
| --- | --- | --- | --- | --- | --- |
| 1 |  |  |  |  |  |

## 5. 加固后证据
| 检查项 | 状态 | 证据 | 与加固前对比 |
| --- | --- | --- | --- |
|  |  |  | 改善 / 持平 / 退化 |

- 基线报告：`after/result.json`、`after/report.md`
- 业务验证（登录、核心接口、批处理、监控）：
- 性能对比（CPU/内存/延迟/错误率）：

## 6. 攻防验证
- WAF/NGFW 检测用例执行记录（仅授权 staging）：
- 命中/拦截率：
- 误报与白名单调整：
- 未覆盖风险：

## 7. 回滚验证
- 回滚触发条件：
- 回滚耗时：
- 回滚后业务确认：
- 回滚脚本是否实际演练：是 / 否

## 8. 结论与遗留风险
- 结论：
- 遗留风险与负责人/期限：
- 后续计划：

## 9. 签署
- 操作人：            日期：
- 复核人：            日期：
- 业务确认：          日期：
"""


def _write_checklist(outdir, result, checks):
    path = os.path.join(outdir, "artifacts", "waf_ngfw_checklist.csv")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(["id", "scope", "category", "severity", "title",
                         "requirement", "evidence", "remediation"])
        for scope, items in checks:
            for item in items:
                writer.writerow([item["id"], scope, item["category"],
                                 item["severity"], item["title"],
                                 item["requirement"], item["evidence"],
                                 item["remediation"]])
    util.add_artifact(result, path)
    return path


def _write_probes(outdir, result, canary):
    probes = []
    for item in PROBES:
        probe = dict(item)
        probe["canary"] = canary
        probe["path"] = probe["path"].replace("{{canary}}", canary)
        probe["body"] = probe["body"].replace("{{canary}}", canary)
        probe["headers"] = {k: v.replace("{{canary}}", canary)
                            for k, v in probe.get("headers", {}).items()}
        probes.append(probe)
    data = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "canary": canary,
        "warning": "仅限 CTF 靶场/自有授权 staging 人工执行；本工具不会发送任何请求。",
        "http_probes": probes,
        "ngfw_probes": [dict(x, canary=canary) for x in NGFW_PROBES],
    }
    path = util.save_json(outdir, "defense_test_cases.json", data)
    util.add_artifact(result, path)

    http_path = os.path.join(outdir, "artifacts", "defense_probes.http")
    os.makedirs(os.path.dirname(http_path), exist_ok=True)
    lines = [
        "# 魔盒-ctf WAF 检测用例（仅生成，未发送）",
        "# 只允许在自有 staging / CTF 靶场人工执行；不要指向生产或未授权目标。",
        "# 将 baseUrl 改为你的授权测试地址，并在代理/SIEM 中确认拦截日志。",
        "@baseUrl = https://YOUR-AUTHORIZED-STAGING-HOST",
        "@canary = %s" % canary,
        "",
    ]
    for probe in probes:
        lines.append("### %s | %s | 预期：%s" % (
            probe["id"], probe["category"], probe["expected"]))
        lines.append("# 风险提示：%s" % probe["risk"])
        lines.append("%s {{baseUrl}}%s" % (probe["method"], probe["path"]))
        for key, value in probe.get("headers", {}).items():
            lines.append("%s: %s" % (key, value))
        if probe.get("body"):
            lines.append("")
            lines.append(probe["body"].rstrip("\r\n"))
        lines.append("")
        lines.append("")
    with open(http_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))
    util.add_artifact(result, http_path)
    return probes, path, http_path


def _write_docs(outdir, result, canary, profile, vendor):
    template_path = os.path.join(outdir, "artifacts", "hardening_before_after_template.md")
    os.makedirs(os.path.dirname(template_path), exist_ok=True)
    with open(template_path, "w", encoding="utf-8") as fp:
        fp.write(BEFORE_AFTER_TEMPLATE)
    util.add_artifact(result, template_path)

    readme = """# 攻防验证使用说明

- 生成时间：%s
- 厂商/环境：%s
- Canary：`%s`
- 范围：%s

## 安全边界

1. 本工具**只生成**清单、用例与模板，不会向任何地址发送请求，也不会连接防火墙/WAF。
2. 所有 HTTP 用例必须由使用者在**自有 staging 或 CTF 靶场**人工执行；
   不得指向生产、第三方或未授权资产。
3. 用例仅用于验证检测/拦截是否生效，使用无害 canary、不存在文件与回环关闭端口，
   不包含绕过、免杀、持久化或真实利用链。
4. NGFW 用例需在隔离测试网段执行，并使用 RFC 5737 文档地址与 `.invalid` 域名。
5. 执行前确认限速与审批；执行后保留 WAF/NGFW/SIEM 日志作为证据。

## 建议执行顺序

1. 先做策略配置自查（checklist），补齐明显缺口。
2. 在 staging 逐条执行 `defense_probes.http`，记录响应码、拦截页、规则 ID、日志时间。
3. 执行 NGFW 测试项，确认 deny/alert 与 SIEM 告警。
4. 用 `--comp baseline` 采集加固前后基线，再用 `--comp compare` 生成对比报告。
5. 将证据填入 `hardening_before_after_template.md` 并归档。

## 结果判定

- 预期拦截却放行：高危，需补规则并复测。
- 预期放行却被拦截：检查误报与白名单，避免影响业务。
- 有告警但无日志/工单：运营闭环不合格。
""" % (time.strftime("%Y-%m-%d %H:%M:%S"), vendor or "未指定", canary, profile)
    readme_path = util.save_text(outdir, "README_defense.txt", readme)
    util.add_artifact(result, readme_path)
    return template_path, readme_path


def _render(result):
    data = result["data"]
    lines = ["# 攻防验证与加固报告", ""]
    lines.append("- 范围：%s" % data.get("profile", ""))
    lines.append("- 厂商/环境：%s" % (data.get("vendor") or "未指定"))
    lines.append("- 目标（仅记录，不发送请求）：`%s`" % (data.get("target") or "-"))
    lines.append("- 清单：WAF %s 项 / NGFW %s 项；HTTP 用例 %s 条；NGFW 用例 %s 条" % (
        data.get("waf_checks", 0), data.get("ngfw_checks", 0),
        data.get("http_cases", 0), data.get("ngfw_cases", 0)))
    lines.append("- Canary：`%s`" % data.get("canary", ""))
    lines.append("")
    lines.append("## 高风险检查项")
    for item in data.get("high_items") or []:
        lines.append("- [%s] %s：%s" % (item["scope"], item["title"], item["requirement"]))
    lines.append("")
    lines.append("## 产物")
    for path in result["artifacts"]:
        lines.append("- `%s`" % path)
    lines.append("")
    lines.append("## 备注")
    for note in result["notes"]:
        lines.append("- %s" % note)
    return "\n".join(lines)


def analyze(target: str = "", outdir: str = "", profile: str = "both",
            vendor: str = "", log=None) -> dict:
    """生成 WAF/NGFW 检查清单、检测用例与加固前后模板；不发送任何请求。"""
    log = log or (lambda m: None)
    outdir = outdir or util.case_dir("defense", vendor or "waf")
    result = util.make_result("defense", outdir)
    profile = (profile or "both").lower()
    if profile not in ("waf", "ngfw", "both"):
        profile = "both"
    result["data"].update({"target": target, "profile": profile, "vendor": vendor})
    canary = "MOHECTF-%s" % time.strftime("%Y%m%d%H%M%S")
    result["data"]["canary"] = canary
    checks = []
    if profile in ("waf", "both"):
        checks.append(("WAF", WAF_CHECKS))
    if profile in ("ngfw", "both"):
        checks.append(("NGFW", NGFW_CHECKS))
    checklist_path = _write_checklist(outdir, result, checks)
    probes, probes_json, probes_http = _write_probes(outdir, result, canary)
    template_path, readme_path = _write_docs(outdir, result, canary, profile, vendor)

    high = []
    for scope, items in checks:
        for item in items:
            if item["severity"] == "high":
                high.append({"scope": scope, "title": item["title"],
                             "requirement": item["requirement"], "id": item["id"]})
    result["data"].update({
        "waf_checks": len(WAF_CHECKS) if profile in ("waf", "both") else 0,
        "ngfw_checks": len(NGFW_CHECKS) if profile in ("ngfw", "both") else 0,
        "http_cases": len(probes) if profile in ("waf", "both") else 0,
        "ngfw_cases": len(NGFW_PROBES) if profile in ("ngfw", "both") else 0,
        "high_items": high,
        "checklist": checklist_path,
        "test_cases": probes_json,
        "http_template": probes_http,
        "report_template": template_path,
        "readme": readme_path,
    })
    if high:
        util.add(result, "info", "高风险检查项 %d 项" % len(high),
                 "\n".join("[%s] %s" % (x["scope"], x["title"]) for x in high[:30]))
    util.add(result, "ok", "检测用例已生成（未发送）",
             "HTTP 用例 %d 条，NGFW 用例 %d 条；仅在自有 staging 人工执行。"
             % (result["data"]["http_cases"], result["data"]["ngfw_cases"]))
    result["notes"].append("本模块不联网、不认证、不向目标发送任何数据包；所有用例需人工执行。")
    result["notes"].append("用例目标是验证拦截/告警与日志闭环，不含绕过、免杀、持久化或真实利用。")
    result["summary"] = ("%s 清单：WAF %s 项 / NGFW %s 项，HTTP 用例 %s，NGFW 用例 %s（仅生成）"
                         % (profile, result["data"]["waf_checks"],
                            result["data"]["ngfw_checks"],
                            result["data"]["http_cases"], result["data"]["ngfw_cases"]))
    log("[defense] 清单与用例已生成，未发送任何请求")
    return util.finish(result, _render(result))


def _load_baseline(path):
    with open(path, "r", encoding="utf-8-sig") as fp:
        return json.load(fp)


def compare(before_json: str, after_json: str, outdir: str = "",
            log=None) -> dict:
    """对比两次基线 result.json，生成加固前后报告。"""
    log = log or (lambda m: None)
    outdir = outdir or util.case_dir("hardening_compare", "before_after")
    result = util.make_result("hardening_compare", outdir)
    before = after = None
    try:
        before = _load_baseline(before_json)
        after = _load_baseline(after_json)
    except Exception as exc:
        result["ok"] = False
        util.add(result, "warn", "读取基线结果失败", str(exc))
        return util.finish(result, _render_compare(result))
    b_checks = {c.get("id", ""): c for c in (before.get("data") or {}).get("checks", [])}
    a_checks = {c.get("id", ""): c for c in (after.get("data") or {}).get("checks", [])}
    rows = []
    improved = regressed = unchanged = missing = 0
    for cid, b in b_checks.items():
        a = a_checks.get(cid)
        if not a:
            rows.append({"id": cid, "title": b.get("title", ""),
                         "before": b.get("status", ""), "after": "缺失",
                         "change": "缺失", "detail": b.get("detail", "")})
            missing += 1
            continue
        bs, as_ = b.get("status", ""), a.get("status", "")
        if bs == as_:
            change = "持平"
            unchanged += 1
        elif bs in ("fail", "warn") and as_ == "pass":
            change = "改善"
            improved += 1
        elif bs == "pass" and as_ in ("fail", "warn"):
            change = "退化"
            regressed += 1
            util.add(result, "warn", "加固后退化：%s" % (a.get("title") or cid),
                     "加固前=%s，加固后=%s" % (bs, as_))
        elif as_ == "pass":
            change = "改善"
            improved += 1
        else:
            change = "变化"
        rows.append({"id": cid, "title": a.get("title") or b.get("title", ""),
                     "before": bs, "after": as_, "change": change,
                     "detail": a.get("detail", "")})
    for cid, a in a_checks.items():
        if cid not in b_checks:
            rows.append({"id": cid, "title": a.get("title", ""),
                         "before": "缺失", "after": a.get("status", ""),
                         "change": "新增", "detail": a.get("detail", "")})

    def counts(data):
        checks = (data.get("data") or {}).get("checks", [])
        out = {}
        for c in checks:
            out[c.get("status", "")] = out.get(c.get("status", ""), 0) + 1
        return out, len(checks)

    b_counts, b_total = counts(before)
    a_counts, a_total = counts(after)
    result["data"].update({
        "before": {"path": os.path.abspath(before_json), "counts": b_counts,
                   "total": b_total, "summary": before.get("summary", "")},
        "after": {"path": os.path.abspath(after_json), "counts": a_counts,
                  "total": a_total, "summary": after.get("summary", "")},
        "rows": rows,
        "improved": improved, "regressed": regressed,
        "unchanged": unchanged, "missing": missing,
    })
    if improved:
        util.add(result, "ok", "改善项 %d 个" % improved,
                 "\n".join("%s：%s → %s" % (r["title"], r["before"], r["after"])
                           for r in rows if r["change"] == "改善")[:4000])
    if regressed:
        util.add(result, "warn", "退化项 %d 个（需复核）" % regressed, "")
    if missing:
        util.add(result, "warn", "加固后缺失项 %d 个" % missing,
                 "\n".join(r["title"] for r in rows if r["change"] == "缺失")[:2000])
    report = _render_compare(result)
    path = util.save_text(outdir, "hardening_compare.md", report)
    util.add_artifact(result, path)
    result["data"]["report"] = path
    result["summary"] = "加固前后对比：改善 %s，退化 %s，持平 %s，缺失 %s" % (
        improved, regressed, unchanged, missing)
    result["notes"].append("对比基于两次 baseline result.json；检查项按 id 对齐。")
    result["notes"].append("状态变化不等同于安全结论，需结合业务验证与残余风险复核。")
    return util.finish(result, report)


def _render_compare(result):
    data = result["data"]
    lines = ["# 加固前后对比报告", ""]
    if data.get("before"):
        lines.append("- 加固前：`%s`" % data["before"]["path"])
        lines.append("- 加固后：`%s`" % data["after"]["path"])
        lines.append("- 加固前统计：%s" % data["before"]["counts"])
        lines.append("- 加固后统计：%s" % data["after"]["counts"])
    lines.append("- 改善 %s / 退化 %s / 持平 %s / 缺失 %s" % (
        data.get("improved", 0), data.get("regressed", 0),
        data.get("unchanged", 0), data.get("missing", 0)))
    lines.append("")
    if data.get("rows"):
        lines.append("## 检查项变化")
        lines.append("| 检查项 | 加固前 | 加固后 | 变化 |")
        lines.append("| --- | --- | --- | --- |")
        for row in data["rows"]:
            lines.append("| %s | %s | %s | %s |" % (
                str(row.get("title", "")).replace("|", "/"),
                row.get("before", ""), row.get("after", ""), row.get("change", "")))
    lines.append("")
    lines.append("## 发现")
    for item in result.get("findings") or []:
        lines.append("- [%s] %s" % (item["level"], item["title"]))
        if item.get("detail"):
            for text in item["detail"].splitlines()[:10]:
                lines.append("  - %s" % text)
    lines.append("")
    lines.append("## 备注")
    for note in result.get("notes") or []:
        lines.append("- %s" % note)
    return "\n".join(lines)
