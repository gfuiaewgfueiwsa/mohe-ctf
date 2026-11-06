# -*- coding: utf-8 -*-
"""RAC 附属自动化 —— Oracle RAC 集群巡检自动化。

内置只读巡检命令集（不修改任何系统/数据库状态），通过 remoteexec 的 SSH
通道到 RAC 节点执行并汇总成巡检报告。占位符 {DB_NAME} 会被实际库名替换。

巡检项：
  cluster   集群整体状态（crsctl check crs / olsnodes / 资源树）
  database  数据库与实例状态（srvctl status/config database）
  listener  监听器状态（srvctl status listener / lsnrctl status）
  asm       ASM 存储（srvctl status asm / lsdg 提示）
  interconnect 私有网络（oifcfg iflist）
  system    节点系统负载（uptime / df / free / top）
  alertlog  告警日志尾部错误扫描（grep ORA-）
  backup    备份信息提示（RMAN 无非交互模板，仅列出目录线索）

适用：DBA 例行巡检、CTF 环境中出现的 Oracle RAC 靶机信息收集。
"""
from typing import Callable, Dict, List

from .remoteexec import HostSpec, exec_one, batch_report

# 巡检命令集（全部只读）。{DB_NAME} 为占位符。
INSPECTIONS: Dict[str, dict] = {
    "cluster": {
        "title": "集群整体状态（Grid Infrastructure）",
        "cmds": [
            "crsctl check crs",
            "crsctl check cluster -all",
            "olsnodes -n -i -s",
            "crsctl status res -t | head -80",
        ],
    },
    "database": {
        "title": "数据库与实例状态",
        "cmds": [
            "srvctl config database",
            "srvctl status database -d {DB_NAME}",
            "srvctl config database -d {DB_NAME} | head -30",
            "ps -ef | grep -E 'ora_(pmon|smon|lgwr|ckpt)' | grep -v grep | head -20",
        ],
    },
    "listener": {
        "title": "监听器状态",
        "cmds": [
            "srvctl status listener",
            "srvctl config listener",
            "lsnrctl status 2>/dev/null | head -40",
        ],
    },
    "asm": {
        "title": "ASM 存储",
        "cmds": [
            "srvctl status asm -a",
            "crsctl status res ora.asm 2>/dev/null | head -20",
            "asmcmd lsdg 2>/dev/null || echo '(asmcmd 不可用，手动检查磁盘组)'",
        ],
    },
    "interconnect": {
        "title": "节点间私有网络",
        "cmds": [
            "oifcfg iflist -p -n 2>/dev/null",
            "ip -br addr 2>/dev/null || ifconfig -a | head -30",
        ],
    },
    "system": {
        "title": "节点系统负载与磁盘",
        "cmds": [
            "uptime",
            "free -m 2>/dev/null || vmstat 1 2",
            "df -h",
            "top -bn1 | head -15",
            "ps -ef --sort=-%mem 2>/dev/null | head -12",
        ],
    },
    "alertlog": {
        "title": "告警日志错误扫描（近 200 行 ORA-/ERROR/FAIL）",
        "cmds": [
            "tail -n 2000 $ORACLE_BASE/diag/rdbms/*/*/trace/alert_*.log 2>/dev/null "
            "| grep -iE 'ORA-|error|fail|critical' | tail -40 || echo '(未找到告警日志或无错误)'",
            "tail -n 100 $GRID_HOME/log/*/alerthistory.log 2>/dev/null | tail -20 "
            "|| true",
        ],
    },
    "backup": {
        "title": "备份与归档线索",
        "cmds": [
            "ls -lht $ORACLE_BASE/fast_recovery_area 2>/dev/null | head -15 "
            "|| echo '(未找到 FRA 目录)'",
            "ls -lht $ORACLE_BASE/admin/*/dpdump 2>/dev/null | head -10 || true",
            "crontab -l 2>/dev/null | grep -iE 'rman|backup|exp' || echo '(crontab 无备份任务或不可读)'",
        ],
    },
}


def run_inspection(spec: HostSpec, items: List[str], db_name: str = "",
                   timeout: float = 45.0, log: Callable = print) -> str:
    """对单节点执行所选巡检项，返回文本报告。"""
    db = db_name or "ORCL"
    lines = [f"Oracle RAC 巡检报告  节点: {spec.user}@{spec.host}:{spec.port}",
             f"巡检项: {', '.join(items)}", "=" * 60]
    for name in items:
        ins = INSPECTIONS.get(name)
        if not ins:
            continue
        lines.append(f"\n### {ins['title']} [{name}]")
        for tpl in ins["cmds"]:
            cmd = tpl.replace("{DB_NAME}", db)
            lines.append(f"$ {cmd}")
            r = exec_one(spec, cmd, timeout=timeout)
            if not r.connected:
                lines.append(f"  [连接失败] {r.error}")
                break
            out = r.output if r.output else "(无输出)"
            for ln in out.splitlines()[:50]:
                lines.append("  " + ln)
            lines.append("")
    lines.append("\n" + "=" * 60)
    lines.append("提示：本巡检全部为只读命令；未覆盖项（性能采样/备份验证）请按 DBA 流程手动执行。")
    return "\n".join(lines)


def run_inspection_multi(hosts: List[HostSpec], items: List[str],
                         db_name: str = "", timeout: float = 45.0,
                         concurrency: int = 2, log: Callable = print) -> str:
    """多节点巡检（并发 2，避免 sshd 与节点负载压力）。"""
    import concurrent.futures as cf
    reports: List[str] = [""] * len(hosts)

    def work(i, h):
        log(f"[{i + 1}/{len(hosts)}] 巡检 {h.user}@{h.host} ...")
        reports[i] = run_inspection(h, items, db_name, timeout,
                                    log=lambda m: log("    " + str(m)))

    with cf.ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        futs = [ex.submit(work, i, h) for i, h in enumerate(hosts)]
        for f in futs:
            f.result()
    return ("\n\n" + "#" * 70 + "\n\n").join(r for r in reports if r)
