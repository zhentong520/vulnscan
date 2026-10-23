#!/usr/bin/env python3
"""聚合 findings.json → Markdown 报告。

用法:
    python render_report.py --findings findings.json --out vuln-report.md [--project <名称>]

报告结构：执行摘要 → 可立即修复（有 fixed_version）→ 密钥（立即轮换）→
其余按 severity → 疑似误报 → 未覆盖项/局限。
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path


def render_finding(f: dict) -> str:
    lines = [f"### [{f['severity']}] {f.get('title', 'unknown')}"]
    det = ", ".join(f.get("detected_by", []))
    loc = f"{f.get('file','')}:{f.get('line') or ''}".rstrip(":")
    lines.append(f"- **检出**: {det}")
    if loc and loc != ":":
        lines.append(f"- **位置**: `{loc}`")
    if f.get("package"):
        lines.append(f"- **依赖**: {f['package']}@{f.get('version','')}" +
                     (f" → 建议升级 **{f['fixed_version']}**" if f.get("fixed_version") else ""))
    if f.get("cwe"):
        lines.append(f"- **CWE**: {f['cwe']}")
    if f.get("evidence"):
        lines.append(f"- **说明**: {f['evidence'][:400]}")
    if f.get("remediation"):
        lines.append(f"- **修复**: {f['remediation']}")
    if f.get("likely_fp"):
        lines.append("- ⚠️ 位于测试/示例/文档路径，**疑似误报或低影响**，请人工复核")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--project", default="目标项目")
    ap.add_argument("--engines", default="", help="实际运行的引擎与版本描述")
    ap.add_argument("--not-covered", default="", help="未覆盖项说明（逗号分隔）")
    args = ap.parse_args()

    data = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    findings = data.get("findings", [])
    stats = data.get("stats", {})
    sev = stats.get("by_severity", {})
    sev_line = " | ".join(f"{k} {v}" for k, v in sorted(
        sev.items(), key=lambda kv: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[kv[0]])) or "无发现"

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    L = [f"# 漏洞扫描报告：{args.project}", "",
         f"- 扫描时间：{now}",
         f"- 引擎：{args.engines or ', '.join(stats.get('by_engine', {}).keys())}",
         "- 授权状态：自有资产" + ("（Web DAST 已过授权确认闸门）"
                                  if any(e in (args.engines or "").lower() for e in ("nuclei", "zap")) else ""), "",
         "## 执行摘要", "",
         f"**{sev_line}**（去重后共 {stats.get('total', 0)} 条）", ""]

    fixable = [f for f in findings if f.get("fixed_version") and not f.get("likely_fp")
               and f["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]
    secrets = [f for f in findings if f.get("type") == "secret" and not f.get("likely_fp")]
    web = [f for f in findings if f.get("type") == "web" and not f.get("likely_fp")
           and f not in secrets]
    normal = [f for f in findings if f not in fixable and f not in secrets
              and f not in web and not f.get("likely_fp")]
    fps = [f for f in findings if f.get("likely_fp")]

    if fixable:
        L += ["## 🟢 可立即修复（升级依赖即可解决，按成本收益排序）", ""]
        for f in fixable:
            L.append(render_finding(f))
    if secrets:
        L += ["## 🔴 密钥泄露（立即轮换——密钥进过仓库即假定已泄露）", ""]
        for f in secrets:
            L.append(render_finding(f))
    if web:
        L += ["## 🌐 Web 站点发现（nuclei 主动探测，仅限已授权目标）", ""]
        for f in web:
            L.append(render_finding(f))
    if normal:
        L += ["## 其他发现（按 severity 排序）", ""]
        for f in normal:
            L.append(render_finding(f))
    if fps:
        L += ["## 疑似误报 / 低影响（命中于测试、示例、文档路径）", ""]
        for f in fps:
            L.append(render_finding(f))
    if not findings:
        L += ["**本次扫描未发现命中。** 注意：这不等于'无漏洞'——见下方未覆盖项。", ""]

    L += ["## 未覆盖项", ""]
    if args.not_covered:
        for item in args.not_covered.split(","):
            if item.strip():
                L.append(f"- {item.strip()}")
    else:
        L.append("- （执行编排时请如实列出：哪些引擎因缺失/失败未运行，对应哪些漏洞类别未检查）")
    L += ["", "## 局限", "",
          "- 开源 SAST 无跨文件污点分析；SCA 只报'依赖存在 CVE'不做可达性分析；",
          "  业务逻辑漏洞（越权/竞态/IDOR）不在模式匹配覆盖范围。",
          "- CVSS 分级 ≠ 实际风险，请结合业务上下文判断修复顺序。", ""]

    Path(args.out).write_text("\n".join(L), encoding="utf-8")
    print(f"报告已生成: {args.out}（{stats.get('total', 0)} 条 findings）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
