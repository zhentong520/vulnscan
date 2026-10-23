#!/usr/bin/env python3
"""聚合多扫描器 JSON 输出：severity 归一化、跨工具去重、误报降权、排序。

用法:
    python aggregate_findings.py --inputs semgrep.json trivy.json gitleaks.json osv-scanner.json pip-audit.json checkov.json --out findings.json

输入不存在的文件会被跳过（引擎失败不阻塞聚合）。
输出 findings.json:
{
  "findings": [ {id, title, severity, engine(s), type, file, line, package, version,
                 fixed_version, evidence(脱敏), remediation, likely_fp, cve} ],
  "stats": {"total": n, "by_severity": {...}, "by_engine": {...}}
}
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
LOW_DIRS = re.compile(
    r"(^|[\\/])(test|tests|fixtures|examples|samples|docs|mocks?|"
    r"dist(-[\w.-]+)?|build|target|coverage|node_modules|vendor|"
    r"\.next|\.nuxt|\.output)([\\/]|$)", re.I)

SECRET_RE = re.compile(
    r"(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}|AKLT[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{30,}|"
    r"xox[bpars]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.|"
    r"(?:[Pp]assword|[Pp]asswd|[Ss]ecret|[Tt]oken|[Aa][Pp][Ii][_-]?[Kk]ey)\s*[=:]\s*['\"][^'\"]{6,}['\"])"
)


def redact(text: str) -> str:
    """密钥证据脱敏：头 6 + *** + 尾 4。"""
    if not text:
        return text
    def _r(m):
        s = m.group(0)
        return s[:6] + "***" + s[-4:] if len(s) > 14 else "***"
    return SECRET_RE.sub(_r, text)


def norm_sev(raw: str, engine: str, extra: str = "") -> str:
    s = (raw or "").strip().upper()
    m = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "ERROR": "HIGH",
         "MEDIUM": "MEDIUM", "MODERATE": "MEDIUM", "WARNING": "MEDIUM",
         "LOW": "LOW", "INFO": "INFO", "UNKNOWN": "LOW"}
    if extra:
        sev = m.get(extra.strip().upper())
        if sev:
            return sev
    return m.get(s, "LOW")


def fp_hit(f: dict) -> bool:
    path = f.get("file") or ""
    return bool(LOW_DIRS.search(path))


def fid(*parts) -> str:
    h = hashlib.sha1("|".join(str(p) for p in parts).encode("utf-8", "ignore")).hexdigest()[:12]
    return h


# ---------- 各引擎解析器：统一为 (type, id-ish, title, sev, file, line, pkg, ver, fixed, evidence, remediation, cwe) ----------

def parse_semgrep(data):
    for r in data.get("results", []):
        ex = r.get("extra", {})
        meta = ex.get("metadata", {})
        cwe = ""
        cwes = meta.get("cwe") or []
        if isinstance(cwes, list) and cwes:
            cwe = str(cwes[0]).split(":")[0]
        sev = norm_sev(ex.get("severity", ""), "semgrep")
        loc = r.get("start", {})
        yield {
            "type": "sast", "engine": "semgrep",
            "title": r.get("check_id", "semgrep-hit"),
            "rule": r.get("check_id", ""),
            "severity": sev,
            "file": r.get("path", ""), "line": loc.get("line", 0),
            "evidence": redact((ex.get("message") or "")[:500]),
            "remediation": ex.get("fix") or meta.get("references") and meta["references"][0] or "",
            "cwe": cwe,
        }


def parse_gitleaks(data):
    if isinstance(data, dict):
        data = data.get("findings", [])
    for r in data or []:
        yield {
            "type": "secret", "engine": "gitleaks",
            "title": f"硬编码密钥: {r.get('RuleID', 'unknown')}",
            "rule": r.get("RuleID", ""),
            "severity": "HIGH",  # 密钥一律 HIGH，处置手册要求立即轮换
            "file": r.get("File", ""), "line": r.get("StartLine", 0),
            "evidence": redact((r.get("Secret") or r.get("Match") or "")[:120]),
            "remediation": "移除密钥并立即轮换；若已进过 git 历史假定已泄露",
        }


def parse_trivy(data):
    for res in data.get("Results", []):
        tgt = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            yield {
                "type": "sca", "engine": "trivy",
                "title": f"{v.get('VulnerabilityID','')} — {v.get('PkgName','')}@{v.get('InstalledVersion','')}",
                "cve": v.get("VulnerabilityID", ""),
                "severity": norm_sev(v.get("Severity", ""), "trivy"),
                "file": tgt, "line": 0,
                "package": v.get("PkgName", ""), "version": v.get("InstalledVersion", ""),
                "fixed_version": (v.get("FixedVersion") or "").split(",")[0] or None,
                "evidence": redact((v.get("Title") or v.get("Description") or "")[:300]),
                "remediation": f"升级 {v.get('PkgName','')} 至 {v.get('FixedVersion') or '已修复版本'}" if v.get("FixedVersion")
                               else "暂无官方修复版本，评估缓解措施",
            }
        for mc in res.get("Misconfigurations") or []:
            yield {
                "type": "iac", "engine": "trivy",
                "title": f"{mc.get('ID','')}: {mc.get('Title','')}",
                "rule": mc.get("ID", ""),
                "severity": norm_sev(mc.get("Severity", ""), "trivy"),
                "file": tgt, "line": mc.get("CauseMetadata", {}).get("StartLine", 0),
                "evidence": (mc.get("Description") or "")[:300],
                "remediation": (mc.get("Resolution") or "")[:300],
            }
        for s in res.get("Secrets") or []:
            yield {
                "type": "secret", "engine": "trivy",
                "title": f"密钥(Trivy): {s.get('RuleID','')}",
                "rule": s.get("RuleID", ""),
                "severity": norm_sev(s.get("Severity", ""), "trivy", "HIGH"),
                "file": tgt, "line": s.get("StartLine", 0),
                "evidence": redact((s.get("Match") or "")[:120]),
                "remediation": "移除并轮换密钥（Gitleaks 若同报以 Gitleaks 结果为准）",
            }


def parse_osv(data):
    for res in data.get("results", []):
        for pkg in res.get("packages", []):
            p = pkg.get("package", {})
            for v in pkg.get("vulnerabilities", []):
                fixed = None
                for aff in v.get("affected", []):
                    for rng in aff.get("ranges", []):
                        for ev in rng.get("events", []):
                            if ev.get("fixed"):
                                fixed = ev["fixed"]
                sev = "MEDIUM"
                # 优先用 OSV database_specific.severity（GHSA 已复核），CVSS 向量仅兜底
                ds_sev = (v.get("database_specific") or {}).get("severity", "")
                sev_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM",
                           "MEDIUM": "MEDIUM", "LOW": "LOW"}
                if ds_sev in sev_map:
                    sev = sev_map[ds_sev]
                else:
                    for s in v.get("severity", []):
                        sc = s.get("score", "") or ""
                        if s.get("type") == "CVSS_V3" and sc[:1].isdigit():
                            f = float(sc.split(".")[0])
                            sev = "CRITICAL" if f >= 9 else "HIGH" if f >= 7 else "MEDIUM" if f >= 4 else "LOW"
                cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), v.get("id", ""))
                yield {
                    "type": "sca", "engine": "osv-scanner",
                    "title": f"{cve} — {p.get('name','')}@{p.get('version','')}",
                    "cve": cve,
                    "severity": sev,
                    "file": res.get("source", {}).get("path", ""), "line": 0,
                    "package": p.get("name", ""), "version": p.get("version", ""),
                    "fixed_version": fixed,
                    "evidence": redact((v.get("summary") or v.get("details") or "")[:300]),
                    "remediation": f"升级 {p.get('name','')} 至 {fixed}" if fixed else "暂无修复版本，评估缓解措施",
                }


def parse_pip_audit(data):
    for dep in data.get("dependencies", []):
        for v in dep.get("vulnerabilities", []):
            cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), v.get("id", ""))
            fix = (v.get("fix_versions") or [None])[0]
            yield {
                "type": "sca", "engine": "pip-audit",
                "title": f"{cve} — {dep.get('name','')}@{dep.get('version','')}",
                "cve": cve,
                "severity": "MEDIUM",
                "file": "requirements.txt", "line": 0,
                "package": dep.get("name", ""), "version": dep.get("version", ""),
                "fixed_version": fix,
                "evidence": redact((v.get("description") or "")[:300]),
                "remediation": f"升级 {dep.get('name','')} 至 {fix}" if fix else "暂无修复版本",
            }


def parse_checkov(data):
    for r in data.get("failed_checks", []):
        lines = r.get("file_line_range") or [0]
        sev = "HIGH" if r.get("severity") == "HIGH" else "MEDIUM"
        yield {
            "type": "iac", "engine": "checkov",
            "title": f"{r.get('check_id','')}: {r.get('check_name','')}",
            "rule": r.get("check_id", ""),
            "severity": sev,
            "file": r.get("file_path", ""), "line": lines[0],
            "evidence": f"resource: {r.get('resource','')}",
            "remediation": r.get("guideline", ""),
        }


def parse_bandit(data):
    for r in data.get("results", []):
        sev = norm_sev(r.get("issue_severity", ""), "bandit")
        yield {
            "type": "sast", "engine": "bandit",
            "title": f"{r.get('test_id','')}: {r.get('issue_text','')[:80]}",
            "rule": r.get("test_id", ""),
            "severity": sev,
            "file": r.get("filename", ""), "line": r.get("line_number", 0),
            "evidence": redact((r.get("code") or "")[:300]),
            "remediation": (r.get("more_info") or ""),
        }


PARSERS = {
    "semgrep": parse_semgrep, "gitleaks": parse_gitleaks, "trivy": parse_trivy,
    "osv-scanner": parse_osv, "pip-audit": parse_pip_audit, "checkov": parse_checkov,
    "bandit": parse_bandit,
}


def dedup_key(f: dict):
    if f.get("type") == "sca":
        # CVE + package + version 合并；无 CVE 用包名兜底
        return ("sca", f.get("cve") or f.get("title", ""), (f.get("package") or "").lower(), f.get("version", ""))
    return ("loc", f.get("rule", ""), (f.get("file") or "").lower(), f.get("line", 0))


def merge(a: dict, b: dict) -> dict:
    engines = sorted(set([a.get("engine", "")] + [b.get("engine", "")] + (a.get("detected_by") or [])))
    a["detected_by"] = engines
    if SEV_ORDER[b["severity"]] < SEV_ORDER[a["severity"]]:
        a["severity"] = b["severity"]
    if b.get("fixed_version") and not a.get("fixed_version"):
        a["fixed_version"] = b["fixed_version"]
    if b.get("cve") and not a.get("cve"):
        a["cve"] = b["cve"]
    return a


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    merged: dict = {}
    skipped = []
    for path in args.inputs:
        p = Path(path)
        engine = p.stem.lower().replace("_", "-")
        parser = PARSERS.get(engine)
        if not parser:
            skipped.append({"file": str(p), "reason": "未知引擎，无法解析"})
            continue
        if not p.exists() or p.stat().st_size == 0:
            skipped.append({"file": str(p), "reason": "文件不存在或为空（引擎未运行/失败）"})
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError as e:
            skipped.append({"file": str(p), "reason": f"JSON 解析失败: {e}"})
            continue
        try:
            for f in parser(data):
                k = dedup_key(f)
                if k in merged:
                    merged[k] = merge(merged[k], f)
                else:
                    f.setdefault("detected_by", [f["engine"]])
                    merged[k] = f
        except Exception as e:  # 单引擎解析失败不阻塞
            skipped.append({"file": str(p), "reason": f"解析异常: {e}"})

    findings = list(merged.values())
    for f in findings:
        f["id"] = fid(f.get("rule") or f.get("cve") or f.get("title"), f.get("file"), f.get("line"))
        f["likely_fp"] = fp_hit(f)
        if f.get("evidence"):
            f["evidence"] = redact(f["evidence"])

    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f.get("fixed_version") is None,
                                 str(f.get("file", ""))))
    stats = {
        "total": len(findings),
        "by_severity": {s: sum(1 for f in findings if f["severity"] == s)
                        for s in SEV_ORDER if any(f["severity"] == s for f in findings)},
        "by_engine": {},
        "likely_fp": sum(1 for f in findings if f["likely_fp"]),
        "skipped": skipped,
    }
    for f in findings:
        for e in f.get("detected_by", []):
            stats["by_engine"][e] = stats["by_engine"].get(e, 0) + 1

    out = {"findings": findings, "stats": stats}
    Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
