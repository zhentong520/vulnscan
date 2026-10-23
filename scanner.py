# -*- coding: utf-8 -*-
"""VulnScan 核心层：扫描引擎封装 + 任务队列 + 结果存储。

封装三个已实测验证的引擎：
  - gitleaks    : 密钥泄漏检测（本地运行，无网络依赖）
  - osv-scanner : 依赖漏洞 SCA（需直连 api.osv.dev，走代理会卡死）
  - trivy       : 依赖漏洞 + IaC 配置（库源用 public.ecr.aws 直连）

聚合与报告复用 vuln-scan-orchestrator skill 的 tools（实测管线）。
"""
import json
import os
import sqlite3
import subprocess
import threading
import time
import traceback
import uuid
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
DATA_DIR = BASE / "data"
SCANS_DIR = DATA_DIR / "scans"
SCANS_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "scans.db"

# 聚合/渲染管线脚本：优先用仓库内置的 tools/（与 skill 同源，见 skill/ 目录），
# 找不到时回退到本机安装的 vuln-scan-orchestrator skill。
# 来源 skill: https://github.com/zhentong520/vuln-scan-orchestrator
SKILL_TOOLS = Path(r"C:/Users/Administrator/.workbuddy/skills/vuln-scan-orchestrator/tools")
PIPELINE_TOOLS = BASE / "tools"

# 同一时间只允许一个扫描任务在跑（扫描都是重 IO/网络操作）
_scan_lock = threading.Lock()

ENGINES = ("gitleaks", "osv-scanner", "trivy")


# ---------------------------------------------------------------- config / exe

def _config():
    cfg = {"scan_tools_dir": ""}
    p = BASE / "config.json"
    if p.exists():
        try:
            cfg.update(json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            pass
    return cfg


def find_exe(engine):
    """在 scan_tools/bin 下找引擎二进制，找不到返回 None。"""
    st = _config().get("scan_tools_dir", "")
    exe_map = {"gitleaks": "gitleaks.exe", "osv-scanner": "osv.exe", "trivy": "trivy.exe"}
    name = exe_map.get(engine)
    if not name:
        return None
    p = Path(st) / "bin" / name
    return p if p.exists() else None


# ---------------------------------------------------------------- engine runners
# 每个返回 (ok: bool, note: str)；exit code 1 在 SCA 引擎里表示「发现了漏洞」，属正常完成。

def _run_gitleaks(exe, target, out_json):
    cmd = [str(exe), "detect", "--source", str(target), "--no-banner", "--redact",
           "--report-format", "json", "--report-path", str(out_json)]
    # detect 默认只扫 git 历史；非 git 目录需 --no-git 才能扫到工作区文件
    if not (Path(target) / ".git").exists():
        cmd.append("--no-git")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    if r.returncode in (0, 1) and out_json.exists():
        return True, ""
    return False, f"gitleaks exit={r.returncode}: {(r.stderr or r.stdout)[-300:]}"


def _direct_env():
    """osv-scanner 必须直连 api.osv.dev —— 剔除所有 proxy 环境变量。"""
    return {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}


def _run_osv(exe, target, out_json):
    cmd = [str(exe), "scan", "source", "-r", str(target),
           "--format", "json", "--output", str(out_json)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600,
                       env=_direct_env())
    if r.returncode in (0, 1) and out_json.exists():
        return True, ""
    return False, f"osv-scanner exit={r.returncode}: {(r.stderr or r.stdout)[-300:]}"


def _run_trivy(exe, target, out_json):
    cmd = [str(exe), "fs", "--scanners", "vuln,misconfig",
           "--db-repository", "public.ecr.aws/aquasecurity/trivy-db:2",
           "--format", "json", "--output", str(out_json), "--quiet", str(target)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600,
                       env=_direct_env())
    if r.returncode == 0 and out_json.exists():
        return True, ""
    return False, f"trivy exit={r.returncode}: {(r.stderr or r.stdout)[-300:]}"


RUNNERS = {"gitleaks": _run_gitleaks, "osv-scanner": _run_osv, "trivy": _run_trivy}


# ---------------------------------------------------------------- storage

def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans(
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            engines TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            error TEXT DEFAULT '',
            created TEXT NOT NULL,
            finished TEXT DEFAULT '',
            stats TEXT DEFAULT '{}')""")


def _set(scan_id, **kw):
    sets = ", ".join(f"{k}=?" for k in kw)
    with _db() as conn:
        conn.execute(f"UPDATE scans SET {sets} WHERE id=?", (*kw.values(), scan_id))


def get_scan(scan_id):
    with _db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None


def list_scans(limit=100):
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def scan_paths(scan_id):
    d = SCANS_DIR / scan_id
    return {"dir": d, "out": d / ".scan-out", "findings": d / ".scan-out" / "findings.json",
            "report": d / ".scan-out" / "vuln-report.md"}


# ---------------------------------------------------------------- pipeline

def _aggregate(scan_id, engines_ran):
    """调聚合 + 渲染脚本（实测管线，含去重 / 误报降权 / 脱敏）。"""
    tools = PIPELINE_TOOLS if (PIPELINE_TOOLS / "aggregate_findings.py").exists() else SKILL_TOOLS
    paths = scan_paths(scan_id)
    inputs = [str(paths["out"] / f"{e}.json") for e in engines_ran
              if (paths["out"] / f"{e}.json").exists()]
    findings, report = paths["findings"], paths["report"]
    r1 = subprocess.run(
        ["python", str(tools / "aggregate_findings.py"),
         "--inputs", *inputs, "--out", str(findings)],
        capture_output=True, text=True, timeout=600)
    if not findings.exists():
        raise RuntimeError(f"aggregate failed: {r1.stdout[-300:]} {r1.stderr[-300:]}")
    r2 = subprocess.run(
        ["python", str(tools / "render_report.py"),
         "--findings", str(findings), "--project", get_scan(scan_id)["target"],
         "--engines", ",".join(engines_ran), "--out", str(report)],
        capture_output=True, text=True, timeout=600)
    return findings, report, r2.stdout


def _stats(findings_path):
    data = json.loads(findings_path.read_text(encoding="utf-8"))
    fs = data.get("findings", data if isinstance(data, list) else [])
    sev, typ, top = {}, {}, 0
    for f in fs:
        s = f.get("severity") or "UNKNOWN"
        sev[s] = sev.get(s, 0) + 1
        t = f.get("type") or "other"
        typ[t] = typ.get(t, 0) + 1
        if not f.get("likely_fp"):
            top += 1
    return {"total": len(fs), "actionable": top, "by_severity": sev, "by_type": typ}


def execute_scan(scan_id, target, engines):
    """后台线程入口：跑引擎 → 聚合 → 渲染 → 落统计。"""
    if not _scan_lock.acquire(timeout=18000):
        _set(scan_id, status="error", error="等待其他扫描任务超时")
        return
    try:
        _set(scan_id, status="running")
        paths = scan_paths(scan_id)
        paths["out"].mkdir(parents=True, exist_ok=True)
        ran, notes = [], []
        for eng in engines:
            exe = find_exe(eng)
            if not exe:
                notes.append(f"{eng}: 未找到可执行文件，跳过")
                continue
            out = paths["out"] / f"{eng}.json"
            ok, note = RUNNERS[eng](exe, target, out)
            if ok:
                ran.append(eng)
            else:
                notes.append(f"{eng}: {note}")
        if not ran:
            raise RuntimeError("所有引擎均失败：" + "; ".join(notes) or "无可用引擎")
        findings, report, _ = _aggregate(scan_id, ran)
        stats = _stats(findings)
        stats["engine_notes"] = notes
        _set(scan_id, status="done", finished=datetime.now().isoformat(" ", "seconds"),
             stats=json.dumps(stats, ensure_ascii=False))
    except Exception as e:
        _set(scan_id, status="error", finished=datetime.now().isoformat(" ", "seconds"),
             error=f"{e}\n{traceback.format_exc()[-500:]}")
    finally:
        _scan_lock.release()


def create_scan(target, engines):
    target = str(Path(target).resolve())
    if not Path(target).is_dir():
        raise ValueError(f"目标目录不存在: {target}")
    engines = [e for e in engines if e in ENGINES]
    if not engines:
        raise ValueError("至少选择一个引擎")
    scan_id = uuid.uuid4().hex[:12]
    with _db() as conn:
        conn.execute("INSERT INTO scans(id,target,engines,status,created) VALUES(?,?,?,?,?)",
                     (scan_id, target, ",".join(engines), "queued",
                      datetime.now().isoformat(" ", "seconds")))
    threading.Thread(target=execute_scan, args=(scan_id, target, engines),
                     daemon=True, name=f"scan-{scan_id}").start()
    return get_scan(scan_id)


def get_findings(scan_id, severity=None, ftype=None, engine=None, keyword=None,
                 include_fp=True, limit=500):
    p = scan_paths(scan_id)["findings"]
    if not p.exists():
        return None
    data = json.loads(p.read_text(encoding="utf-8"))
    fs = data.get("findings", [])
    out = []
    kw = (keyword or "").lower()
    for f in fs:
        if not include_fp and f.get("likely_fp"):
            continue
        if severity and f.get("severity") != severity:
            continue
        if ftype and f.get("type") != ftype:
            continue
        if engine and engine not in (f.get("detected_by") or ""):
            continue
        if kw and kw not in json.dumps(f, ensure_ascii=False).lower():
            continue
        out.append(f)
    # CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    out.sort(key=lambda f: order.get(f.get("severity"), 9))
    return out[:limit]


init_db()
