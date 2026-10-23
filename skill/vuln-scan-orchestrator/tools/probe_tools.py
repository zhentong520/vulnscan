#!/usr/bin/env python3
"""探测本机可用扫描器 + 识别目标特征 + 生成扫描计划。

用法:
    python probe_tools.py --target <目录> [--scan-tools <pip install --target 目录>]

输出 JSON:
{
  "engines": { "<name>": {"available": bool, "version": str|null, "via": "native|pip-target|docker", "note": str} },
  "target_profile": {"languages": [...], "has_lockfiles": [...], "has_iac": [...], "is_git": bool},
  "plan": [{"engine": str, "command": [...], "reason": str, "output": str}]
}

只读探测，不修改目标。Semgrep 在 Windows 原生静默退出（官方不支持 Windows），
因此用小样本试扫验证而不是只看命令是否存在。
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SEMGRPG_SMOKE = "import hashlib\nhashlib.md5(b'x')\n"

LOCKFILES = {
    "requirements.txt", "Pipfile.lock", "poetry.lock", "pyproject.toml",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock", "*.csproj", "Gemfile.lock", "composer.lock",
}
IAC_HINTS = ("*.tf", "*.tfvars", "Chart.yaml", "*.yaml")


def run(cmd, **kw):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=kw.pop("timeout", 60), **kw)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, "", str(e)


def probe_native(name: str, args: list[str], scan_tools: str = "") -> dict:
    """PATH 查找 + scan-tools/bin 回退（独立二进制常集中放在该目录）。"""
    exe = shutil.which(name)
    via = "native"
    if not exe and scan_tools:
        for suffix in (".exe", ".cmd", ""):
            cand = Path(scan_tools) / "bin" / f"{name}{suffix}"
            if cand.exists():
                exe = str(cand)
                via = "local-bin"
                break
    if not exe:
        return {"available": False, "version": None, "via": "native", "note": f"{name} 不在 PATH"}
    rc, out, err = run([exe] + args)
    ver = out.splitlines()[0] if out else None
    return {"available": rc == 0, "version": ver, "via": via, "note": "", "exe": exe}


def probe_pip_target(module: str, scan_tools: str) -> dict:
    """pip install --target 安装的包：通过 PYTHONPATH 探测。"""
    py = sys.executable
    env = dict(os.environ, PYTHONPATH=scan_tools)
    rc, out, err = run([py, "-m", module, "--version"], env=env, timeout=90)
    if rc == 0 and out:
        ver = next((l for l in out.splitlines() if l and "deprecat" not in l.lower()), out.splitlines()[0])
        return {"available": True, "version": ver, "via": "pip-target", "note": f"PYTHONPATH={scan_tools}"}
    return {"available": False, "version": None, "via": "pip-target", "note": err[:200] or "模块不可用"}


def probe_docker(image: str) -> dict:
    rc, out, _ = run(["docker", "ps"], timeout=15)
    if rc != 0:
        return {"available": False, "version": None, "via": "docker", "note": "Docker daemon 不可用"}
    return {"available": True, "version": None, "via": "docker", "note": f"可用镜像 {image}"}


def probe_semgrep(scan_tools: str) -> dict:
    """Semgrep Windows 原生会静默退出——以真实试扫为最终裁决。

    --version/import 检查只做预检（弃用警告走 stderr，stdout 可能全空），
    试扫输出含 '"results"' 才算可用。
    """
    def _clean(s: str) -> str:
        return "\n".join(l for l in (s or "").splitlines() if "deprecat" not in l.lower()).strip()

    via = "pip-target" if scan_tools else "native"
    env = dict(os.environ, PYTHONPATH=scan_tools) if scan_tools else os.environ
    # 预检：模块能否加载（决定用 -m 还是裸命令）
    rc0, _, _ = run([sys.executable, "-c", "import semgrep"], env=env, timeout=120)
    if rc0 != 0 and scan_tools:
        return {"available": False, "version": None, "via": via,
                "note": f"semgrep 模块不可加载（PYTHONPATH={scan_tools}）"}
    base_cmd = [sys.executable, "-m", "semgrep"] if rc0 == 0 else ["semgrep"]

    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "smoke.py").write_text(SEMGRPG_SMOKE, encoding="utf-8")
        rc, out, err = run(base_cmd + ["scan", "--config", "p/default", "--json", td],
                           env=env, timeout=300)
        if rc == 0 and '"results"' in out:
            return {"available": True, "version": result_version(base_cmd, env), "via": via,
                    "note": f"PYTHONPATH={scan_tools}" if scan_tools else ""}
        if rc == 0:
            return {"available": False, "version": None, "via": via,
                    "note": "试扫静默退出无输出——Windows 原生不支持 Semgrep，需 Docker/WSL"}
        detail = (_clean(err) or _clean(out))[:150]
        return {"available": False, "version": None, "via": via,
                "note": f"试扫失败: {detail}" if detail else "试扫失败（无可用输出）"}


def result_version(base_cmd, env) -> str | None:
    rc, out, err = run(base_cmd + ["--version"], env=env, timeout=120)
    lines = [l for l in out.splitlines() if l.strip() and "deprecat" not in l.lower()]
    return lines[0] if lines else None


def profile_target(target: Path) -> dict:
    langs, locks, iac = set(), set(), []
    for p in target.rglob("*"):
        if any(s in p.parts for s in (".git", "node_modules", ".venv", "venv", "target", "dist", "build")):
            continue
        if p.is_file():
            n = p.name
            if n == "*.java" or n.endswith(".java"):
                langs.add("java")
            elif n.endswith((".py",)):
                langs.add("python")
            elif n.endswith((".go",)):
                langs.add("go")
            elif n.endswith((".js", ".ts", ".jsx", ".tsx", ".vue")):
                langs.add("js-ts")
            if n in LOCKFILES:
                locks.add(n)
            if n.endswith(".tf") or n.endswith(".tfvars"):
                iac.append(p.name)
            if n == "Chart.yaml" or (n.endswith(".yaml") and "k8s" in str(p).lower()):
                iac.append(p.name)
    return {
        "languages": sorted(langs),
        "has_lockfiles": sorted(locks),
        "has_iac": iac[:20],
        "is_git": (target / ".git").exists(),
    }


def build_plan(profile: dict, engines: dict, target: str, outdir: str) -> list:
    plan = []
    langs = profile["languages"]

    def add(engine, cmd, reason):
        plan.append({"engine": engine, "command": cmd, "reason": reason,
                     "output": str(Path(outdir) / f"{engine}.json")})

    def wanted(engine, reason):
        """引擎可用才排进计划；不可用则记录跳过原因。"""
        eng = engines.get(engine, {})
        if eng.get("available"):
            return True
        plan.append({"engine": engine, "command": [], "skip": True,
                     "reason": f"{reason}，但引擎不可用（{eng.get('note') or '未安装'}）", "output": ""})
        return False

    if langs and wanted("semgrep", "源码 SAST"):
        sg = engines.get("semgrep", {})
        base = [sys.executable, "-m", "semgrep"] if sg.get("via") == "pip-target" else ["semgrep"]
        add("semgrep", base + ["scan", "--config", "p/default", "--json", "--output",
                               str(Path(outdir) / "semgrep.json"), target],
            f"源码 SAST（语言: {','.join(langs) or '未知'}）")
    lock_kinds = ("pom.xml", "package.json", "go.mod", "requirements.txt", "Cargo.toml",
                  "package-lock.json", "pnpm-lock.yaml", "yarn.lock")
    if any(k in profile["has_lockfiles"] for k in lock_kinds) and \
            wanted("osv-scanner", "存在依赖清单，SCA 扫描已知 CVE"):
        add("osv-scanner", [engines["osv-scanner"].get("exe", "osv-scanner"),
                            "scan", "-r", "--format", "json",
                            "--output", str(Path(outdir) / "osv-scanner.json"), target],
            "存在依赖清单，SCA 扫描已知 CVE")
    if wanted("gitleaks", "密钥硬编码扫描"):
        add("gitleaks", [engines["gitleaks"].get("exe", "gitleaks"),
                         "detect", "--source", target, "--no-git", "--redact",
                         "--report-format", "json", "--report-path", str(Path(outdir) / "gitleaks.json")],
            "密钥硬编码扫描（--no-git 只扫工作区）")
    if profile["has_iac"] and engines.get("trivy", {}).get("available"):
        add("trivy-config", [engines["trivy"].get("exe", "trivy"), "config", "--format", "json",
                             "--output", str(Path(outdir) / "trivy.json"), target], "存在 IaC 文件")
    elif profile["has_iac"] and not engines.get("trivy", {}).get("available"):
        plan.append({"engine": "trivy-config", "command": [], "skip": True,
                     "reason": "存在 IaC 文件，但 trivy 不可用", "output": ""})
    if "python" in langs and engines.get("pip-audit", {}).get("available"):
        req = Path(target) / "requirements.txt"
        if req.exists():
            env = dict(os.environ, PYTHONPATH=engines["pip-audit"]["note"].split("=", 1)[-1]) \
                if "PYTHONPATH=" in engines["pip-audit"]["note"] else os.environ
            add("pip-audit", [sys.executable, "-m", "pip_audit", "-r", str(req),
                              "--format", "json", "-o", str(Path(outdir) / "pip-audit.json")],
                "Python 依赖 CVE（PyPI 生态最准）")
            plan[-1]["env"] = {"PYTHONPATH": env.get("PYTHONPATH", "")}
    if not plan:
        plan.append({"engine": "none", "command": [], "reason": "目标无对应生态（无源码语言/依赖清单/IaC），不硬凑", "output": ""})
    return plan


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--scan-tools", default="", help="pip install --target 的目录（pip-audit/semgrep 所在）")
    ap.add_argument("--out", default="", help="结果 JSON 输出路径（缺省打印 stdout）")
    ap.add_argument("--plan-outdir", default="", help="扫描计划中输出文件的目标目录")
    args = ap.parse_args()

    target = Path(args.target).resolve()
    if not target.is_dir():
        print(json.dumps({"error": f"目标不存在: {target}"}))
        return 2
    outdir = args.plan_outdir or str(target / ".scan-out")

    engines: dict[str, dict] = {}
    st = args.scan_tools
    engines["semgrep"] = probe_semgrep(st)
    engines["osv-scanner"] = probe_native("osv-scanner", ["--version"], st)
    engines["gitleaks"] = probe_native("gitleaks", ["version"], st)
    engines["trivy"] = probe_native("trivy", ["--version"], st)
    engines["checkov"] = probe_native("checkov", ["--version"], st)
    engines["bandit"] = probe_native("bandit", ["--version"], st)
    engines["pip-audit"] = probe_pip_target("pip_audit", st) if st \
        else probe_native("pip-audit", ["--version"], st)
    if not engines["trivy"]["available"]:
        engines["trivy-docker"] = probe_docker("aquasec/trivy")

    profile = profile_target(target)
    plan = build_plan(profile, engines, str(target), outdir)

    result = {"engines": engines, "target_profile": profile, "plan": plan}
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
