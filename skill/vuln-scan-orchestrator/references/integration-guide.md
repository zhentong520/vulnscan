# 引擎集成指南（安装 / CLI / 输出格式）

> 所有引擎统一输出 **JSON**（`--json` / `-f json`），供 `tools/aggregate_findings.py` 聚合。
> Windows 注意：**Semgrep OSS 不支持 Windows 原生运行**（静默退出，无输出无报错），
> Windows 上只能走 Docker 或 WSL；`probe_tools.py` 会用小样本试扫来探测这一点。

## Semgrep（SAST 首选）

```bash
# 安装
pip install semgrep                    # Linux/macOS
docker run --rm -v "$(pwd):/src" returntocorp/semgrep  # Docker（Windows 可用）

# 扫描（输出 JSON 到文件）
semgrep scan --config auto --json --output semgrep.json <目标目录>
# --config auto      首次联网下载推荐规则集
# --config p/python  指定语言规则集；--config p/owasp-top-ten 等
# --secrets          需要 Semgrep Secrets（付费），OSS 不含
```

JSON 结构：`results[].{check_id, path, start.line, extra.{message, severity, metadata}}`。
severity 词汇：`INFO / WARNING / ERROR` → 归一化映射：INFO→LOW/INFO, WARNING→MEDIUM, ERROR→HIGH。
规则命中里 `metadata.cwe` 可提取 CWE 编号。

## OSV-Scanner（SCA 首选）

```bash
# 安装：GitHub Releases 直接下二进制（Windows 也有官方 exe）
# https://github.com/google/osv-scanner/releases

osv-scanner scan --format json --output osv.json -r <目录>   # -r 递归
osv-scanner scan source --lockfile <path> --format json       # v2 语法
```

JSON 结构：`results[].packages[].package.{name, version, ecosystem}` +
`vulnerabilities[].{id, summary, severity, affected[].ranges[].events[].fixed}`。
`id` 即 GHSA/OSV id；`fixed` 版本用于"可处置性"排序。

## Trivy（SCA/容器/IaC 多面手）

```bash
# 安装：GitHub Releases 二进制（Windows zip）或 docker aquasec/trivy

trivy fs --format json --output trivy.json <目录>       # 文件系统（依赖+配置+密钥）
trivy image --format json --output trivy-image.json <镜像>
trivy config --format json --output trivy-config.json <目录>  # 仅 IaC
```

JSON 结构：`Results[].{Target, Class, Vulnerabilities[], Misconfigurations[], Secrets[]}`。
Vulnerabilities 字段：`VulnerabilityID`（CVE）、`PkgName`、`InstalledVersion`、`FixedVersion`、`Severity`（CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN，已是标准词汇）。

**首次运行必须先下载漏洞库（约 60MB），网络策略与 osv-scanner 相反**（实测经验，国内受限网络）：
- 默认库源 `mirror.gcr.io` 是 Google 系，**直连必被墙**；走代理又受代理稳定性影响（502 抖动）。
- **首选 `--db-repository public.ecr.aws/aquasecurity/trivy-db:2` 直连**（AWS ECR 公共库，实测一次通过）。
- `ghcr.io` 直连会 5 分钟超时，走代理抖动大，作次选。库只在首次下载/过期更新时需要网络，之后本地扫描离线可用。
- 记得 `--scanners vuln,misconfig`，否则 Misconfigurations（IaC 检查，osv-scanner 的盲区）不会输出。

## Gitleaks（Secrets 首选）

```bash
# 安装：GitHub Releases 二进制（Windows zip）

gitleaks detect --source <目录> --report-format json --report-path gitleaks.json --no-git
# --no-git   只扫工作区文件；去掉则扫 git 历史（更慢更全，按需触发）
# --redact   报告里脱敏（本技能建议始终带上，聚合器再做一层保险）
```

JSON 结构：`[].{RuleID, File, StartLine, Secret, Match}`。聚合时 Secret/Match 必须**脱敏**（头 6 + `***` + 尾 4）。

## Checkov（IaC 首选）

```bash
pip install checkov

checkov -d <目录> -o json --output-file-path checkov.json  # 目录扫描
checkov -f main.tf -o json
```

JSON 结构：`{failed_checks: [{check_id, check_name, file_path, file_line_range, guideline, resource}], passed_checks, summary}`。
failed 的才算 finding；`check_id` 形如 `CKV_AWS_18`；`guideline` 是修复文档链接。

## pip-audit（Python 依赖补充）

```bash
pip install pip-audit

pip-audit -r requirements.txt --format json -o pip-audit.json
pip-audit <venv路径或省略扫当前环境> --format json
```

JSON 结构：`dependencies[].{name, version, vulnerabilities[].{id, fix_versions, aliases}}`。
`id` 是 PYSEC，`aliases` 通常含 CVE 编号。

## Bandit（Python SAST 补充）

```bash
pip install bandit
bandit -r <目录> -f json -o bandit.json
```

`results[].{test_id, filename, line_number, issue_severity, issue_confidence, issue_text}`。
置信度 CONFIDENCE 独立字段，可用来过滤低置信命中。

## gosec（Go SAST 补充）

```bash
gosec -fmt json -out gosec.json ./...
```

## OWASP ZAP（DAST，授权闸门后）

```bash
docker run -v "$(pwd):/zap/wrk" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t <URL> -J zap.json
# zap-baseline 只做被动扫描（不改流量）；zap-full-scan 含 active 攻击，风险更高
```

Windows 无 Docker 时可用 ZAP 安装包 + Java 运行。报告字段复杂，聚合器只取 `site[].alerts[]` 的
`riskcode`（3=Critical 2=High 1=Medium 0=Low）、`alert`、`instances[].uri`。

## 通用运行约定

1. 每个引擎输出写到 `<target>/.scan-out/<engine>.json`（目录扫描完提醒用户可删）
2. 单引擎失败 → 记录 `{engine, error}` 继续下一个，不中断整条流水线
3. 扫描只读目标文件，不修改、不执行目标代码
4. 全程不把目标代码/路径上传到任何外部服务（semgrep `--config auto` 首次联网只下载规则，不上传代码）
