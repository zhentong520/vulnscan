# VulnScan — 轻量级漏洞扫描系统

一个简单可用的 Web 漏洞扫描服务：提交扫描目标 → 后台跑扫描 → 聚合去重 → 在线看报告。

集成四个经过真实项目实测验证的开源引擎：

| 引擎 | 能力 | 目标类型 | 版本实测 |
|------|------|----------|----------|
| [gitleaks](https://github.com/gitleaks/gitleaks) | 密钥泄漏检测（本地运行，无网络依赖） | 本地目录 | 8.30.1 |
| [osv-scanner](https://github.com/google/osv-scanner) | 依赖漏洞 SCA（lockfile 级，直连 api.osv.dev） | 本地目录 | 2.7.0 |
| [Trivy](https://github.com/aquasecurity/trivy) | 依赖漏洞 + IaC 配置（库源 `public.ecr.aws` 直连） | 本地目录 | 0.76.1 |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Web 站点主动扫描 DAST（内置 8000+ 模板） | http(s):// URL | 3.11.1 |

## 与 vuln-scan-orchestrator skill 的关系

本系统源自 [vuln-scan-orchestrator](https://github.com/zhentong520/vuln-scan-orchestrator) skill 的实测沉淀：

- **`tools/`** — 从 skill 中 vendor 的聚合/报告管线脚本（`aggregate_findings.py`、`render_report.py`），负责多引擎结果去重合并、误报降权（test/dist/docs 等目录）、密钥脱敏（头 6 + `***` + 尾 4）
- **`skill/`** — skill 的完整副本（SKILL.md + 4 份 references + 3 个工具脚本），包含引擎选型矩阵、集成指南、triage playbook、DAST 授权门禁等运维知识

`scanner.py` 优先使用仓库内置的 `tools/`，若本机安装了同名 skill 也可自动回退复用。两处脚本同源维护。

## 快速开始

```bash
# 1. 准备引擎二进制（Windows），放入 scan_tools/bin/：
#    gitleaks.exe / osv.exe / trivy.exe / nuclei.exe
#    nuclei 首次运行前需拉取模板：nuclei -update-templates
#    （下载地址见 skill/vuln-scan-orchestrator/references/integration-guide.md）

# 2. 配置 config.json 指向二进制目录
{ "scan_tools_dir": "C:/path/to/scan-tools" }

# 3. 安装依赖并启动（Python 3.12+，Flask）
pip install flask
python app.py
# 打开 http://127.0.0.1:5330
```

界面操作：填目标（本地目录绝对路径，或 http(s):// 站点 URL）→ 勾选引擎 → URL 目标需勾选**授权确认** → 开始扫描 → 等状态变为 done → 查看统计卡 / 过滤结果表 / 完整 Markdown 报告。

### Web 扫描（内网站点）授权与降噪

- **授权闸门**：URL 目标必须勾选「我确认已获得该站点的扫描授权」，前后端双重校验，仅限内部 / 已授权资产
- **默认降噪**：自动排除 `intrusive / dos / fuzz` 标签模板（不会打挂目标），限速 60 req/s
- **直连目标**：自动剔除代理环境变量，内网地址走系统代理会不通

## API

| 接口 | 说明 |
|------|------|
| `POST /api/scans` | 提交扫描 `{target, engines[], authorized}`（URL 目标 `authorized` 必须为 true） |
| `GET /api/scans` | 历史列表 |
| `GET /api/scans/<id>` | 扫描详情（状态、统计） |
| `GET /api/scans/<id>/findings` | 结果过滤：`severity` / `type` / `engine` / `q` / `include_fp` |
| `GET /api/scans/<id>/report` | Markdown 报告 |

## 实测要点（踩坑沉淀）

- **osv-scanner 必须直连** api.osv.dev——走本地代理会卡死（代码已自动剔除 proxy 环境变量）
- **trivy 库源**默认 `mirror.gcr.io` 在国内不可达，已固定用 `--db-repository public.ecr.aws/aquasecurity/trivy-db:2` 直连；漏洞库下载后本地扫描离线可用
- **gitleaks** `detect` 默认只扫 git 历史，非 git 目录自动加 `--no-git`
- **nuclei** 同样直连目标（内网地址走代理不通）；`-duc` 禁用更新检查避免启动卡顿；模板放 `~/nuclei-templates` 即离线可用
- SCA 引擎 exit code 1 表示「发现了漏洞」，属正常完成而非失败
- 同一时间只跑一个扫描任务（串行锁），扫描结果存 SQLite

## 已知局限

- 目录扫描不支持 git clone / 容器镜像；Web 扫描为单 URL（无爬虫发现的整站递归）
- 单用户，无认证——请勿暴露到公网
- 单任务串行，无并发调度
- Windows 下引擎二进制为 `.exe`（Linux 可在 `find_exe` 中改扩展名）

## License

MIT
