---
name: vuln-scan-orchestrator
description: 漏洞扫描编排层：集成 Semgrep/Trivy/Gitleaks/OSV-Scanner/Checkov 等开源扫描器，对自己拥有或已书面授权的资产做 SAST/SCA/密钥/IaC/容器扫描，聚合去重后输出定级报告。触发词：漏洞扫描、安全扫描、扫漏洞、vuln scan、SAST、SCA、依赖漏洞、密钥泄露、secret scanning、代码审计扫描、semgrep、trivy、gitleaks、checkov、安全体检。NOT for：对未授权第三方目标主动扫描或利用（违反《网络安全法》285/286 条，一律拒绝）；渗透测试的授权验证与利用阶段（用 pentest-orchestrator）；编写攻击载荷或免杀。
allowed-tools: Read, Grep, Glob, Bash, Write, Edit, WebFetch, WebSearch
---

# 漏洞扫描编排层（vuln-scan-orchestrator）

## Scope（范围，先读）
本技能是**漏洞扫描的编排层**：调用业界最佳开源扫描器，对**你拥有或已获书面授权的资产**做系统化安全扫描，
并把多工具结果**聚合、去重、定级**成一份可执行的报告。

**核心主张：集成优于重写。** 扫描引擎全部用成熟开源项目（Semgrep / Trivy / Gitleaks / OSV-Scanner / Checkov），
本技能只负责四件引擎不做的事：

1. **选型决策**——目标是什么，该跑哪几个扫描器、用什么参数（`references/scanner-matrix.md`）
2. **能力探测与优雅降级**——本机有哪些工具可用，缺的工具怎么装，不能跑的要明说而不是假装跑过
3. **聚合去重定级**——同一 CVE 被 Trivy 和 OSV-Scanner 同时报出时合并成一条；各工具 severity 词汇归一化
4. **授权闸门**——动态扫描（DAST）必须绑定书面授权，缺授权直接终止

## 红线（无例外）
- **只扫自己拥有或已书面授权的资产。** 对未授权第三方目标主动扫描违反《网络安全法》第 285/286 条，
  本技能在任何形态下都不提供该能力——不因为加了"仅供学习"而改变性质。
- **不在扫描中执行目标代码。** 扫描器只做静态分析（读代码/读依赖清单），不启动被测系统、不注入载荷。
- **密钥证据脱敏。** 报告与终端输出中的密钥片段只留头尾，中间省略。
- **扫描结果不外传。** 不把发现的漏洞细节、目标信息发送到任何第三方服务。

## 架构

```
vuln-scan-orchestrator/
├── SKILL.md                          # 本文件：选型决策、流水线、闸门、报告
├── references/
│   ├── scanner-matrix.md             # 扫描器能力对比矩阵 + 选型决策树
│   ├── integration-guide.md          # 各工具安装（原生/Docker）、CLI、输出格式、聚合要点
│   ├── triage-playbook.md            # 定级、去重、误报处置、修复优先级排序
│   └── authorization-gate.md         # DAST 授权四要素模板（与 pentest-orchestrator 同源）
└── tools/
    ├── probe_tools.py                # 探测本机可用扫描器（原生/Docker/pip），输出能力清单
    ├── aggregate_findings.py         # 多工具输出聚合：归一化 severity、跨工具去重、排序
    └── render_report.py              # 聚合结果 → Markdown 报告
```

## 扫描类别与引擎映射

| 类别 | 查什么 | 首选引擎 | 备选 |
|---|---|---|---|
| **SAST** | 源码中的注入/不安全模式 | Semgrep（3000+ 社区规则，30+ 语言） | Opengrep（规则许可更宽松） |
| **SCA** | 依赖的已知 CVE | OSV-Scanner（误报最低） | Trivy、OWASP Dependency-Check |
| **Secrets** | 硬编码密钥/令牌 | Gitleaks | TruffleHog |
| **IaC** | Terraform/K8s/CFn 误配 | Checkov | Trivy config、tfsec、KICS |
| **Container** | 镜像漏洞/SBOM | Trivy | Grype + Syft |
| **DAST** ⚠️ | 运行中应用的注入/误配 | OWASP ZAP | Nuclei |

> DAST 需要**授权闸门**通过才能启用，见下文「Phase 0」。
> 语言专用补充：Python→Bandit、Go→gosec、Java→SpotBugs+FindSecBugs（注意后者 2020 年后停更）。

## 执行流水线

### Phase 0 — 授权闸门（仅 DAST 需要）
若计划包含 DAST（ZAP/Nuclei），**必须先过闸门**：目标是你自己的资产，或有书面授权四要素
（授权方签字、明确目标范围、明确时间窗、测试方法边界）。缺任一要素 → **直接终止**，不降级为"先扫扫看"。
纯静态扫描（SAST/SCA/Secrets/IaC）针对自己的代码，无需此闸门。

### Phase 1 — 能力探测
```bash
python tools/probe_tools.py --target <目录> [--scan-tools <pip --target 目录>]
```
- pip 方式安装的 semgrep/pip-audit 用 `--scan-tools` 指向 `pip install --target` 目录（PYTHONPATH 注入探测）
- 独立二进制（gitleaks/trivy/osv-scanner）放在任意目录并 `export PATH="<目录>:$PATH"` 即可被探测
- Semgrep 的探测是**真实试扫**而非版本查询——Windows 原生会静默退出，必须验证
输出：本机可用引擎清单（native / docker / pip 可装）、目标特征识别（语言/依赖清单/IaC 文件）、
以及**建议的扫描计划**（跑哪些引擎、跳过哪些、为什么）。
目标没有对应生态时明确说"无适用引擎"，不硬凑。

### Phase 2 — 执行扫描
按计划逐个跑，每个引擎输出**原始 JSON**（不转 Markdown，保留结构化细节供聚合）。
原则：
- 一个引擎失败不阻塞其他引擎，记录失败原因继续
- 扫描范围限定在目标目录，不扫 `.git` 历史除非用户明确要（gitleaks 单独触发）
- 超长扫描（全量容器镜像）先问范围或限制为文件系统层

### Phase 3 — 聚合定级
```bash
python tools/aggregate_findings.py --inputs <各引擎JSON> --out findings.json
```
做三件事：
1. **Severity 归一化**——各工具词汇（ERROR/WARNING、CRITICAL/HIGH、High/Medium/Low、CVSS）统一到
   `CRITICAL / HIGH / MEDIUM / LOW / INFO`
2. **跨工具去重**——同 `CVE + package` 合并为一条并标注 `detected_by: [trivy, osv-scanner]`；
   同 `rule + file + line` 合并。**去重发生在报告生成前**，所以计数是去重后的唯一 finding 数
3. **可处置性标注**——有 `fixed_version` 的排前（能直接升级解决）；标记疑似误报特征

### Phase 4 — 报告
```bash
python tools/render_report.py --findings findings.json --out vuln-report.md
```
报告结构见 `references/triage-playbook.md` 的模板：执行摘要（按 severity 计数 + 一句话结论）→
按优先级分组的 finding（含文件/行号/证据/修复建议）→ 未覆盖项与局限说明。

## 误报控制（本技能的核心价值）
开源扫描器的已知短板，必须在报告里如实标注而不是照单全收：
- **Trivy/OWASP DC**：CPE 匹配启发式导致误报偏高；仅"依赖存在 CVE"不等于"可达可利用"——
  无可达性分析时标注"需人工确认可达性"
- **Semgrep OSS**：单文件模式匹配，无跨文件污点分析；规则命中需人工复核上下文
- **ZAP**：对现代 SPA 误报较多
- **所有工具**：测试夹具/示例代码/死代码中的命中，优先级应低于生产路径命中
   → 聚合时按文件路径分层（`test/`、`fixtures/`、`examples/` 降权）

## 常见坑速查
| 现象 | 处理 |
|---|---|
| 引擎未安装 | `probe_tools.py` 会给出安装命令；Docker 可用时优先容器方式（不污染本机） |
| Docker daemon 未运行 | `docker ps` 失败即不可用，别假设容器方式可行 |
| 扫描超时 | 缩小范围（指定子目录/单文件）或降低规则集 |
| 结果为空 | 先确认目标有对应生态（Java 项目跑 Bandit 必然空手） |
| 同一 CVE 报多次 | 正常，`aggregate_findings.py` 会合并 |
| 网络拉不到规则库 | Semgrep 规则库需联网首次下载；离线时用本地规则 |

## 完成前验证清单（必过）
- [ ] 已确认目标为自有或已授权资产（DAST 额外过了授权闸门）
- [ ] `probe_tools.py` 输出的能力清单如实反映了实际可用引擎（没跑的就是没跑）
- [ ] 报告中的 finding 数是**去重后**的唯一 finding 数，且标注了各自由哪些工具检出
- [ ] Severity 已归一化，非原始工具词汇
- [ ] 密钥证据已脱敏
- [ ] 明确列出**未覆盖项**（哪些引擎因缺失/失败没跑，因此哪些漏洞类别没查）
- [ ] 修复建议按"可处置性"排序（有 fixed_version 的在前）

更多细节见：
`references/scanner-matrix.md`、`references/integration-guide.md`、`references/triage-playbook.md`、`references/authorization-gate.md`。
