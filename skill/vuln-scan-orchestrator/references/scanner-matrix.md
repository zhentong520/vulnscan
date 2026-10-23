# 扫描器能力对比矩阵

> 选型依据：覆盖类别、许可限制、安装方式、输出格式、误报特征。
> **原则：每个类别选一个首选引擎，不重复堆同类工具**（同一层跑三个工具只会得到三份需要合并的噪声）。

## 总览

| 引擎 | 类别 | 语言/对象覆盖 | 许可 | 安装 | 输出 | 误报特征 |
|---|---|---|---|---|---|---|
| **Semgrep** (CE) | SAST | 30+ 语言 | 引擎 LGPL-2.1 / 规则 Semgrep Rules License | pip / docker / 二进制 | JSON, SARIF | 单文件模式匹配，无跨文件污点；规则命中需上下文复核 |
| **Opengrep** | SAST | 30+ 语言 | 引擎+规则均 LGPL（无限制） | pip / docker / 二进制 | JSON, SARIF | 同 Semgrep；规则许可更宽松，适合内部分发 |
| **OSV-Scanner** | SCA | Go/npm/pip/Maven/Gradle/Cargo/NuGet 等 | Apache-2.0 | Go / docker / 二进制 | JSON, SARIF | 误报最低（生态专用匹配）；只报已知 CVE，不做可达性 |
| **Trivy** | SCA+IaC+Secret+Container | 镜像/文件系统/K8s/Terraform | Apache-2.0 | 二进制 / docker | JSON, SARIF, table | CPE 匹配启发式，依赖类误报偏高 |
| **Gitleaks** | Secrets | 任意（40+ 密钥类型） | MIT | Go / docker / 二进制 | JSON, SARIF, CSV | 低误报；通用规则（generic-api-key）需复核 |
| **TruffleHog** | Secrets | 任意 + 密钥有效性验证 | AGPL-3.0 | Go / docker | JSON | 验证模式会向厂商发请求——注意外泄风险 |
| **Checkov** | IaC | Terraform/CFn/K8s/Helm/ARM/Bicep | Apache-2.0 | pip / docker | JSON, SARIF, CLI | 策略偏严，误报中等；有图分析跨资源能力 |
| **Bandit** | SAST (Python) | Python | Apache-2.0 | pip | JSON, SARIF | 仅 Python；置信度分级可帮助筛误报 |
| **gosec** | SAST (Go) | Go | Apache-2.0 | Go / docker | JSON, SARIF | 仅 Go |
| **OWASP ZAP** ⚠️ | DAST | 运行中的 Web 应用 | Apache-2.0 | docker / 二进制 / Java | JSON, XML, HTML | 对现代 SPA 误报较多；**需授权闸门** |
| **Nuclei** ⚠️ | DAST | 基于模板的网络/Web 探测 | MIT | Go / docker | JSON | 模板双刃性；**需授权闸门** |

⚠️ = 动态扫描，只在授权通过后启用。

## 选型决策树

```
目标是什么？
├─ 源码目录
│   ├─ 主语言是什么？
│   │   ├─ Java/Kotlin        → Semgrep（+ 可选 SpotBugs/FindSecBugs，注意后者停更）
│   │   ├─ Python             → Semgrep + Bandit（双重覆盖，Bandit 置信度可筛误报）
│   │   ├─ Go                 → Semgrep + gosec
│   │   ├─ JS/TS              → Semgrep
│   │   └─ 多语言/未知        → Semgrep（唯一通用解）
│   └─ 同时必跑：Gitleaks（密钥不分语言）+ 依赖扫描
├─ 依赖清单存在（pom.xml / package.json / requirements.txt / go.mod）
│   └─ OSV-Scanner（首选）→ Trivy（需要 IaC/容器一起扫时合并）
├─ IaC 文件存在（*.tf / *.yaml k8s / CloudFormation）
│   └─ Checkov（策略最全 + 跨资源图分析）
├─ 容器镜像 / Dockerfile
│   └─ Trivy image（首选）→ Grype + Syft（需要 SBOM 单独流转时）
├─ 运行中的应用 + 有书面授权
│   └─ OWASP ZAP（先 passive 后 active；active 前再过一次授权确认）
└─ 以上都不是
    └─ 明说"无适用引擎"，不硬凑
```

## 组合建议（按项目类型）

| 项目类型 | 推荐组合 | 说明 |
|---|---|---|
| Java/Spring Boot 单体 | Semgrep + OSV-Scanner + Gitleaks | Maven/Gradle 依赖走 OSV；源码走 Semgrep |
| Node 前端 | Semgrep + OSV-Scanner + Gitleaks | package-lock.json 给 OSV |
| Python 服务 | Semgrep + Bandit + pip-audit + Gitleaks | pip-audit 对 PyPI 生态最准 |
| Go 服务 | Semgrep + gosec + OSV-Scanner + Gitleaks | |
| K8s/Terraform 仓库 | Checkov + Trivy config + Gitleaks | IaC 是主战场 |
| 容器镜像 | Trivy image + Trivy fs（配置+密钥） | 一个工具两层扫 |
| 全栈单体仓（如 aideepin） | Semgrep + OSV-Scanner + Gitleaks + Checkov(若有 IaC) | 四引擎并行，聚合去重 |

## 已知覆盖盲区（必须在报告中说明）

| 盲区 | 原因 | 缓解 |
|---|---|---|
| 跨文件污点分析 | Semgrep OSS 无；CodeQL 有但**专有代码商用需付费** | 关键路径人工审计；Opengrep 有过程间分析 |
| 业务逻辑漏洞（IDOR、越权、竞态） | 模式匹配无法理解语义 | 用 `authz-object-binding` / `multistep-race-cache` 等白盒审计 skill |
| AI 生成代码特有问题 | 各工具均无专门规则 | 关注幻觉 API 调用、不安全默认值 |
| 可达性分析 | 开源 SCA 只报"依赖有 CVE" | 报告标注"需人工确认可达性"，避免虚高优先级 |
| 0day / 未公开漏洞 | 依赖漏洞库 | 无解，接受局限 |

## 许可注意
- **CodeQL**：免费仅限开源代码与学术研究；**专有代码在 CI/CD 使用需 GitHub Advanced Security 付费许可**。本技能默认不纳入。
- **TruffleHog**：AGPL-3.0，且验证模式会向第三方发请求（可能暴露密钥存在性）。默认不用。
- **FindSecBugs**：最后公开发布 2020 年，维护新鲜度有风险，作为可选项并注明。
