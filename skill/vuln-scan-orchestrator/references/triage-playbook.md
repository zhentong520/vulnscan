# 定级与处置手册（triage playbook）

## Severity 归一化映射

| 工具原始词汇 | 归一化 |
|---|---|
| Trivy / Checkov：CRITICAL | CRITICAL |
| Trivy：HIGH；Semgrep：ERROR | HIGH |
| Trivy：MEDIUM；Semgrep：WARNING；Checkov 默认 failed；Bandit：issue_severity=MEDIUM | MEDIUM |
| Trivy：LOW/UNKNOWN；Semgrep：INFO；Bandit：LOW | LOW / INFO |
| ZAP riskcode | 3→CRITICAL 2→HIGH 1→MEDIUM 0→LOW |
| CVSS ≥9.0 / ≥7.0 / ≥4.0 / <4.0 | CRITICAL / HIGH / MEDIUM / LOW |

## 优先级排序原则（报告分组顺序）

1. **CRITICAL/HIGH + 有 fixed_version** → 立即修（升级依赖即可解决，成本最低收益最高）
2. **CRITICAL/HIGH + 无 fixed_version** → 评估缓解措施（版本锁定、WAF、访问控制）
3. **Secrets（任何 severity）** → 视为已泄露立即轮换，而不是"待办"——密钥一旦进过仓库历史就假定被爬取
4. **MEDIUM/LOW + 生产路径** → 排入常规修复迭代
5. **命中位于 test/、fixtures/、examples/、docs/** → 降权标注，不与生产路径混排

## 去重规则（aggregate_findings.py 的实现依据）

| 场景 | 合并键 | 合并后 |
|---|---|---|
| 同一 CVE 被多工具报出 | `CVE 编号 + package + version` | 一条，`detected_by` 记录全部来源，取最高 severity |
| 同一规则命中相邻行 | `rule_id + file + line 相邻 ±2` | 一条，行号取首行 |
| Gitleaks 与 Trivy 的 secret 检测重叠 | `file + line + 密钥类型近似` | 保留 Gitleaks（更准），Trivy 来源附注 |

## 误报处置

**疑似误报特征（聚合器自动标注 `likely_fp`，人工终审）：**
- 命中在测试夹具/示例/注释中的注入类规则
- SCA 报的 CVE 但项目实际未调用该依赖的相关功能（无可达性分析，标"需人工确认"）
- Checkov 对带 variables 的 Terraform 模板误判默认值
- Semgrep 对 ORM 参数化查询误报 SQL 注入（规则按裸字符串拼接写的）

**处置动作：** 不删数据，标 `status: confirmed / likely_fp / accepted_risk`，报告里分开展示。
误报样本攒下来可以沉淀为该项目的扫描基线（Semgrep 支持 `--baseline`，Checkov 支持 skip 列表）。

## 修复建议写法

每条 finding 的修复建议必须包含三要素：
1. **动作**：升级到 `<fixed_version>` / 重构为参数化查询 / 移除并轮换密钥
2. **位置**：文件 + 行号
3. **验证方式**：修复后重跑哪个引擎的哪条规则确认关闭

## 报告模板

```markdown
# 漏洞扫描报告：<项目名>
- 扫描时间 / 目标路径 / 提交版本（若为 git 仓库）
- 引擎与版本：semgrep x.y / trivy x.y / ...
- 授权状态：自有资产 / 书面授权（DAST 附授权摘要）

## 执行摘要
CRITICAL n | HIGH n | MEDIUM n | LOW n | INFO n
一句话结论：<最需要立刻处理的事>

## 发现明细（按上文优先级分组）
### [CRITICAL] CVE-XXXX-XXXX — <package>@<version>
- 检出：trivy, osv-scanner
- 位置：pom.xml:42
- 说明：<summary>
- 修复：升级至 <fixed_version>；重跑 osv-scanner 确认
- 状态：confirmed

## 未覆盖项
- <引擎名> 未运行（原因：<未安装/不适用/失败>），因此<漏洞类别>未检查
## 局限
- 无跨文件污点分析 / 无可达性分析 / 业务逻辑漏洞不在覆盖范围
```

## 完成标准

- [ ] 计数是去重后的
- [ ] 每条标注检出工具
- [ ] Secrets 已脱敏且单列（附"立即轮换"提示）
- [ ] 未覆盖项与局限如实列出
