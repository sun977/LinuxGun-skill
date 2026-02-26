# LinuxGun-skill - AI应急响应技能

## 目录结构

- [SKILL.md](SKILL.md) (精简版 ✨)
  - 核心内容：触发条件、快速开始、分析格式、流程导航
- [README.txt](README.txt) (优化说明)
- [references/](references/)
  - [workflows.md](references/workflows.md) - 16个排查流程的检查项清单
  - [commands-mapping.md](references/commands-mapping.md) - 检查项 → 具体命令的完整映射表（结构化表格）
  - [analysis-guide.md](references/analysis-guide.md) - 详细的解读要点和风险判断标准

## 优化收益

- SKILL.md 从 42KB 精简到约 5KB（减少 88%）
- 采用渐进式披露原则，按需加载 references 文件
- 清晰的三层文档结构：导航 → 命令 → 解读
- 更易于维护和更新
- 符合 skill-creator 最佳实践

## 使用建议

1. 首次排查时，完整阅读 SKILL.md（核心内容）
2. 根据用户选择的流程，在 workflows.md 中查看检查项
3. 在 commands-mapping.md 中查找对应命令并执行
4. 使用 analysis-guide.md 进行深度解读和风险判断

## 主要改进

1. SKILL.md 精简：只保留触发、验证、分析格式、流程导航
2. 拆分详细内容：检查项 → workflows.md，命令 → commands-mapping.md，解读 → analysis-guide.md
3. 结构化表格：所有命令和解读要点使用表格形式，便于查找
4. 去除冗余：减少重复的解读要点描述，集中到 analysis-guide.md
5. 快速导航：SKILL.md 中提供清晰的流程选择和 references 链接

---

## 🎯 优化亮点

### 1. SKILL.md 精简化 (5KB)

- 保留：触发条件、验证规则、输出分析格式、流程导航
- 移除：大量详细命令列表、冗长解读要点
- 新增：清晰的超链接指引到 references 文件

### 2. 渐进式披露设计

- 层次1: SKILL.md (always loaded) - 快速导航和选择
- 层次2: workflows.md (按需加载) - 检查项清单
- 层次3: commands-mapping.md (按需加载) - 具体命令
- 层次4: analysis-guide.md (按需加载) - 深度解读

### 3. 结构化表格

- commands-mapping.md: 200+ 个检查项按表格式组织，包含命令、输出格式、解读重点
- analysis-guide.md: 详细的解读要点分类表格，包含风险等级、处置建议

### 4. 去重与复用

- 消除了原始文件中每个检查项重复的"解读要点"
- 所有统一解读内容集中到 analysis-guide.md
- 通过检查项ID映射，减少冗余

---

## 🚀 使用方法

### 普通排查流程

```
用户选择"系统信息排查"
         ↓
在 workflows.md 中查看→ 系统信息排查 的检查项列表
         ↓
在 commands-mapping.md 中查找→ 用户信息分析 的命令
         ↓
执行命令获取输出
         ↓
在 analysis-guide.md 中查看→ UID=0用户 的解读要点
         ↓
给出专业分析报告
```

### 快速全面排查

1. 选择"快速全面排查"（SKILL.md中已说明）
2. 按 commands-mapping.md 中标识 ⚠️ 的关键检查项优先执行
3. 使用 analysis-guide.md 中的"综合分析方法"构建时间线
4. 使用"风险评估矩阵"判定威胁等级

---

## 📋 主要改进内容

### SKILL.md (精简到核心)

- ✅ 触发条件和验证规则（保留完整）
- ✅ 标准分析报告格式（保留完整）
- ✅ 16个排查流程的清晰导航
- ✅ 快速开始指南和最佳实践
- ❌ 详细命令列表（移到 commands-mapping.md）
- ❌ 冗长解读要点（移到 analysis-guide.md）

### references/workflows.md (新增)

- ✅ 清晰列出16个排查流程
- ✅ 每个流程的子检查项清单
- ✅ 纯结构化，无具体命令和解读
- ✅ 易于快速浏览和选择

### references/commands-mapping.md (新增)

- ✅ 200+ 检查项的完整命令映射
- ✅ 表格形式：检查项 | 命令 | 输出格式 | 解读重点
- ✅ 按流程和检查项分类
- ✅ 标注 ⚠️ 的关键检查项

### references/analysis-guide.md (新增)

- ✅ 详细的解读要点和风险判断标准
- ✅ 按领域分类（用户、进程、网络、文件等）
- ✅ 风险等级说明（🔴高危 🟡中危 🟢低危）
- ✅ 综合分析方法（时间线构建、风险评估矩阵）
- ✅ 响应建议（立即响应、深度排查、持续监控）

---

## 🎖️ 符合 skill-creator 最佳实践

- ✅ Concise is Key - SKILL.md 从42KB降到5KB
- ✅ Appropriate Degrees of Freedom - 指令分层，从导航到详细
- ✅ Progressive Disclosure - 4层按需加载设计
- ✅ Avoid Duplication - 解读要点统一到 analysis-guide.md
- ✅ Structured Organization - 使用表格和清晰的分类

---

## 📝 后续建议

1. 测试验证：实际使用新结构，检查是否有遗漏的检查项或命令
2. 持续优化：根据实际使用反馈调整各文件的详细程度
3. 扩展命令：如果有未覆盖的命令，可直接添加到 commands-mapping.md
4. 更新解读：如果发现新的攻击手法，更新 analysis-guide.md

优化已完成！新的结构更加清晰、高效、易于维护。🎉