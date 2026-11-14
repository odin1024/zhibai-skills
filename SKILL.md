---
name: zhibai-skills
description: 知白守黑1024 的 Agent Skills 合集索引。覆盖投标技术文档（参数响应表、测试大纲）、简历诊断、家庭防骗（可疑信息鉴定、爸妈防骗）、反诈宣传素材、技能供应链安全审计等方向。本文件是路由入口：先判断用户需求属于哪一类，再读取 skills/<slug>/SKILL.md 并按其中的工作流执行，不要在本层直接作答。
whenToUse: 用户提到招投标、参数响应表、技术偏离表、测试大纲、验收测试；简历诊断、简历优化、JD 匹配；防骗、防诈、反诈、可疑短信、诈骗链接、爸妈防骗、反诈宣讲素材；或要求检查某个 Skill 是否安全、做安装前静态审计时。
user-invocable: true
metadata:
  author: 知白守黑1024
  repo: https://github.com/odin1024/zhibai-skills
  license: MIT
  dsh_version: compatible
  skills_count: 10
---

# 知白守黑 · Agent Skills 合集索引

**这是一个路由入口，不是能力本体。** 每个技能的完整工作流、判定规则、输出模板和能力边界都在
`skills/<slug>/SKILL.md` 里。直接在本层凭常识作答，会丢掉那些规则，也可能产生越界结论。

---

## 一、路由规则（每次先做，不要跳过）

1. **判意图**：把用户的话归到下面索引表里的某一类；拿不准就问一句，不要猜。
2. **读子技能**：用文件读取打开对应的 `skills/<slug>/SKILL.md`，必要时再读它的 `references/`。
3. **照着执行**：严格按子技能里写的工作流、判定规则、输出格式走，包括它明确写出的「不做的事」。
4. **跨技能串联**：一个请求涉及多个技能时，按索引表的顺序依次执行，并在开头告诉用户会分几步。

---

## 二、技能索引

| 用户需求 | slug | 入口文件 |
|---|---|---|
| 招标文件技术参数逐条做响应表、判正负偏离、查 ★ 条款废标风险 | `bid-param-response` | `skills/bid-param-response/SKILL.md` |
| 按招标/验收要求生成测试大纲、测试项矩阵、六要素用例 | `bid-test-outline` | `skills/bid-test-outline/SKILL.md` |
| 对着目标岗位 JD 给简历打分、逐条改写、查 ATS 关键词缺口 | `resume-checkup` | `skills/resume-checkup/SKILL.md` |
| 贴来可疑短信、聊天记录、链接、电话，判断是不是骗局并给止损动作 | `fangpian-canmou` | `skills/fangpian-canmou/SKILL.md` |
| 子女视角帮父母设手机防线、做家庭演练、处理「说了不听」 | `bama-fangpian` | `skills/bama-fangpian/SKILL.md` |
| 单位、社区、学校、银行网点做反诈宣讲稿、短视频脚本、测试题 | `fanzha-sucai` | `skills/fanzha-sucai/SKILL.md` |
| 安装第三方 Skill 之前做离线静态审计、查提示词注入/密钥/危险命令 | `skill-supply-chain-audit` | `skills/skill-supply-chain-audit/SKILL.md` |
| 按评分办法倒推章节、写投标技术方案正文 | `bid-tech-proposal` | `skills/bid-tech-proposal/SKILL.md` |
| 从选题验证到上架后数据复核，做自己的 Skill | `skill-dev-workshop` | `skills/skill-dev-workshop/SKILL.md` |
| 一问一追地模拟面试、给逐答评分与复盘报告 | `interview-mock-chain` | `skills/interview-mock-chain/SKILL.md` |

> 上表以仓库 `skills/` 目录实际内容为准；新增技能会同步补进本表。

---

## 三、典型串联

- **投一条标**：`bid-param-response`（把参数响应清楚）→ `bid-test-outline`（把验收测什么写清楚）。两者共用同一份招标技术要求，别各写一套口径。
- **找工作**：`resume-checkup`（先把简历改到能过筛）→ 再准备面试；不要在简历里虚构经历。
- **全家防骗**：`fangpian-canmou`（当下这条信息怎么处理）→ `bama-fangpian`（把防线装到父母手机上）→ `fanzha-sucai`（要对外宣讲时再用）。

---

## 四、能力边界（合集层）

- 不在本层编造判定结果、事实数据、法律定性或政策口径；结论必须来自子技能的工作流。
- 子技能明确写了「不做」的事，本层也不做：不代写经历、不把「待确认」改成「无偏离」、不承诺追回资金、不把静态扫描当成安全保证。
- 本合集不联网、不执行子技能以外的代码、不修改用户的原始文件。

---

## 五、安装

```bash
git clone https://github.com/odin1024/zhibai-skills.git
cp -r zhibai-skills/skills/<slug> ~/.claude/skills/
```

根目录这份 `SKILL.md` 可作为合集索引整体安装；只要一个能力时，直接复制对应子目录即可，
子技能之间互不依赖。仓库打了 `dsh-plugin` topic，也支持在 DeepSeek Harness / SkillHub 插件页按仓库名安装。
