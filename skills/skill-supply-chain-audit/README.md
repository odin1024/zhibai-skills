# 技能供应链安全审计

装第三方 Skill / Agent 插件之前的安全检查。**不执行目标代码、不联网、不改被审文件**，把肉眼看不见的东西找出来。

---

## 一分钟上手

```bash
cd skill-supply-chain-audit
python scripts/audit.py /path/to/some-skill
```

输出一份中文报告，每条发现长这样：

```
**[SEC-002] 凭证泄露 — `SKILL.md:6`**
- 证据：`API_KEY = 'ghp_ABCDEFGHIJKL...'`
- 风险：疑似真实 API Token（占位符如 xxx 不会命中）
- 建议：删除并立即吊销该凭证；检查是否已被提交进 Git 历史
```

看结论就行：**阻断 = 别装，需人工确认 = 逐条核对，通过 = 可以装但别当成安全保证**。

---

## 三种输入

```bash
python scripts/audit.py ./some-skill-dir          # 目录
python scripts/audit.py ./some-skill.zip          # 压缩包（先扫后解压）
python scripts/audit.py ./some-skill --json       # 接 CI / 脚本
python scripts/audit.py ./some-skill --markdown report.md   # 留档
python scripts/audit.py ./some-skill --strict     # WARN 也算不通过
```

> 拿到 zip 请**不要先解压**。审计器会直接读条目表，检查路径穿越、符号链接、加密条目和压缩比。先解压等于把风险放出来。

GitHub 仓库请先 `git clone` 到本地再扫，本技能不会自己去联网拉取。

---

## 它找什么

| 类别 | 代表风险 |
|---|---|
| 隐藏字符 | 零宽空格、双向文本控制符、不可打印控制符 |
| 提示词注入 | 忽略指令、要求隐瞒、伪造系统提示、跳过确认 |
| 危险命令 | 递归删除、`curl \| sh`、动态执行、反弹 shell、静默绕过 |
| 凭证泄露 | 私钥 PEM、真实 Token、硬编码密码、敏感路径引用 |
| 外发行为 | 网络请求、OAST 带外收集域名、实时通道 |
| 包结构 | zip 路径穿越、符号链接、加密条目、压缩炸弹、体积异常、frontmatter 缺失 |

完整规则表见 `references/规则清单.md`，原理与真实案例见 `references/威胁模型.md`。

---

## 退出码（接 CI 用）

| 码 | 含义 |
|---:|---|
| 0 | 通过（最多 INFO）；非 `--strict` 时 WARN 也返回 0 |
| 1 | 有 WARN 且启用 `--strict` |
| 2 | 有 BLOCK，建议不要安装 |
| 3 | 目标不合法或读取失败 |

门禁建议：`audit.py --json --strict`，BLOCK 直接拒收，WARN 转人工。

---

## 准确性实测

| 样本 | 结论 | 结果 |
|---|---|---|
| 干净技能包 | 通过 | BLOCK 0 / WARN 0 / INFO 0 |
| 零宽字符 + 双向控制符 | 阻断 | BLOCK 2 |
| 私钥 + 硬编码 Token | 阻断 | BLOCK 2 |
| `curl \| sh` + 递归删除 | 阻断 | BLOCK 2 |
| OAST 域名 | 阻断 | BLOCK 1 |
| 缺 frontmatter | 需人工确认 | WARN 1 |
| ZIP 路径穿越 | 阻断 | BLOCK 1 |

`python scripts/selftest.py` → **7/7 通过**。

另外用本项目自己的六个技能（含 18 KB 级 SKILL.md 与六份深度知识库）做过误报测试：全部「通过」，BLOCK 0 / WARN 0，仅各有一条外链 INFO。

---

## 误报怎么办

安全类、教学类技能正文里必然引用危险词，规则会命中。这是设计使然，不是 bug。

按这个顺序核对：是不是反模式示例？是不是占位符？是不是在讲防御原理？外链是不是可信域名？逐条写出依据即可降级，**但不要一键全降级**。

私钥、真实 Token、双向控制符、OAST 域名、zip 结构攻击这五类，正常文档里没有正当用途，**不能自动降级**。

---

## 它不做什么

静态扫描看不到：运行时才拼接出来的恶意逻辑、二进制文件行为、依赖包投毒、联网后才触发的下载、诱导用户手动执行的社会工程、以及「看起来完全正常但指令本身有害」的内容。

**它不是安全保证，只是安装前的第一道筛子。** 装完仍建议看一眼会话里的实际动作。

---

## 目录

```
skill-supply-chain-audit/
├── SKILL.md                      主入口（给 Agent 读的工作流）
├── README.md                     本文件
├── FAQ.md                        高频问题
├── TROUBLESHOOTING.md            异常处理
├── references/
│   ├── 威胁模型.md               六类威胁的原理、案例、绕过手法、人工复核清单
│   └── 规则清单.md               规则 ID、正则、级别、阈值、扩展方法
└── scripts/
    ├── audit.py                  审计器（纯标准库）
    ├── selftest.py               7 组构造样本自检
    └── verify.py                 技能包结构与 frontmatter 自检
```

---

## 自检

```bash
python scripts/selftest.py
python scripts/verify.py
```

作者：知白守黑1024 · MIT
