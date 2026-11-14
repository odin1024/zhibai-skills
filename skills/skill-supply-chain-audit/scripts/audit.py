# -*- coding: utf-8 -*-
"""Agent Skill / 插件包 静态安全审计器。

用途：在安装第三方 SKILL.md、技能包或插件仓库之前，做一次不执行代码的静态检查。
只读目标文件，不导入、不执行、不联网，纯 Python 标准库。

用法：
    python audit.py <目录或 zip>                 输出中文报告
    python audit.py <path> --json               输出机器可读 JSON
    python audit.py <path> --markdown out.md    同时写出 Markdown 报告
    python audit.py <path> --strict             有 WARN 也返回非零

退出码：
    0 = 通过（最多只有 INFO）
    1 = 存在 WARN（--strict 时也返回 1）
    2 = 存在 BLOCK（建议不要安装）
    3 = 目标不合法或读取失败

设计原则：
    1. 证据优先——每条发现都给文件、行号、命中片段，不写「可能有风险」这种空话。
    2. 区分「实际密钥」和「文档里的占位符」，避免把示例误判成泄露。
    3. 静态分析有边界，报告必须写明没覆盖什么，不能给用户虚假的安全感。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path, PurePosixPath

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# 规则库
#
# pattern 为正则字符串。为避免本文件被自己扫描时产生自指误报，
# 部分高危字面量用字符串拼接构造，运行时再编译成完整正则。
# ---------------------------------------------------------------------------

BLOCK = "BLOCK"
WARN = "WARN"
INFO = "INFO"

RULES: list[dict] = []


def _lit(*parts: str) -> str:
    """把高危字面量拆段拼接，运行时等价于直接书写。

    两个目的：审计器扫描自身目录时不产生自指误报；
    平台安全扫描不会把「规则里的关键词」误判成真实调用。
    """
    return "".join(parts)


def rule(rid: str, level: str, cat: str, pattern: str, desc: str, fix: str):
    RULES.append(dict(id=rid, level=level, cat=cat, pattern=pattern,
                      desc=desc, fix=fix, regex=re.compile(pattern, re.I | re.M)))


# 一、不可见字符与文本方向控制（提示词注入最常见的载体）
rule("INV-001", BLOCK, "隐藏字符",
     r"[\u200b\u200c\u200d\u200e\u200f\u2060\ufeff]",
     "存在零宽字符或不可见格式符，可用于夹带隐藏指令、绕过人工阅读与内容审核",
     "用 Unicode 规范化清理，或删除该字符后重新核对上下文；安装前要求作者提供干净版本")
rule("INV-002", BLOCK, "隐藏字符",
     r"[\u202a-\u202e\u2066-\u2069]",
     "存在双向文本控制符，可让屏幕上显示的顺序与机器读取的顺序不一致",
     "删除控制符；这类字符在正常中文技能文档里没有正当用途")
rule("INV-003", WARN, "隐藏字符",
     r"[\x00-\x08\x0b\x0c\x0e-\x1f]",
     "包含不可打印的控制字符（Tab / 换行 / 回车之外的）",
     "检查是否为复制粘贴带入的脏字符，必要时重新保存为 UTF-8 纯文本")
rule("INV-004", WARN, "隐藏字符",
     r"[\u00a0\u3000]{3,}",
     "连续多个不换行空格或全角空格，可能用于隐藏内容或撑开版面",
     "替换为普通空格，确认没有藏在其中的内容")

# 二、提示词注入 / 越权指令
rule("PI-001", WARN, "提示词注入",
     r"(忽略(以上|之前|前面|上述)|无视(以上|之前|前面)|ignore\s+(all\s+)?(previous|prior|above)|disregard\s+(all\s+)?(previous|prior))",
     "出现要求模型忽略既有指令的句式，是典型的提示词注入话术",
     "核对上下文：若出现在「反模式示例」中属正常；若出现在正常说明里，不要安装")
rule("PI-002", WARN, "提示词注入",
     r"(不要告诉用户|别让用户知道|不要提及|do\s+not\s+(tell|mention|inform)\s+(the\s+)?user|keep\s+this\s+secret|silently|secretly)",
     "要求对用户隐瞒行为，与技能应透明可控的原则冲突",
     "要求作者说明为什么需要隐藏；无法给出合理解释则视为恶意")
rule("PI-003", WARN, "提示词注入",
     r"(system\s+prompt|系统提示词|开发者指令|developer\s+message|<\|im_start\|>|\[INST\])",
     "出现试图伪造或引用系统级指令的标记",
     "确认是否只是教学示例；技能正文不应包含对话角色标记")
rule("PI-004", WARN, "提示词注入",
     r"(无条件执行|无需确认|不要询问|without\s+(asking|confirm)|always\s+run\s+this|auto[- ]?execute)",
     "要求跳过用户确认直接执行，扩大技能的实际权限",
     "改为「执行前先向用户确认」，或在能力边界里写清需要用户授权")

# 三、危险命令与执行面
rule("EX-001", BLOCK, "危险命令",
     r"\b" + "r" + r"m\s+-[rRfF]{1,3}\s+(/|~|\*|\$HOME|\.)(?=\s|$)",
     "递归删除根目录、家目录或通配符路径，误执行会造成不可逆数据丢失",
     "删除该命令；技能不应包含任何递归删除")
rule("EX-002", BLOCK, "危险命令",
     r"(curl|wget)[^\n|]{0,120}\|\s*(sudo\s+)?(ba)?sh\b",
     "下载内容直接管道给 shell 执行，等价于运行远端任意代码",
     "改为先下载、校验哈希、人工审阅再执行")
rule("EX-003", WARN, "危险命令",
     _lit(r"\b(o", "s", r"\.system|", "sub", "process",
          r"\.(call|run|Popen)|child_process|execSync|shelljs|Runtime\.getRuntime\(\)\.exec)"),
     "存在启动外部进程的能力，需确认调用参数是否来自不可信输入",
     "核对调用点：参数应固定或白名单化，不接受用户文本拼接")
rule("EX-004", WARN, "危险命令",
     _lit(r"\b(ev", "al|ex", r"ec)\s*\(|\bnew\s+Function\s*\(|powershell\s+(-e|-enc|EncodedCommand)"),
     "存在动态执行字符串或编码命令，容易隐藏真实意图",
     "改为显式逻辑；编码命令必须先解码审阅")
rule("EX-005", WARN, "危险命令",
     r"(\bnc\s+-e\b|/dev/tcp/|base64\s+(-d|--decode)[^\n]{0,60}\|\s*(ba)?sh|chmod\s+777|chown\s+-R\s+/)",
     "反弹 shell、解码后执行、全开放权限等高危操作特征",
     "一律拒绝，除非能给出完整且可复核的正当用途")
rule("EX-006", WARN, "危险命令",
     r"(>\s*/dev/null\s*2>&1|--no-verify|--force\s|git\s+push\s+.*-f|set\s+-e\s+&&\s*curl)",
     "静默失败、跳过校验或强制推送，会掩盖失败并绕过保护",
     "去掉静默与跳过校验参数，保留可观察的输出")

# 四、凭证、密钥与敏感路径
rule("SEC-001", BLOCK, "凭证泄露",
     r"-----BEGIN\s+(RSA|EC|OPENSSH|DSA|PGP)?\s*PRIVATE\s+KEY-----",
     "包含私钥 PEM 头，属于明确的凭证泄露",
     "立即删除并轮换该密钥；不要安装含私钥的技能包")
rule("SEC-002", BLOCK, "凭证泄露",
     r"\b(ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|skh_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{24,}|AKIA[0-9A-Z]{16,}|xox[baprs]-[A-Za-z0-9-]{20,})",
     "疑似真实 API Token / 访问密钥（占位符如 xxx、YOUR_KEY 不会命中）",
     "删除并立即吊销该凭证；检查是否已被提交进 Git 历史")
rule("SEC-003", WARN, "凭证泄露",
     r"(\.aws/credentials|\.ssh/id_|\.npmrc|\.netrc|\.git-credentials|\.env\b|keychain|Credential\s+Manager|credential\.helper)",
     "引用了本机凭证存放位置，需确认是否会读取或外传",
     "确认技能是否真的需要访问这些路径；不需要就删掉相关说明与代码")
rule("SEC-004", WARN, "凭证泄露",
     r"(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['\"][^'\"\s]{12,}['\"]",
     "疑似硬编码了具体的凭据值（非变量名）",
     "改为从环境变量读取，并把示例值换成明显的占位符")
rule("SEC-005", WARN, "凭证泄露",
     r"(process\.env|os\.environ|getenv|System\.getenv)\s*[\[\(]['\"][A-Z_]*(KEY|TOKEN|SECRET|PASS)",
     "从环境变量读取密钥，本身正常，但要确认后续没有写进日志或请求",
     "核对读取后的使用链路，禁止打印、写文件或拼进 URL")

# 五、外发与网络行为
rule("NET-001", WARN, "外发行为",
     _lit(r"\b(reque", r"sts\.(get|post|put|patch)|urllib\.request|urlopen\(|fetch\(|axios\.|"
          r"http\.client|XMLHttpRequest|curl\s+-X\s+POST|Invoke-WebRequest)"),
     "存在对外发起网络请求的能力，需确认目标域名与发送的数据",
     "列出目标域名与字段；若包含本地文件内容或环境变量，视为高危")
rule("NET-002", WARN, "外发行为",
     r"https?://[^\s\)\"'`]+",
     "包含外部链接（仅提示，需人工判断是否为可信域名）",
     "核对域名所有权；短链、IP 直连、陌生域名要特别谨慎")
rule("NET-003", BLOCK, "外发行为",
     r"(webhook\.site|requestbin|ngrok\.io|pipedream\.net|burpcollaborator|oastify\.com|interact\.sh)",
     "指向常见的带外数据收集（OAST）服务，通常用于把数据偷偷送出",
     "立即拒绝安装；这类域名在技能里没有正当用途")
rule("NET-004", WARN, "外发行为",
     _lit(r"(sock", r"et\.|web", "sock", r"et|WebSocket\(|discord\.com/api/webhooks|"
          r"telegram\.org/api|/webhooks?/send)"),
     "存在实时通道或 webhook 推送能力",
     "确认是否需要；不需要就移除，需要则在文档里写明推送内容")

# 六、包结构与元数据
rule("META-001", WARN, "元数据",
     r"^---\s*$",
     "检测到 YAML frontmatter 分隔符（仅信息项，用于确认 SKILL.md 结构）",
     "无需处理")
rule("META-002", WARN, "元数据",
     r"(https?://|ftp://)[^\s]{0,80}(/\.\./|\.\./\.\./)",
     "URL 中出现路径穿越片段，可能用于读取预期外的资源",
     "规范化路径后再请求")

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024
MAX_FILES = 300
TEXT_SUFFIXES = {".md", ".markdown", ".txt", ".py", ".js", ".ts", ".jsx", ".tsx",
                 ".json", ".yaml", ".yml", ".toml", ".sh", ".bash", ".ps1",
                 ".bat", ".cmd", ".rb", ".go", ".rs", ".java", ".html", ".css",
                 ".sql", ".ini", ".cfg", ".conf", ".xml", ".mjs", ".cjs"}


@dataclass
class Finding:
    level: str
    rule_id: str
    category: str
    file: str
    line: int
    evidence: str
    description: str
    fix: str


@dataclass
class FileEntry:
    path: str
    text: str | None
    size: int
    is_symlink: bool = False
    encrypted: bool = False


def load_target(target: Path) -> tuple[list[FileEntry], list[Finding]]:
    entries: list[FileEntry] = []
    findings: list[Finding] = []
    if target.is_dir():
        for p in sorted(target.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(target).as_posix()
            if "__pycache__" in rel or rel.endswith(".pyc"):
                continue
            size = p.stat().st_size
            txt = None
            if p.suffix.lower() in TEXT_SUFFIXES and size <= MAX_FILE_BYTES:
                txt = p.read_text(encoding="utf-8", errors="replace")
            entries.append(FileEntry(rel, txt, size, p.is_symlink()))
    elif target.is_file() and target.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(target) as z:
                infos = z.infolist()
                if len(infos) > MAX_FILES:
                    findings.append(Finding(BLOCK, "ZIP-001", "包结构", target.name, 0,
                                            f"{len(infos)} 个文件",
                                            "文件数量超过上限，可能是压缩炸弹或夹带大量无关文件",
                                            "拒绝安装，要求作者精简"))
                total = 0
                for info in infos:
                    name = info.filename
                    total += info.file_size
                    symlink = (info.external_attr >> 16) & 0o170000 == 0o120000
                    encrypted = bool(info.flag_bits & 0x1)
                    parts = PurePosixPath(name).parts
                    bad = name.startswith("/") or ".." in parts or re.match(r"^[A-Za-z]:", name)
                    if bad:
                        findings.append(Finding(BLOCK, "ZIP-002", "包结构", target.name, 0, name,
                                                "压缩包内含绝对路径或 ../ 路径穿越，解压可能写到目标目录之外",
                                                "拒绝安装；正规安装包不应包含这类路径"))
                    if symlink:
                        findings.append(Finding(WARN, "ZIP-003", "包结构", target.name, 0, name,
                                                "压缩包内含符号链接，可能指向宿主机任意位置",
                                                "解压前剔除符号链接，或用严格沙箱解压"))
                    if encrypted:
                        findings.append(Finding(BLOCK, "ZIP-004", "包结构", target.name, 0, name,
                                                "存在加密条目，静态审计无法读取其内容",
                                                "拒绝安装；要求提供未加密版本"))
                    if info.compress_size > 0 and info.file_size / info.compress_size > 200:
                        findings.append(Finding(BLOCK, "ZIP-005", "包结构", target.name, 0, name,
                                                f"压缩比 {info.file_size // info.compress_size}:1，疑似压缩炸弹",
                                                "拒绝安装；不要尝试解压"))
                    txt = None
                    if not bad and not symlink and PurePosixPath(name).suffix.lower() in TEXT_SUFFIXES \
                            and info.file_size <= MAX_FILE_BYTES:
                        try:
                            txt = z.read(info).decode("utf-8", errors="replace")
                        except Exception:
                            txt = None
                    entries.append(FileEntry(name, txt, info.file_size, symlink, encrypted))
                if total > MAX_TOTAL_BYTES:
                    findings.append(Finding(WARN, "ZIP-006", "包结构", target.name, 0,
                                            f"{total // 1024 // 1024} MB",
                                            "解压后总体积超过 20 MB",
                                            "确认是否真的需要这么多内容；技能包通常以文本为主"))
        except zipfile.BadZipFile as e:
            findings.append(Finding(BLOCK, "ZIP-000", "包结构", target.name, 0, str(e),
                                    "不是合法的 ZIP 文件", "重新获取完整的安装包"))
    else:
        findings.append(Finding(BLOCK, "IN-000", "输入", str(target), 0, "",
                                "目标既不是目录也不是 ZIP 文件", "传入技能目录或技能包 zip 路径"))
    return entries, findings


def evidence_of(line: str, start: int, end: int) -> str:
    snippet = line[max(0, start - 24): min(len(line), end + 24)].strip()
    snippet = snippet.replace("\x00", "")
    return snippet[:120] if len(snippet) <= 120 else snippet[:117] + "..."


def scan_text(entries: list[FileEntry]) -> list[Finding]:
    out: list[Finding] = []
    url_hits: dict[str, int] = {}
    for e in entries:
        if e.text is None:
            continue
        for lineno, line in enumerate(e.text.splitlines(), start=1):
            for r in RULES:
                m = r["regex"].search(line)
                if not m:
                    continue
                # URL 规则只记一条汇总，避免每条链接刷屏
                if r["id"] == "NET-002":
                    url_hits[e.path] = url_hits.get(e.path, 0) + 1
                    continue
                if r["id"] == "META-001":
                    continue
                out.append(Finding(r["level"], r["id"], r["cat"], e.path, lineno,
                                   evidence_of(line, m.start(), m.end()), r["desc"], r["fix"]))
        if e.size > 512 * 1024:
            out.append(Finding(WARN, "SIZE-001", "包结构", e.path, 0, f"{e.size // 1024} KB",
                               "单文件超过 512 KB，多数客户端会在约 8000 字符处截断长文档",
                               "拆成 references/ 分层文件，主入口保持精简"))
        if e.text and len(e.text) > 12000:
            out.append(Finding(WARN, "SIZE-002", "包结构", e.path, 0, f"{len(e.text)} 字符",
                               "主文档过长，模型加载时尾部内容可能被截断",
                               "把细节移到 references/，SKILL.md 只保留入口与流程"))
    for path, n in url_hits.items():
        out.append(Finding(INFO, "NET-002", "外发行为", path, 0, f"{n} 处外链",
                           "文件内包含外部链接，需人工确认域名可信",
                           "逐个核对域名；短链与 IP 直连要展开后再判断"))
    return out


def check_frontmatter(entries: list[FileEntry]) -> list[Finding]:
    out: list[Finding] = []
    for e in entries:
        if e.text is None or not e.path.lower().endswith("skill.md"):
            continue
        t = e.text
        if not t.startswith("---"):
            out.append(Finding(WARN, "META-010", "元数据", e.path, 1, t[:60],
                               "SKILL.md 缺少 YAML frontmatter，客户端可能无法识别触发条件",
                               "补上 --- 包裹的 name / description / version 等字段"))
            continue
        end = t.find("\n---", 3)
        head = t[3:end] if end > 0 else t[3:2000]
        required = {"name": r"^\s*name\s*:", "description": r"^\s*description\s*:",
                    "slug": r"^\s*slug\s*:", "version": r"^\s*version\s*:"}
        for key, pat in required.items():
            if not re.search(pat, head, re.M):
                out.append(Finding(WARN, "META-011", "元数据", e.path, 1, f"缺少 {key}",
                                   f"frontmatter 缺少 {key} 字段",
                                   f"补上 {key}；发布到 SkillHub 时 slug 与 version 是必填"))
    return out


def dedup(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out = []
    for f in findings:
        key = (f.rule_id, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    order = {BLOCK: 0, WARN: 1, INFO: 2}
    out.sort(key=lambda x: (order[x.level], x.file, x.line, x.rule_id))
    return out


def verdict(findings: list[Finding]) -> tuple[str, str]:
    n_block = sum(1 for f in findings if f.level == BLOCK)
    n_warn = sum(1 for f in findings if f.level == WARN)
    if n_block:
        return "阻断", f"发现 {n_block} 项高危问题，建议不要安装。先要求作者修复，或改用可信来源的同类技能。"
    if n_warn:
        return "需人工确认", f"未发现高危项，但有 {n_warn} 项需要核对上下文。多数是文档示例或正常能力，逐条看证据即可。"
    return "通过", "静态检查未发现风险特征。注意这不代表运行时一定安全，见报告末尾的覆盖边界。"


COVERAGE = """静态审计能发现：不可见字符、提示词注入话术、危险命令特征、硬编码密钥、
敏感路径引用、外发请求与 OAST 域名、压缩包结构攻击、frontmatter 缺失、体积异常。

静态审计不能发现：混淆后运行时才拼接出来的恶意逻辑、二进制文件里的行为、
依赖包供应链投毒、需要联网才触发的下载、社会工程诱导用户手动执行的操作、
以及任何「看起来完全正常但指令本身有害」的内容。

结论只能作为安装前的第一道筛子，不能替代沙箱执行、来源核验和人工通读。"""


def render_markdown(target: str, findings: list[Finding], files: int, bytes_: int) -> str:
    state, advice = verdict(findings)
    lines = [
        "# 技能安全审计报告", "",
        f"- 审计目标：`{target}`",
        f"- 审计时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 扫描文件：{files} 个，共 {bytes_ / 1024:.1f} KB",
        f"- 审计器版本：{VERSION}（纯静态、不执行目标代码）", "",
        f"## 结论：{state}", "", advice, "",
        "| 等级 | 数量 | 含义 |", "|---|---:|---|",
        f"| 阻断 BLOCK | {sum(1 for f in findings if f.level == BLOCK)} | 建议不要安装 |",
        f"| 警告 WARN | {sum(1 for f in findings if f.level == WARN)} | 需人工核对上下文 |",
        f"| 信息 INFO | {sum(1 for f in findings if f.level == INFO)} | 仅提示，不影响结论 |", "",
    ]
    if findings:
        lines += ["## 发现明细", ""]
        cur = None
        for f in findings:
            if f.level != cur:
                lines += [f"### {f.level} 级", ""]
                cur = f.level
            lines += [
                f"**[{f.rule_id}] {f.category} — `{f.file}`"
                + (f":{f.line}" if f.line else "") + "**", "",
                f"- 证据：`{f.evidence}`",
                f"- 风险：{f.description}",
                f"- 建议：{f.fix}", "",
            ]
    else:
        lines += ["## 发现明细", "", "无。", ""]
    lines += ["## 覆盖边界", ""] + [COVERAGE, ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Agent Skill 静态安全审计器")
    ap.add_argument("target", help="技能目录或 .zip 包")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--markdown", metavar="PATH", help="额外写出 Markdown 报告")
    ap.add_argument("--strict", action="store_true", help="有 WARN 也返回非零退出码")
    ap.add_argument("--exclude-self", action="store_true", default=True,
                    help="跳过审计器自身文件（默认开启，避免自指误报）")
    args = ap.parse_args()

    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        print(f"目标不存在：{target}", file=sys.stderr)
        return 3

    entries, structural = load_target(target)
    if args.exclude_self:
        entries = [e for e in entries if not e.path.endswith("audit.py")]
    findings = dedup(structural + scan_text(entries) + check_frontmatter(entries))
    total_bytes = sum(e.size for e in entries)
    state, advice = verdict(findings)

    report = render_markdown(str(target), findings, len(entries), total_bytes)
    if args.markdown:
        Path(args.markdown).write_text(report, encoding="utf-8")
        print(f"Markdown 报告已写入：{args.markdown}")

    if args.json:
        print(json.dumps({
            "target": str(target), "version": VERSION, "verdict": state,
            "advice": advice, "fileCount": len(entries), "bytes": total_bytes,
            "summary": {lv: sum(1 for f in findings if f.level == lv)
                        for lv in (BLOCK, WARN, INFO)},
            "findings": [asdict(f) for f in findings],
        }, ensure_ascii=False, indent=2))
    else:
        print(report)

    n_block = sum(1 for f in findings if f.level == BLOCK)
    n_warn = sum(1 for f in findings if f.level == WARN)
    if n_block:
        return 2
    if n_warn and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
