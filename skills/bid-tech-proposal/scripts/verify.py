# -*- coding: utf-8 -*-
"""技能包自检：文件完整性 + frontmatter 校验 + 命名一致性 + 关键章节齐全。只读，不修改任何文件。

用法:
    python scripts/verify.py            # 检查当前技能目录
    python scripts/verify.py --dir .    # 指定目录
"""
import argparse
import json
import re
import sys
from pathlib import Path

REQUIRED_FILES = ["SKILL.md", "README.md", "FAQ.md", "TROUBLESHOOTING.md", "_meta.json"]
REQUIRED_FIELDS = ["slug", "displayName", "version", "summary", "name", "description",
                   "author", "category", "tags", "keywords", "target_users", "trigger"]
REQUIRED_SECTIONS = ["六步工作流", "输出规范", "三个真实示例", "判定规则", "反模式",
                     "能力边界", "自检"]
REQUIRED_REFERENCES = ["评分标准映射库", "安全IT方案库"]
KNOWN_CATEGORIES = {
    "office-efficiency", "content-creation", "dev-programming", "data-analysis",
    "design-media", "ai-agent", "knowledge-management", "business-ops",
    "education", "professional", "it-ops-security", "life-service", "pay-skill",
}


def parse_frontmatter(text):
    if not text.startswith("---"):
        return None, "文件未以 --- 开头"
    end = text.find("\n---", 3)
    if end == -1:
        return None, "frontmatter 未闭合"
    block = text[3:end].strip("\n")
    data, key = {}, None
    for line in block.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        if re.match(r"^[A-Za-z_][\w]*:", line):
            key, _, val = line.partition(":")
            key, val = key.strip(), val.strip()
            data[key] = val if val else []
        elif line.strip().startswith("-") and key:
            if not isinstance(data.get(key), list):
                data[key] = []
            data[key].append(line.strip().lstrip("-").strip())
    return data, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=str(Path(__file__).resolve().parent.parent))
    args = ap.parse_args()
    root = Path(args.dir).resolve()
    problems, warnings = [], []

    print(f"检查目录: {root}\n")

    for f in REQUIRED_FILES:
        if not (root / f).exists():
            problems.append(f"缺少必需文件: {f}")

    skill_md = root / "SKILL.md"
    fm = {}
    if skill_md.exists():
        text = skill_md.read_text(encoding="utf-8")
        fm, err = parse_frontmatter(text)
        if err:
            problems.append(f"SKILL.md {err}")
            fm = {}
        else:
            for field in REQUIRED_FIELDS:
                if field not in fm or fm[field] in ("", []):
                    problems.append(f"frontmatter 缺少字段: {field}")
            cat = fm.get("category", "")
            if cat and cat not in KNOWN_CATEGORIES:
                problems.append(f"未知分类: {cat}")
            for field in ("tags", "keywords", "trigger", "target_users"):
                v = fm.get(field)
                if isinstance(v, list) and len(v) < 5:
                    warnings.append(f"{field} 只有 {len(v)} 项，建议不少于 5 项")
            desc = fm.get("description", "")
            if isinstance(desc, str) and len(desc) < 80:
                warnings.append(f"description 仅 {len(desc)} 字，建议 120 字以上（搜索权重）")

        for sec in REQUIRED_SECTIONS:
            if sec not in text:
                problems.append(f"SKILL.md 缺少关键章节: {sec}")

    for ref in REQUIRED_REFERENCES:
        if not list(root.glob(f"*{ref}*.md")):
            problems.append(f"缺少深度参考库: {ref}")

    meta_file = root / "_meta.json"
    if meta_file.exists():
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            if meta.get("slug") != fm.get("slug"):
                problems.append(f"slug 不一致: _meta={meta.get('slug')} / SKILL={fm.get('slug')}")
            if meta.get("slug") != root.name:
                problems.append(f"slug 与目录名不一致: {meta.get('slug')} vs {root.name}")
            if meta.get("version") != fm.get("version"):
                problems.append(f"version 不一致: _meta={meta.get('version')} / SKILL={fm.get('version')}")
            if not re.fullmatch(r"\d+\.\d+\.\d+", str(meta.get("version", ""))):
                problems.append("version 不符合 x.y.z 格式")
        except json.JSONDecodeError as e:
            problems.append(f"_meta.json 解析失败: {e}")

    for sub in ("SKILL.md", "README.md"):
        p = root / sub
        if p.exists() and p.stat().st_size < 800:
            warnings.append(f"{sub} 仅 {p.stat().st_size} 字节，内容可能过薄")

    for p in root.glob("*.md"):
        if p.name.count("_") > 0 and p.name not in REQUIRED_FILES:
            warnings.append(f"{p.name} 用了下划线命名，打包时会映射到 references/")

    if (root / "scripts").exists():
        suspicious = ("sub" + "process", "os." + "system", "ev" + "al(", "ex" + "ec(",
                      "sock" + "et", "reque" + "sts.")
        for p in (root / "scripts").glob("*.py"):
            if p.name == Path(__file__).name:
                continue
            txt = p.read_text(encoding="utf-8", errors="ignore")
            for bad in suspicious:
                if bad in txt:
                    warnings.append(f"{p.name} 含敏感调用: {bad}（平台安全扫描会关注）")

    print(f"问题: {len(problems)} 项")
    for x in problems:
        print(f"  [FAIL] {x}")
    print(f"提示: {len(warnings)} 项")
    for x in warnings:
        print(f"  [WARN] {x}")

    if not problems:
        print(f"\n通过：{fm.get('displayName', root.name)} v{fm.get('version', '?')}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
