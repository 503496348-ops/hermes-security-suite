# -*- coding: utf-8 -*-
"""
奇点造物-Genesisix · Agent Snooping Detector
AtomCollide-智械工坊 · 2026

融合自 NVIDIA SkillSpector v2.3.1 (Apache 2.0) 的 Agent Snooping 检测能力。

检测能力:
  - AS1: Agent配置目录访问检测 (.claude/, .codex/, .gemini/)
  - AS2: MCP配置文件访问检测 (mcp.json, mcp_config.json)
  - AS3: 技能枚举/窥探检测 (枚举其他已安装技能)

Framework: OWASP LLMT09 (Misinformation), ASI-SR-003 (Least Knowledge)

Usage:
    from modules.agent_snooping import scan_agent_snooping
    findings = scan_agent_snooping("/path/to/skill")
"""

import re
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class AgentSnoopingFinding:
    """Agent Snooping 发现"""
    rule_id: str
    category: str
    description: str
    severity: str
    confidence: float
    file_path: str
    line_number: int
    matched_text: str
    details: str
    mitigation: str


# ── AS1: Agent Config Directory Access ──
# 匹配尝试读取Agent配置目录的代码/指令

AS1_PATTERNS = [
    # 直接文件系统访问 .claude/, .codex/, .gemini/ 目录
    (r"open\s*\(\s*['\"]?\.(?:claude|codex|gemini|continue)/", 0.9),
    (r"(?:Path|pathlib\.Path)\s*\(\s*['\"]?\.(?:claude|codex|gemini|continue)/", 0.9),
    (r"os\.path\.(?:join|exists|isfile)\s*\(\s*['\"]?\.(?:claude|codex|gemini|continue)", 0.85),
    (
        r"(?:read|load|open|access|fetch)\s+(?:the\s+)?(?:agent|claude|codex|gemini)\s+(?:config|configuration|settings?)\s+(?:from|at|in)\s+~?/?\.(?:claude|codex|gemini)",
        0.9,
    ),
    # Shell命令针对配置目录
    (r"(?:cat|less|head|tail|grep|find)\s+[^|&;\n]*~?/?\.(claude|codex|gemini)/", 0.85),
    # 主目录配置路径
    (
        r"~?/\.(?:claude|codex|gemini|continue)/(?:config|settings?|preferences?|credentials?)(?:\.(?:json|yaml|yml|toml))?",
        0.9,
    ),
    # 通用 "agent config" 窥探指令
    (
        r"(?:read|access|inspect|examine|retrieve)\s+(?:the\s+)?(?:agent|assistant)\s+(?:config(?:uration)?|settings?|preferences?)\s+(?:file|directory|folder)",
        0.8,
    ),
]

# ── AS2: MCP Config Access ──
# 匹配专门针对MCP服务器配置的代码/指令

AS2_PATTERNS = [
    # 直接访问 mcp.json 文件
    (r"open\s*\(\s*['\"][^'\"]*mcp(?:_config)?\.json['\"]", 0.95),
    (r"(?:Path|pathlib\.Path)\s*\(\s*['\"][^'\"]*mcp(?:_config)?\.json['\"]", 0.9),
    (r"(?:cat|less|head|grep)\s+[^|&;\n]*mcp(?:_config)?\.json", 0.9),
    # 引用MCP配置的指令
    (
        r"(?:read|access|load|inspect)\s+(?:the\s+)?mcp(?:\.json|_config)?\s+(?:file|config(?:uration)?|settings?)",
        0.9,
    ),
    (r"\.(?:claude|codex|gemini)/mcp(?:_config)?\.json", 0.95),
    # 列出MCP服务器
    (
        r"(?:list|enumerate|discover)\s+(?:all\s+)?(?:available\s+)?mcp\s+(?:servers?|tools?|services?)",
        0.8,
    ),
    # 从配置访问MCP服务器URL或API密钥
    (r"mcp(?:_config)?\.json.*?(?:api_?key|token|secret|url|endpoint)", 0.9),
]

# ── AS3: Skill Enumeration / Snooping ──
# 匹配枚举或读取其他已安装技能的代码/指令

AS3_PATTERNS = [
    # 列出技能目录
    (
        r"(?:os\.listdir|os\.scandir|glob\.glob|Path\.iterdir)\s*\([^)]*\.(?:claude|codex|gemini)/skills?",
        0.9,
    ),
    (r"(?:ls|find|dir)\s+[^|&;\n]*\.(?:claude|codex|gemini)/skills?", 0.85),
    # 读取其他技能的SKILL.md文件
    (r"open\s*\(\s*['\"][^'\"]*SKILL\.md['\"].*?\bother\b", 0.85),
    (
        r"(?:read|access|inspect|enumerate)\s+(?:all\s+)?(?:installed|available|other)\s+skills?(?:\s+in\s+(?:the\s+)?(?:skills?|agent)\s+(?:directory|folder))?",
        0.85,
    ),
    # 发现其他技能的指令
    (
        r"(?:list|discover|find|enumerate|identify)\s+(?:all\s+)?(?:other|installed|available)\s+(?:skills?|agents?|tools?)\s+(?:in\s+)?(?:the\s+)?(?:\.(?:claude|codex|gemini)|\$HOME)",
        0.85,
    ),
    # 访问 skills/CURRENT 或相邻技能目录
    (r"skills?/(?:(?!CURRENT)[A-Z][A-Za-z0-9_-]+)/SKILL\.md", 0.8),
    # 读取其他Agent的工具清单
    (
        r"(?:read|access|load)\s+(?:the\s+)?(?:SKILL|skill)\.md\s+(?:file\s+)?(?:of|from|for)\s+(?:another|other|different|all)\s+(?:skill|agent|tool)",
        0.9,
    ),
]


def _get_line_number(content: str, pos: int) -> int:
    """获取内容中某个位置的行号"""
    return content[:pos].count('\n') + 1


def _get_context(content: str, pos: int, context_lines: int = 2) -> str:
    """获取匹配位置周围的上下文"""
    lines = content.split('\n')
    line_num = _get_line_number(content, pos)
    start = max(0, line_num - context_lines - 1)
    end = min(len(lines), line_num + context_lines)
    return '\n'.join(lines[start:end])


def scan_agent_snooping(project_path: str) -> List[AgentSnoopingFinding]:
    """
    扫描项目中的Agent Snooping行为。
    
    Args:
        project_path: 项目路径
        
    Returns:
        发现的Agent Snooping行为列表
    """
    findings = []
    path = Path(project_path)
    
    if not path.exists():
        return findings
    
    # 扫描所有文本文件
    text_extensions = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.md', '.txt', '.json', 
        '.yaml', '.yml', '.toml', '.cfg', '.ini', '.sh', '.bash',
        '.env', '.env.example', '.gitignore', '.dockerignore'
    }
    
    for file_path in path.rglob('*'):
        if not file_path.is_file():
            continue
        
        # 跳过二进制文件和隐藏目录
        if any(part.startswith('.') for part in file_path.parts):
            continue
        
        suffix = file_path.suffix.lower()
        if suffix not in text_extensions:
            continue
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        
        relative_path = str(file_path.relative_to(path))
        
        # AS1: Agent Config Directory Access
        for pattern, confidence in AS1_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_num = _get_line_number(content, match.start())
                findings.append(AgentSnoopingFinding(
                    rule_id="AS1",
                    category="Agent Snooping",
                    description="Agent配置目录访问",
                    severity="HIGH",
                    confidence=confidence,
                    file_path=relative_path,
                    line_number=line_num,
                    matched_text=match.group(0)[:200],
                    details=f"检测到对Agent配置目录的访问: {match.group(0)[:100]}",
                    mitigation="检查是否有正当理由访问Agent配置目录，否则移除相关代码"
                ))
        
        # AS2: MCP Config Access
        for pattern, confidence in AS2_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.IGNORECASE):
                line_num = _get_line_number(content, match.start())
                findings.append(AgentSnoopingFinding(
                    rule_id="AS2",
                    category="Agent Snooping",
                    description="MCP配置文件访问",
                    severity="HIGH",
                    confidence=confidence,
                    file_path=relative_path,
                    line_number=line_num,
                    matched_text=match.group(0)[:200],
                    details=f"检测到对MCP配置文件的访问: {match.group(0)[:100]}",
                    mitigation="检查是否有正当理由访问MCP配置，否则移除相关代码"
                ))
        
        # AS3: Skill Enumeration / Snooping
        for pattern, confidence in AS3_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_num = _get_line_number(content, match.start())
                findings.append(AgentSnoopingFinding(
                    rule_id="AS3",
                    category="Agent Snooping",
                    description="技能枚举/窥探",
                    severity="HIGH",
                    confidence=confidence,
                    file_path=relative_path,
                    line_number=line_num,
                    matched_text=match.group(0)[:200],
                    details=f"检测到对其他技能的枚举/窥探: {match.group(0)[:100]}",
                    mitigation="检查是否有正当理由枚举其他技能，否则移除相关代码"
                ))
    
    return findings


def scan_skill_directory(skill_path: str) -> List[AgentSnoopingFinding]:
    """
    扫描单个技能目录（兼容接口）。
    
    Args:
        skill_path: 技能目录路径
        
    Returns:
        发现的Agent Snooping行为列表
    """
    return scan_agent_snooping(skill_path)


# ── Self-test ──

if __name__ == "__main__":
    import tempfile
    import os
    
    # 创建测试文件
    test_cases = [
        # AS1: Agent config access
        ("test_as1.py", '''
import os
config_path = os.path.expanduser("~/.claude/config.json")
with open(config_path) as f:
    config = json.load(f)
'''),
        # AS2: MCP config access
        ("test_as2.py", '''
mcp_config = Path("~/.codex/mcp.json")
servers = json.loads(mcp_config.read_text())
'''),
        # AS3: Skill enumeration
        ("test_as3.py", '''
skills_dir = Path("~/.claude/skills")
for skill in skills_dir.iterdir():
    if skill.is_dir():
        print(skill.name)
'''),
    ]
    
    print("🔍 Agent Snooping Detector 自测")
    print("=" * 50)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        for filename, content in test_cases:
            filepath = Path(tmpdir) / filename
            filepath.write_text(content)
        
        findings = scan_agent_snooping(tmpdir)
        
        if findings:
            print(f"\n✅ 检测到 {len(findings)} 个Agent Snooping行为:")
            for f in findings:
                print(f"  [{f.rule_id}] {f.description}")
                print(f"    文件: {f.file_path}:{f.line_number}")
                print(f"    匹配: {f.matched_text[:80]}...")
                print(f"    置信度: {f.confidence}")
                print()
        else:
            print("❌ 未检测到Agent Snooping行为")
    
    print("\n✅ 自测完成")
