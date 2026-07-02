# -*- coding: utf-8 -*-
"""
奇点造物-Genesisix · Agent Scan Pipeline
AtomCollide-智械工坊 · 2026

面向 Agent 安全审计的三阶段扫描框架。

三阶段流水线:
  1. 信息收集 — 收集目标配置、能力和暴露的端点
  2. 并行漏洞检测 — 每个检测技能一个轻量级worker，并发执行
  3. 漏洞审查 — 合并结果，映射到OWASP ASI，分配最终严重程度

Usage:
    from modules.agent_scan_pipeline import AgentScanPipeline
    pipeline = AgentScanPipeline()
    results = pipeline.scan("/path/to/skill")
"""

import asyncio
import re
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed


class Severity(Enum):
    """严重程度枚举"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ScanFinding:
    """扫描发现"""
    rule_id: str
    category: str
    description: str
    severity: Severity
    confidence: float
    file_path: str
    line_number: int
    matched_text: str
    details: str
    mitigation: str
    owasp_category: str = ""


@dataclass
class ScanStage:
    """扫描阶段"""
    stage_id: str
    name: str
    description: str
    findings: List[ScanFinding] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    duration_ms: float = 0.0


@dataclass
class ScanResult:
    """扫描结果"""
    target_path: str
    stages: List[ScanStage] = field(default_factory=list)
    all_findings: List[ScanFinding] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    total_duration_ms: float = 0.0


# ── OWASP ASI 分类映射 ──

OWASP_ASI_CATEGORIES = {
    "ASI-01": "Unauthorized Access",
    "ASI-02": "Data Leakage",
    "ASI-03": "Prompt Injection",
    "ASI-04": "Tool Abuse",
    "ASI-05": "Agent Snooping",
    "ASI-06": "Supply Chain",
    "ASI-07": "Excessive Agency",
    "ASI-08": "Misconfiguration",
    "ASI-09": "Misinformation",
    "ASI-10": "Memory Poisoning",
}

# 规则ID到OWASP ASI的映射
RULE_TO_OWASP = {
    "AS1": "ASI-05",  # Agent Snooping
    "AS2": "ASI-05",  # Agent Snooping
    "AS3": "ASI-05",  # Agent Snooping
    "SC1": "ASI-06",  # Supply Chain
    "SC2": "ASI-06",  # Supply Chain
    "SC3": "ASI-06",  # Supply Chain
    "SC4": "ASI-06",  # Supply Chain
    "SC5": "ASI-06",  # Supply Chain
    "SC6": "ASI-06",  # Supply Chain
    "E1": "ASI-02",   # Data Leakage
    "E2": "ASI-02",   # Data Leakage
    "TM1": "ASI-04",  # Tool Abuse
    "TM2": "ASI-04",  # Tool Abuse
    "MP1": "ASI-10",  # Memory Poisoning
    "MP2": "ASI-10",  # Memory Poisoning
    "AST1": "ASI-07", # Excessive Agency
    "AST2": "ASI-07", # Excessive Agency
    "TT1": "ASI-02",  # Data Leakage (Taint Tracking)
    "TT2": "ASI-02",  # Data Leakage (Taint Tracking)
    "TT3": "ASI-07",  # Excessive Agency (Taint Tracking)
    "YR1": "ASI-06",  # Supply Chain (YARA)
    "YR2": "ASI-06",  # Supply Chain (YARA)
    "LP1": "ASI-04",  # Tool Abuse (MCP)
    "LP2": "ASI-04",  # Tool Abuse (MCP)
    "TP1": "ASI-04",  # Tool Abuse (MCP)
    "TP2": "ASI-04",  # Tool Abuse (MCP)
    "TP3": "ASI-04",  # Tool Abuse (MCP)
    "TP4": "ASI-04",  # Tool Abuse (MCP)
}


class AgentScanPipeline:
    """
    Agent扫描流水线
    
    三阶段架构:
    1. 信息收集 - 收集目标配置、能力和暴露的端点
    2. 并行漏洞检测 - 每个检测技能一个轻量级worker，并发执行
    3. 漏洞审查 - 合并结果，映射到OWASP ASI，分配最终严重程度
    """
    
    def __init__(self, max_workers: int = 4):
        """
        初始化流水线
        
        Args:
            max_workers: 最大并行worker数量
        """
        self.max_workers = max_workers
        self.stages: List[ScanStage] = []
        self.all_findings: List[ScanFinding] = []
    
    def scan(self, target_path: str) -> ScanResult:
        """
        执行完整扫描
        
        Args:
            target_path: 目标路径
            
        Returns:
            扫描结果
        """
        import time
        start_time = time.time()
        
        result = ScanResult(target_path=target_path)
        
        # Stage 1: 信息收集
        stage1 = self._stage1_reconnaissance(target_path)
        result.stages.append(stage1)
        
        # Stage 2: 并行漏洞检测
        stage2 = self._stage2_parallel_detection(target_path)
        result.stages.append(stage2)
        
        # Stage 3: 漏洞审查
        stage3 = self._stage3_review(result.stages)
        result.stages.append(stage3)
        
        # 合并所有发现
        result.all_findings = self.all_findings
        
        # 生成摘要
        result.summary = self._generate_summary(result)
        
        result.total_duration_ms = (time.time() - start_time) * 1000
        
        return result
    
    def _stage1_reconnaissance(self, target_path: str) -> ScanStage:
        """
        Stage 1: 信息收集
        
        收集目标配置、能力和暴露的端点
        """
        import time
        start_time = time.time()
        
        stage = ScanStage(
            stage_id="1",
            name="信息收集",
            description="收集目标配置、能力和暴露的端点"
        )
        
        path = Path(target_path)
        if not path.exists():
            return stage
        
        # 收集文件信息
        file_stats = {
            "total_files": 0,
            "python_files": 0,
            "config_files": 0,
            "skill_files": 0,
        }
        
        for file_path in path.rglob("*"):
            if not file_path.is_file():
                continue
            
            file_stats["total_files"] += 1
            
            suffix = file_path.suffix.lower()
            if suffix == ".py":
                file_stats["python_files"] += 1
            elif suffix in {".json", ".yaml", ".yml", ".toml", ".cfg", ".ini"}:
                file_stats["config_files"] += 1
            elif suffix == ".md" and file_path.name.upper() in {"SKILL.MD", "README.MD"}:
                file_stats["skill_files"] += 1
        
        stage.stats = file_stats
        stage.duration_ms = (time.time() - start_time) * 1000
        
        return stage
    
    def _stage2_parallel_detection(self, target_path: str) -> ScanStage:
        """
        Stage 2: 并行漏洞检测
        
        每个检测技能一个轻量级worker，并发执行
        """
        import time
        start_time = time.time()
        
        stage = ScanStage(
            stage_id="2",
            name="并行漏洞检测",
            description="每个检测技能一个轻量级worker，并发执行"
        )
        
        # 定义检测技能
        detection_skills = [
            ("agent_snooping", self._detect_agent_snooping),
            ("supply_chain", self._detect_supply_chain),
            ("ast_analysis", self._detect_ast_analysis),
            ("taint_tracking", self._detect_taint_tracking),
        ]
        
        # 并行执行检测
        findings = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_skill = {
                executor.submit(skill_func, target_path): skill_name
                for skill_name, skill_func in detection_skills
            }
            
            for future in as_completed(future_to_skill):
                skill_name = future_to_skill[future]
                try:
                    skill_findings = future.result()
                    findings.extend(skill_findings)
                    stage.stats[skill_name] = len(skill_findings)
                except Exception as e:
                    stage.stats[f"{skill_name}_error"] = 1
        
        stage.findings = findings
        self.all_findings.extend(findings)
        stage.duration_ms = (time.time() - start_time) * 1000
        
        return stage
    
    def _stage3_review(self, stages: List[ScanStage]) -> ScanStage:
        """
        Stage 3: 漏洞审查
        
        合并结果，映射到OWASP ASI，分配最终严重程度
        """
        import time
        start_time = time.time()
        
        stage = ScanStage(
            stage_id="3",
            name="漏洞审查",
            description="合并结果，映射到OWASP ASI，分配最终严重程度"
        )
        
        # 合并所有发现
        all_findings = []
        for s in stages:
            all_findings.extend(s.findings)
        
        # 映射到OWASP ASI
        for finding in all_findings:
            if finding.rule_id in RULE_TO_OWASP:
                finding.owasp_category = RULE_TO_OWASP[finding.rule_id]
        
        # 统计
        stage.stats = {
            "total_findings": len(all_findings),
            "critical": sum(1 for f in all_findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in all_findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in all_findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in all_findings if f.severity == Severity.LOW),
            "info": sum(1 for f in all_findings if f.severity == Severity.INFO),
        }
        
        stage.findings = all_findings
        stage.duration_ms = (time.time() - start_time) * 1000
        
        return stage
    
    def _detect_agent_snooping(self, target_path: str) -> List[ScanFinding]:
        """检测Agent Snooping行为"""
        try:
            from .agent_snooping import scan_agent_snooping
            findings = scan_agent_snooping(target_path)
            
            # 转换为ScanFinding
            return [
                ScanFinding(
                    rule_id=f.rule_id,
                    category=f.category,
                    description=f.description,
                    severity=Severity.HIGH,
                    confidence=f.confidence,
                    file_path=f.file_path,
                    line_number=f.line_number,
                    matched_text=f.matched_text,
                    details=f.details,
                    mitigation=f.mitigation,
                )
                for f in findings
            ]
        except Exception:
            return []
    
    def _detect_supply_chain(self, target_path: str) -> List[ScanFinding]:
        """检测供应链安全"""
        try:
            from .supply_chain import scan_dependencies
            threats = scan_dependencies(target_path)
            
            # 转换为ScanFinding
            return [
                ScanFinding(
                    rule_id=t.rule_id,
                    category=t.category,
                    description=t.description,
                    severity=Severity.HIGH if t.severity == "HIGH" else Severity.MEDIUM,
                    confidence=t.confidence,
                    file_path=target_path,
                    line_number=0,
                    matched_text=t.package_name,
                    details=t.details,
                    mitigation=t.mitigation,
                )
                for t in threats
            ]
        except Exception:
            return []
    
    def _detect_ast_analysis(self, target_path: str) -> List[ScanFinding]:
        """检测AST行为分析"""
        try:
            from .ast_analyzer import scan_ast
            findings = scan_ast(target_path)
            
            # 转换为ScanFinding
            return [
                ScanFinding(
                    rule_id=f.get("rule_id", "AST"),
                    category="AST Analysis",
                    description=f.get("description", ""),
                    severity=Severity.HIGH if f.get("severity") == "HIGH" else Severity.MEDIUM,
                    confidence=f.get("confidence", 0.8),
                    file_path=f.get("file_path", ""),
                    line_number=f.get("line_number", 0),
                    matched_text=f.get("matched_text", ""),
                    details=f.get("details", ""),
                    mitigation=f.get("mitigation", ""),
                )
                for f in findings
            ]
        except Exception:
            return []
    
    def _detect_taint_tracking(self, target_path: str) -> List[ScanFinding]:
        """检测污点追踪"""
        try:
            from .taint_tracker import scan_taint
            findings = scan_taint(target_path)
            
            # 转换为ScanFinding
            return [
                ScanFinding(
                    rule_id=f.get("rule_id", "TT"),
                    category="Taint Tracking",
                    description=f.get("description", ""),
                    severity=Severity.HIGH if f.get("severity") == "HIGH" else Severity.MEDIUM,
                    confidence=f.get("confidence", 0.8),
                    file_path=f.get("file_path", ""),
                    line_number=f.get("line_number", 0),
                    matched_text=f.get("matched_text", ""),
                    details=f.get("details", ""),
                    mitigation=f.get("mitigation", ""),
                )
                for f in findings
            ]
        except Exception:
            return []
    
    def _generate_summary(self, result: ScanResult) -> Dict[str, Any]:
        """生成扫描摘要"""
        all_findings = result.all_findings
        
        return {
            "total_findings": len(all_findings),
            "by_severity": {
                "critical": sum(1 for f in all_findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in all_findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in all_findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in all_findings if f.severity == Severity.LOW),
                "info": sum(1 for f in all_findings if f.severity == Severity.INFO),
            },
            "by_owasp": {
                category: sum(1 for f in all_findings if f.owasp_category == category_id)
                for category_id, category in OWASP_ASI_CATEGORIES.items()
            },
            "risk_score": self._calculate_risk_score(all_findings),
            "recommendation": self._generate_recommendation(all_findings),
        }
    
    def _calculate_risk_score(self, findings: List[ScanFinding]) -> int:
        """计算风险评分 (0-100)"""
        if not findings:
            return 0
        
        severity_weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }
        
        total_score = sum(
            severity_weights.get(f.severity, 0) * f.confidence
            for f in findings
        )
        
        # 归一化到0-100
        max_possible = len(findings) * 25  # 假设所有都是CRITICAL
        normalized_score = min(100, int((total_score / max_possible) * 100)) if max_possible > 0 else 0
        
        return normalized_score
    
    def _generate_recommendation(self, findings: List[ScanFinding]) -> str:
        """生成建议"""
        if not findings:
            return "✅ 未发现安全问题"
        
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        
        if critical_count > 0:
            return f"🚨 发现 {critical_count} 个严重问题，建议立即修复"
        elif high_count > 0:
            return f"⚠️ 发现 {high_count} 个高危问题，建议尽快修复"
        else:
            return f"ℹ️ 发现 {len(findings)} 个中低危问题，建议按优先级修复"


# ── Self-test ──

if __name__ == "__main__":
    import tempfile
    import os
    
    print("🔍 Agent Scan Pipeline 自测")
    print("=" * 50)
    
    # 创建测试目录
    with tempfile.TemporaryDirectory() as tmpdir:
        # 创建测试文件
        test_files = {
            "test_snooping.py": '''
import os
config_path = os.path.expanduser("~/.claude/config.json")
with open(config_path) as f:
    config = json.load(f)
''',
            "requirements.txt": '''
requests==2.31.0
colourama
numpy
''',
            "SKILL.md": '''
# Test Skill
This is a test skill.
''',
        }
        
        for filename, content in test_files.items():
            filepath = Path(tmpdir) / filename
            filepath.write_text(content)
        
        # 运行扫描
        pipeline = AgentScanPipeline(max_workers=2)
        result = pipeline.scan(tmpdir)
        
        # 输出结果
        print(f"\n📊 扫描结果:")
        print(f"  目标路径: {result.target_path}")
        print(f"  总发现数: {result.summary.get('total_findings', 0)}")
        print(f"  风险评分: {result.summary.get('risk_score', 0)}/100")
        print(f"  建议: {result.summary.get('recommendation', '')}")
        
        print(f"\n📋 阶段详情:")
        for stage in result.stages:
            print(f"  [{stage.stage_id}] {stage.name}")
            print(f"    发现数: {len(stage.findings)}")
            print(f"    耗时: {stage.duration_ms:.1f}ms")
            if stage.stats:
                print(f"    统计: {stage.stats}")
        
        print(f"\n🔍 详细发现:")
        for finding in result.all_findings[:5]:  # 只显示前5个
            print(f"  [{finding.rule_id}] {finding.description}")
            print(f"    文件: {finding.file_path}:{finding.line_number}")
            print(f"    严重程度: {finding.severity.value}")
            print(f"    OWASP: {finding.owasp_category}")
            print()
    
    print("\n✅ 自测完成")
