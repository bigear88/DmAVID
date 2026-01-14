"""
Hybrid Vulnerability Detection Framework

Combines static analysis with LLM-based semantic analysis for
comprehensive smart contract vulnerability detection.

Author: Curtis Chang
"""

import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .llm_detector import LLMDetector, RAGEnhancedDetector, DetectionResult
from .static_analyzer import SlitherAnalyzer, StaticAnalysisResult


class DetectionStage(Enum):
    """Enumeration of detection stages."""
    STATIC_ANALYSIS = "static_analysis"
    RAG_RETRIEVAL = "rag_retrieval"
    LLM_ANALYSIS = "llm_analysis"
    ENSEMBLE = "ensemble"


@dataclass
class HybridDetectionResult:
    """Comprehensive result from hybrid detection."""
    contract_id: str
    has_vulnerability: bool
    confidence: float
    vulnerability_types: List[str]
    severity: str
    
    # Stage-specific results
    static_result: Optional[StaticAnalysisResult] = None
    llm_result: Optional[DetectionResult] = None
    
    # Timing information
    total_time: float = 0.0
    stage_times: Dict[str, float] = field(default_factory=dict)
    
    # Detailed findings
    findings: List[Dict] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Ensemble details
    ensemble_weights: Dict[str, float] = field(default_factory=dict)
    agreement_score: float = 0.0


class HybridDetector:
    """
    Hybrid vulnerability detector combining multiple analysis methods.
    
    This detector implements a two-stage approach:
    1. Quick static analysis using Slither for pattern-based detection
    2. Deep semantic analysis using LLM for complex vulnerability detection
    
    The results are combined using an ensemble method with configurable weights.
    """
    
    DEFAULT_WEIGHTS = {
        "static": 0.3,
        "llm": 0.7
    }
    
    SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]
    
    def __init__(
        self,
        llm_model: str = "gpt-4.1-mini",
        use_rag: bool = True,
        knowledge_base_path: Optional[str] = None,
        weights: Optional[Dict[str, float]] = None,
        skip_static_if_clean: bool = False
    ):
        """
        Initialize the hybrid detector.
        
        Args:
            llm_model: LLM model to use
            use_rag: Whether to use RAG enhancement
            knowledge_base_path: Path to RAG knowledge base
            weights: Custom ensemble weights
            skip_static_if_clean: Skip LLM if static analysis finds no issues
        """
        self.weights = weights or self.DEFAULT_WEIGHTS
        self.skip_static_if_clean = skip_static_if_clean
        
        # Initialize static analyzer
        self.static_analyzer = SlitherAnalyzer()
        
        # Initialize LLM detector
        if use_rag and knowledge_base_path:
            self.llm_detector = RAGEnhancedDetector(
                knowledge_base_path=knowledge_base_path,
                model=llm_model
            )
        else:
            self.llm_detector = LLMDetector(model=llm_model)
    
    def _combine_vulnerability_types(
        self,
        static_result: StaticAnalysisResult,
        llm_result: DetectionResult
    ) -> List[str]:
        """Combine vulnerability types from both methods."""
        types = set()
        
        # From static analysis
        for vuln in static_result.vulnerabilities:
            vuln_type = vuln.get("check", vuln.get("type", "unknown"))
            types.add(vuln_type)
        
        # From LLM analysis
        if llm_result.vulnerability_type:
            types.add(llm_result.vulnerability_type)
        
        return list(types)
    
    def _determine_severity(
        self,
        static_result: StaticAnalysisResult,
        llm_result: DetectionResult
    ) -> str:
        """Determine overall severity from combined results."""
        severities = []
        
        # From static analysis
        for vuln in static_result.vulnerabilities:
            impact = vuln.get("impact", "").lower()
            if impact in self.SEVERITY_LEVELS:
                severities.append(impact)
        
        # From LLM (infer from confidence)
        if llm_result.has_vulnerability:
            if llm_result.confidence > 0.9:
                severities.append("critical")
            elif llm_result.confidence > 0.7:
                severities.append("high")
            elif llm_result.confidence > 0.5:
                severities.append("medium")
            else:
                severities.append("low")
        
        if not severities:
            return "info"
        
        # Return highest severity
        for level in self.SEVERITY_LEVELS:
            if level in severities:
                return level
        
        return "info"
    
    def _ensemble_decision(
        self,
        static_result: StaticAnalysisResult,
        llm_result: DetectionResult
    ) -> Tuple[bool, float, float]:
        """
        Make ensemble decision from both methods.
        
        Returns:
            Tuple of (has_vulnerability, confidence, agreement_score)
        """
        static_positive = len(static_result.vulnerabilities) > 0
        llm_positive = llm_result.has_vulnerability
        
        # Calculate weighted score
        static_score = 1.0 if static_positive else 0.0
        llm_score = llm_result.confidence if llm_positive else (1 - llm_result.confidence)
        
        weighted_score = (
            self.weights["static"] * static_score +
            self.weights["llm"] * llm_score
        )
        
        # Agreement score
        if static_positive == llm_positive:
            agreement = 1.0
        else:
            agreement = 0.0
        
        # Decision threshold
        has_vulnerability = weighted_score > 0.5
        confidence = weighted_score
        
        return has_vulnerability, confidence, agreement
    
    def _collect_findings(
        self,
        static_result: StaticAnalysisResult,
        llm_result: DetectionResult
    ) -> List[Dict]:
        """Collect all findings from both methods."""
        findings = []
        
        # Static analysis findings
        for vuln in static_result.vulnerabilities:
            findings.append({
                "source": "static_analysis",
                "type": vuln.get("check", "unknown"),
                "severity": vuln.get("impact", "unknown"),
                "description": vuln.get("description", ""),
                "location": vuln.get("elements", [])
            })
        
        # LLM findings
        if llm_result.has_vulnerability:
            findings.append({
                "source": "llm_analysis",
                "type": llm_result.vulnerability_type or "unknown",
                "severity": "high" if llm_result.confidence > 0.7 else "medium",
                "description": llm_result.reasoning,
                "confidence": llm_result.confidence
            })
        
        return findings
    
    def _generate_recommendations(
        self,
        findings: List[Dict],
        llm_result: DetectionResult
    ) -> List[str]:
        """Generate recommendations based on findings."""
        recommendations = []
        
        vuln_types = set(f.get("type", "") for f in findings)
        
        if "reentrancy" in str(vuln_types).lower():
            recommendations.append(
                "Implement checks-effects-interactions pattern to prevent reentrancy"
            )
            recommendations.append(
                "Consider using ReentrancyGuard from OpenZeppelin"
            )
        
        if "overflow" in str(vuln_types).lower() or "underflow" in str(vuln_types).lower():
            recommendations.append(
                "Use Solidity 0.8.x or SafeMath library for arithmetic operations"
            )
        
        if "access" in str(vuln_types).lower():
            recommendations.append(
                "Implement proper access control using OpenZeppelin's Ownable or AccessControl"
            )
        
        if "oracle" in str(vuln_types).lower():
            recommendations.append(
                "Use time-weighted average prices (TWAP) for oracle data"
            )
            recommendations.append(
                "Implement price deviation checks and circuit breakers"
            )
        
        if not recommendations:
            recommendations.append(
                "Consider a professional security audit before deployment"
            )
        
        return recommendations
    
    def detect(
        self,
        contract_code: str,
        contract_id: str = "unknown"
    ) -> HybridDetectionResult:
        """
        Perform hybrid vulnerability detection.
        
        Args:
            contract_code: Solidity source code
            contract_id: Contract identifier
            
        Returns:
            HybridDetectionResult with comprehensive analysis
        """
        start_time = time.time()
        stage_times = {}
        
        # Stage 1: Static Analysis
        stage_start = time.time()
        static_result = self.static_analyzer.analyze(contract_code, contract_id)
        stage_times[DetectionStage.STATIC_ANALYSIS.value] = time.time() - stage_start
        
        # Optional: Skip LLM if static analysis is clean
        if self.skip_static_if_clean and static_result.success:
            if not static_result.vulnerabilities and not static_result.warnings:
                return HybridDetectionResult(
                    contract_id=contract_id,
                    has_vulnerability=False,
                    confidence=0.9,
                    vulnerability_types=[],
                    severity="info",
                    static_result=static_result,
                    llm_result=None,
                    total_time=time.time() - start_time,
                    stage_times=stage_times,
                    findings=[],
                    recommendations=["No vulnerabilities detected by static analysis"],
                    ensemble_weights=self.weights,
                    agreement_score=1.0
                )
        
        # Stage 2: LLM Analysis
        stage_start = time.time()
        llm_result = self.llm_detector.detect(contract_code, contract_id)
        stage_times[DetectionStage.LLM_ANALYSIS.value] = time.time() - stage_start
        
        # Stage 3: Ensemble Decision
        stage_start = time.time()
        has_vulnerability, confidence, agreement = self._ensemble_decision(
            static_result, llm_result
        )
        stage_times[DetectionStage.ENSEMBLE.value] = time.time() - stage_start
        
        # Combine results
        vulnerability_types = self._combine_vulnerability_types(static_result, llm_result)
        severity = self._determine_severity(static_result, llm_result)
        findings = self._collect_findings(static_result, llm_result)
        recommendations = self._generate_recommendations(findings, llm_result)
        
        total_time = time.time() - start_time
        
        return HybridDetectionResult(
            contract_id=contract_id,
            has_vulnerability=has_vulnerability,
            confidence=confidence,
            vulnerability_types=vulnerability_types,
            severity=severity,
            static_result=static_result,
            llm_result=llm_result,
            total_time=total_time,
            stage_times=stage_times,
            findings=findings,
            recommendations=recommendations,
            ensemble_weights=self.weights,
            agreement_score=agreement
        )
    
    def batch_detect(
        self,
        contracts: List[Dict[str, str]],
        progress_callback=None
    ) -> List[HybridDetectionResult]:
        """
        Detect vulnerabilities in multiple contracts.
        
        Args:
            contracts: List of dicts with 'id' and 'code' keys
            progress_callback: Optional progress callback
            
        Returns:
            List of HybridDetectionResult objects
        """
        results = []
        total = len(contracts)
        
        for i, contract in enumerate(contracts):
            result = self.detect(
                contract_code=contract['code'],
                contract_id=contract.get('id', f'contract_{i}')
            )
            results.append(result)
            
            if progress_callback:
                progress_callback(i + 1, total, result)
        
        return results


if __name__ == "__main__":
    # Example usage
    sample_contract = """
    pragma solidity ^0.8.0;
    
    contract VulnerableBank {
        mapping(address => uint256) public balances;
        
        function deposit() public payable {
            balances[msg.sender] += msg.value;
        }
        
        function withdraw() public {
            uint256 amount = balances[msg.sender];
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "Transfer failed");
            balances[msg.sender] = 0;
        }
    }
    """
    
    detector = HybridDetector(use_rag=False)
    result = detector.detect(sample_contract, "vulnerable_bank")
    
    print(f"Contract: {result.contract_id}")
    print(f"Has Vulnerability: {result.has_vulnerability}")
    print(f"Confidence: {result.confidence:.2f}")
    print(f"Severity: {result.severity}")
    print(f"Types: {result.vulnerability_types}")
    print(f"Agreement: {result.agreement_score:.2f}")
    print(f"Total Time: {result.total_time:.2f}s")
    print(f"\nRecommendations:")
    for rec in result.recommendations:
        print(f"  - {rec}")
