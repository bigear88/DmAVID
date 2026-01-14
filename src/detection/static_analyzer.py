"""
Static Analysis Module for Smart Contract Vulnerability Detection

This module provides static analysis capabilities using Slither.
Author: Curtis Chang
"""

import os
import json
import subprocess
import tempfile
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class StaticAnalysisResult:
    """Data class for static analysis results."""
    contract_id: str
    vulnerabilities: List[Dict]
    warnings: List[Dict]
    info: List[Dict]
    analysis_time: float
    success: bool
    error_message: Optional[str] = None


class SlitherAnalyzer:
    """
    Static analyzer using Slither for smart contract analysis.
    
    Slither is a Solidity static analysis framework that runs a suite
    of vulnerability detectors and prints visual information about
    contract details.
    """
    
    # Slither detector categories
    DETECTOR_CATEGORIES = {
        "high": [
            "reentrancy-eth",
            "reentrancy-no-eth",
            "arbitrary-send-eth",
            "controlled-delegatecall",
            "suicidal",
            "uninitialized-state",
            "uninitialized-storage"
        ],
        "medium": [
            "reentrancy-benign",
            "reentrancy-events",
            "incorrect-equality",
            "locked-ether",
            "shadowing-state",
            "tx-origin"
        ],
        "low": [
            "assembly",
            "boolean-equal",
            "constable-states",
            "external-function",
            "naming-convention",
            "pragma",
            "solc-version"
        ]
    }
    
    def __init__(
        self,
        solc_version: str = "0.8.0",
        detectors: Optional[List[str]] = None,
        exclude_detectors: Optional[List[str]] = None
    ):
        """
        Initialize the Slither analyzer.
        
        Args:
            solc_version: Solidity compiler version
            detectors: Specific detectors to run (None = all)
            exclude_detectors: Detectors to exclude
        """
        self.solc_version = solc_version
        self.detectors = detectors
        self.exclude_detectors = exclude_detectors or []
        
    def _create_temp_file(self, contract_code: str) -> str:
        """Create a temporary file with the contract code."""
        fd, path = tempfile.mkstemp(suffix=".sol")
        with os.fdopen(fd, 'w') as f:
            f.write(contract_code)
        return path
    
    def _run_slither(self, contract_path: str) -> Dict:
        """
        Run Slither on a contract file.
        
        Args:
            contract_path: Path to the Solidity file
            
        Returns:
            Dictionary with Slither results
        """
        cmd = [
            "slither",
            contract_path,
            "--json", "-",
            "--solc-disable-warnings"
        ]
        
        if self.detectors:
            cmd.extend(["--detect", ",".join(self.detectors)])
        
        for detector in self.exclude_detectors:
            cmd.extend(["--exclude", detector])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.stdout:
                return json.loads(result.stdout)
            return {"success": False, "error": result.stderr}
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Analysis timeout"}
        except json.JSONDecodeError:
            return {"success": False, "error": "Invalid JSON output"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _categorize_findings(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Categorize findings by severity.
        
        Args:
            findings: List of Slither findings
            
        Returns:
            Dictionary with categorized findings
        """
        categorized = {
            "vulnerabilities": [],  # High severity
            "warnings": [],         # Medium severity
            "info": []              # Low severity / informational
        }
        
        for finding in findings:
            impact = finding.get("impact", "").lower()
            
            if impact in ["high", "critical"]:
                categorized["vulnerabilities"].append(finding)
            elif impact == "medium":
                categorized["warnings"].append(finding)
            else:
                categorized["info"].append(finding)
        
        return categorized
    
    def analyze(
        self,
        contract_code: str,
        contract_id: str = "unknown"
    ) -> StaticAnalysisResult:
        """
        Analyze a smart contract using Slither.
        
        Args:
            contract_code: Solidity source code
            contract_id: Contract identifier
            
        Returns:
            StaticAnalysisResult with findings
        """
        import time
        start_time = time.time()
        
        # Create temporary file
        temp_path = self._create_temp_file(contract_code)
        
        try:
            # Run Slither
            result = self._run_slither(temp_path)
            analysis_time = time.time() - start_time
            
            if not result.get("success", True):
                return StaticAnalysisResult(
                    contract_id=contract_id,
                    vulnerabilities=[],
                    warnings=[],
                    info=[],
                    analysis_time=analysis_time,
                    success=False,
                    error_message=result.get("error", "Unknown error")
                )
            
            # Extract and categorize findings
            findings = result.get("results", {}).get("detectors", [])
            categorized = self._categorize_findings(findings)
            
            return StaticAnalysisResult(
                contract_id=contract_id,
                vulnerabilities=categorized["vulnerabilities"],
                warnings=categorized["warnings"],
                info=categorized["info"],
                analysis_time=analysis_time,
                success=True
            )
            
        finally:
            # Clean up temporary file
            if os.path.exists(temp_path):
                os.remove(temp_path)
    
    def batch_analyze(
        self,
        contracts: List[Dict[str, str]],
        progress_callback=None
    ) -> List[StaticAnalysisResult]:
        """
        Analyze multiple contracts.
        
        Args:
            contracts: List of dicts with 'id' and 'code' keys
            progress_callback: Optional progress callback
            
        Returns:
            List of StaticAnalysisResult objects
        """
        results = []
        total = len(contracts)
        
        for i, contract in enumerate(contracts):
            result = self.analyze(
                contract_code=contract['code'],
                contract_id=contract.get('id', f'contract_{i}')
            )
            results.append(result)
            
            if progress_callback:
                progress_callback(i + 1, total, result)
        
        return results


class MythrilAnalyzer:
    """
    Static analyzer using Mythril for symbolic execution.
    
    Mythril is a security analysis tool for EVM bytecode that uses
    symbolic execution, SMT solving and taint analysis.
    """
    
    def __init__(
        self,
        execution_timeout: int = 300,
        solver_timeout: int = 10000,
        max_depth: int = 22
    ):
        """
        Initialize Mythril analyzer.
        
        Args:
            execution_timeout: Maximum execution time in seconds
            solver_timeout: SMT solver timeout in milliseconds
            max_depth: Maximum transaction depth
        """
        self.execution_timeout = execution_timeout
        self.solver_timeout = solver_timeout
        self.max_depth = max_depth
    
    def analyze(
        self,
        contract_code: str,
        contract_id: str = "unknown"
    ) -> StaticAnalysisResult:
        """
        Analyze contract using Mythril.
        
        Args:
            contract_code: Solidity source code
            contract_id: Contract identifier
            
        Returns:
            StaticAnalysisResult with findings
        """
        import time
        start_time = time.time()
        
        # Create temporary file
        fd, temp_path = tempfile.mkstemp(suffix=".sol")
        with os.fdopen(fd, 'w') as f:
            f.write(contract_code)
        
        try:
            cmd = [
                "myth", "analyze",
                temp_path,
                "--execution-timeout", str(self.execution_timeout),
                "--solver-timeout", str(self.solver_timeout),
                "--max-depth", str(self.max_depth),
                "-o", "json"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.execution_timeout + 60
            )
            
            analysis_time = time.time() - start_time
            
            if result.stdout:
                try:
                    findings = json.loads(result.stdout)
                    issues = findings.get("issues", [])
                    
                    vulnerabilities = [
                        issue for issue in issues
                        if issue.get("severity", "").lower() in ["high", "critical"]
                    ]
                    warnings = [
                        issue for issue in issues
                        if issue.get("severity", "").lower() == "medium"
                    ]
                    info = [
                        issue for issue in issues
                        if issue.get("severity", "").lower() in ["low", "informational"]
                    ]
                    
                    return StaticAnalysisResult(
                        contract_id=contract_id,
                        vulnerabilities=vulnerabilities,
                        warnings=warnings,
                        info=info,
                        analysis_time=analysis_time,
                        success=True
                    )
                except json.JSONDecodeError:
                    pass
            
            return StaticAnalysisResult(
                contract_id=contract_id,
                vulnerabilities=[],
                warnings=[],
                info=[],
                analysis_time=analysis_time,
                success=False,
                error_message=result.stderr or "Analysis failed"
            )
            
        except subprocess.TimeoutExpired:
            return StaticAnalysisResult(
                contract_id=contract_id,
                vulnerabilities=[],
                warnings=[],
                info=[],
                analysis_time=time.time() - start_time,
                success=False,
                error_message="Analysis timeout"
            )
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


if __name__ == "__main__":
    # Example usage
    sample_contract = """
    pragma solidity ^0.8.0;
    
    contract SimpleStorage {
        uint256 private value;
        
        function setValue(uint256 _value) public {
            value = _value;
        }
        
        function getValue() public view returns (uint256) {
            return value;
        }
    }
    """
    
    analyzer = SlitherAnalyzer()
    result = analyzer.analyze(sample_contract, "simple_storage")
    
    print(f"Contract: {result.contract_id}")
    print(f"Success: {result.success}")
    print(f"Vulnerabilities: {len(result.vulnerabilities)}")
    print(f"Warnings: {len(result.warnings)}")
    print(f"Info: {len(result.info)}")
    print(f"Analysis Time: {result.analysis_time:.2f}s")
