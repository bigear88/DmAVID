"""
LLM-based Smart Contract Vulnerability Detector

This module implements vulnerability detection using Large Language Models (GPT-4).
Author: Curtis Chang
"""

import os
import json
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from openai import OpenAI


@dataclass
class DetectionResult:
    """Data class for storing detection results."""
    contract_id: str
    has_vulnerability: bool
    confidence: float
    vulnerability_type: Optional[str]
    reasoning: str
    detection_time: float
    raw_response: str


class LLMDetector:
    """
    LLM-based vulnerability detector for smart contracts.
    
    Uses GPT-4 to analyze Solidity smart contracts and detect potential
    security vulnerabilities through semantic understanding.
    """
    
    # Vulnerability types to detect
    VULNERABILITY_TYPES = [
        "reentrancy",
        "integer_overflow",
        "integer_underflow",
        "access_control",
        "unchecked_call",
        "denial_of_service",
        "front_running",
        "time_manipulation",
        "bad_randomness",
        "flash_loan_attack",
        "price_oracle_manipulation",
        "governance_attack"
    ]
    
    def __init__(
        self,
        model: str = "gpt-4.1-mini",
        temperature: float = 0.1,
        max_tokens: int = 2048,
        api_key: Optional[str] = None
    ):
        """
        Initialize the LLM detector.
        
        Args:
            model: OpenAI model to use
            temperature: Sampling temperature (lower = more deterministic)
            max_tokens: Maximum tokens in response
            api_key: OpenAI API key (defaults to environment variable)
        """
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.client = OpenAI(api_key=api_key or os.getenv("OPENAI_API_KEY"))
        
    def _build_prompt(self, contract_code: str, context: Optional[str] = None) -> str:
        """
        Build the analysis prompt for the LLM.
        
        Args:
            contract_code: Solidity source code
            context: Optional additional context (e.g., from RAG)
            
        Returns:
            Formatted prompt string
        """
        base_prompt = f"""You are an expert smart contract security auditor specializing in Ethereum and DeFi protocols.

Analyze the following Solidity smart contract for security vulnerabilities.

## Contract Code:
```solidity
{contract_code}
```

"""
        if context:
            base_prompt += f"""## Additional Context (from knowledge base):
{context}

"""
        
        base_prompt += """## Analysis Instructions:
1. Carefully examine the contract for common vulnerability patterns
2. Pay special attention to:
   - Reentrancy vulnerabilities
   - Integer overflow/underflow
   - Access control issues
   - Unchecked external calls
   - Flash loan attack vectors
   - Price oracle manipulation risks
   - Front-running vulnerabilities

## Required Output Format (JSON):
```json
{
    "has_vulnerability": true/false,
    "confidence": 0.0-1.0,
    "vulnerability_type": "type or null",
    "severity": "critical/high/medium/low/info",
    "vulnerable_functions": ["function_name"],
    "reasoning": "detailed explanation",
    "recommendations": ["fix suggestion"]
}
```

Provide your analysis:"""
        
        return base_prompt
    
    def _parse_response(self, response_text: str) -> Dict:
        """
        Parse the LLM response into structured data.
        
        Args:
            response_text: Raw response from LLM
            
        Returns:
            Parsed dictionary with detection results
        """
        try:
            # Try to extract JSON from response
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start != -1 and json_end > json_start:
                json_str = response_text[json_start:json_end]
                return json.loads(json_str)
        except json.JSONDecodeError:
            pass
        
        # Fallback: parse text response
        has_vuln = any(keyword in response_text.lower() 
                      for keyword in ['vulnerability', 'vulnerable', 'risk', 'issue'])
        
        return {
            "has_vulnerability": has_vuln,
            "confidence": 0.5,
            "vulnerability_type": None,
            "reasoning": response_text,
            "recommendations": []
        }
    
    def detect(
        self,
        contract_code: str,
        contract_id: str = "unknown",
        context: Optional[str] = None
    ) -> DetectionResult:
        """
        Detect vulnerabilities in a smart contract.
        
        Args:
            contract_code: Solidity source code
            contract_id: Identifier for the contract
            context: Optional RAG context
            
        Returns:
            DetectionResult with analysis findings
        """
        start_time = time.time()
        
        prompt = self._build_prompt(contract_code, context)
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert smart contract security auditor."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )
            
            raw_response = response.choices[0].message.content
            parsed = self._parse_response(raw_response)
            
            detection_time = time.time() - start_time
            
            return DetectionResult(
                contract_id=contract_id,
                has_vulnerability=parsed.get("has_vulnerability", False),
                confidence=parsed.get("confidence", 0.5),
                vulnerability_type=parsed.get("vulnerability_type"),
                reasoning=parsed.get("reasoning", ""),
                detection_time=detection_time,
                raw_response=raw_response
            )
            
        except Exception as e:
            detection_time = time.time() - start_time
            return DetectionResult(
                contract_id=contract_id,
                has_vulnerability=False,
                confidence=0.0,
                vulnerability_type=None,
                reasoning=f"Error during detection: {str(e)}",
                detection_time=detection_time,
                raw_response=""
            )
    
    def batch_detect(
        self,
        contracts: List[Dict[str, str]],
        progress_callback=None
    ) -> List[DetectionResult]:
        """
        Detect vulnerabilities in multiple contracts.
        
        Args:
            contracts: List of dicts with 'id' and 'code' keys
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of DetectionResult objects
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


class RAGEnhancedDetector(LLMDetector):
    """
    LLM detector enhanced with Retrieval-Augmented Generation (RAG).
    
    Uses a knowledge base of known vulnerabilities and attack patterns
    to provide context for the LLM analysis.
    """
    
    def __init__(
        self,
        knowledge_base_path: str,
        embedding_model: str = "text-embedding-3-small",
        **kwargs
    ):
        """
        Initialize RAG-enhanced detector.
        
        Args:
            knowledge_base_path: Path to knowledge base directory
            embedding_model: Model for generating embeddings
            **kwargs: Additional arguments for LLMDetector
        """
        super().__init__(**kwargs)
        self.knowledge_base_path = knowledge_base_path
        self.embedding_model = embedding_model
        self.knowledge_base = self._load_knowledge_base()
        
    def _load_knowledge_base(self) -> List[Dict]:
        """Load and index the knowledge base."""
        knowledge = []
        
        # Load vulnerability patterns
        patterns_file = os.path.join(
            self.knowledge_base_path, 
            "vulnerability_patterns.json"
        )
        if os.path.exists(patterns_file):
            with open(patterns_file, 'r') as f:
                knowledge.extend(json.load(f))
        
        # Load attack case studies
        cases_file = os.path.join(
            self.knowledge_base_path,
            "attack_cases.json"
        )
        if os.path.exists(cases_file):
            with open(cases_file, 'r') as f:
                knowledge.extend(json.load(f))
        
        return knowledge
    
    def _retrieve_context(self, contract_code: str, top_k: int = 3) -> str:
        """
        Retrieve relevant context from knowledge base.
        
        Args:
            contract_code: Contract to analyze
            top_k: Number of relevant items to retrieve
            
        Returns:
            Formatted context string
        """
        # Simple keyword-based retrieval (can be enhanced with embeddings)
        relevant = []
        
        keywords = [
            "transfer", "call", "delegatecall", "selfdestruct",
            "balance", "msg.sender", "tx.origin", "block.timestamp"
        ]
        
        for item in self.knowledge_base:
            score = sum(1 for kw in keywords if kw in contract_code.lower())
            if score > 0:
                relevant.append((score, item))
        
        relevant.sort(key=lambda x: x[0], reverse=True)
        top_items = [item for _, item in relevant[:top_k]]
        
        if not top_items:
            return ""
        
        context_parts = []
        for item in top_items:
            context_parts.append(
                f"**{item.get('title', 'Unknown')}**\n"
                f"Type: {item.get('type', 'N/A')}\n"
                f"Description: {item.get('description', 'N/A')}\n"
            )
        
        return "\n---\n".join(context_parts)
    
    def detect(
        self,
        contract_code: str,
        contract_id: str = "unknown",
        context: Optional[str] = None
    ) -> DetectionResult:
        """
        Detect vulnerabilities with RAG enhancement.
        
        Args:
            contract_code: Solidity source code
            contract_id: Contract identifier
            context: Optional additional context
            
        Returns:
            DetectionResult with RAG-enhanced analysis
        """
        # Retrieve relevant context from knowledge base
        rag_context = self._retrieve_context(contract_code)
        
        # Combine with any provided context
        full_context = rag_context
        if context:
            full_context = f"{rag_context}\n\n{context}"
        
        return super().detect(contract_code, contract_id, full_context)


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
    
    detector = LLMDetector()
    result = detector.detect(sample_contract, "sample_vulnerable_bank")
    
    print(f"Contract: {result.contract_id}")
    print(f"Has Vulnerability: {result.has_vulnerability}")
    print(f"Confidence: {result.confidence}")
    print(f"Type: {result.vulnerability_type}")
    print(f"Reasoning: {result.reasoning}")
    print(f"Detection Time: {result.detection_time:.2f}s")
