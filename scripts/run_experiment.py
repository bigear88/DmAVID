#!/usr/bin/env python3
"""
Main Experiment Runner for Smart Contract Vulnerability Detection

This script orchestrates the complete experiment pipeline including:
- Data loading and preprocessing
- Running detection methods
- Evaluating results
- Generating reports

Author: Curtis Chang
"""

import os
import sys
import json
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.detection.llm_detector import LLMDetector, RAGEnhancedDetector
from src.detection.static_analyzer import SlitherAnalyzer
from src.detection.hybrid_detector import HybridDetector
from src.evaluation.metrics import MetricsCalculator, generate_comparison_table


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ExperimentRunner:
    """
    Main experiment runner class.
    
    Handles the complete experiment pipeline from data loading
    to result generation.
    """
    
    def __init__(
        self,
        config_path: str,
        output_dir: str = "results"
    ):
        """
        Initialize experiment runner.
        
        Args:
            config_path: Path to configuration file
            output_dir: Directory for output files
        """
        self.config = self._load_config(config_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize detectors
        self.detectors = self._initialize_detectors()
        
        # Results storage
        self.results = {}
        self.metrics = {}
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file."""
        import yaml
        
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def _initialize_detectors(self) -> Dict:
        """Initialize all detection methods."""
        detectors = {}
        
        # LLM-only detector
        if self.config.get('methods', {}).get('llm', {}).get('enabled', True):
            detectors['llm'] = LLMDetector(
                model=self.config.get('openai', {}).get('model', 'gpt-4.1-mini'),
                temperature=self.config.get('openai', {}).get('temperature', 0.1)
            )
        
        # Static analyzer
        if self.config.get('methods', {}).get('static', {}).get('enabled', True):
            detectors['static'] = SlitherAnalyzer()
        
        # Hybrid detector
        if self.config.get('methods', {}).get('hybrid', {}).get('enabled', True):
            detectors['hybrid'] = HybridDetector(
                llm_model=self.config.get('openai', {}).get('model', 'gpt-4.1-mini'),
                use_rag=self.config.get('methods', {}).get('hybrid', {}).get('use_rag', False)
            )
        
        return detectors
    
    def load_dataset(self, dataset_path: str) -> List[Dict]:
        """
        Load dataset from directory or file.
        
        Args:
            dataset_path: Path to dataset
            
        Returns:
            List of contract dictionaries
        """
        contracts = []
        dataset_path = Path(dataset_path)
        
        if dataset_path.is_file():
            # Load from JSON file
            with open(dataset_path, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    contracts = data
                else:
                    contracts = data.get('contracts', [])
        
        elif dataset_path.is_dir():
            # Load from directory of .sol files
            for sol_file in dataset_path.rglob('*.sol'):
                with open(sol_file, 'r') as f:
                    code = f.read()
                
                # Determine label from directory structure
                label = 'vulnerable' if 'vulnerable' in str(sol_file).lower() else 'safe'
                
                contracts.append({
                    'id': sol_file.stem,
                    'code': code,
                    'label': label,
                    'path': str(sol_file)
                })
        
        logger.info(f"Loaded {len(contracts)} contracts from {dataset_path}")
        return contracts
    
    def run_detection(
        self,
        contracts: List[Dict],
        method_name: str
    ) -> List[Dict]:
        """
        Run detection using specified method.
        
        Args:
            contracts: List of contracts to analyze
            method_name: Name of detection method
            
        Returns:
            List of detection results
        """
        detector = self.detectors.get(method_name)
        if not detector:
            logger.error(f"Unknown method: {method_name}")
            return []
        
        results = []
        total = len(contracts)
        
        for i, contract in enumerate(contracts):
            logger.info(f"[{method_name}] Processing {i+1}/{total}: {contract['id']}")
            
            try:
                if method_name == 'static':
                    result = detector.analyze(
                        contract['code'],
                        contract['id']
                    )
                    results.append({
                        'contract_id': contract['id'],
                        'ground_truth': contract.get('label') == 'vulnerable',
                        'prediction': len(result.vulnerabilities) > 0,
                        'confidence': 1.0 if result.vulnerabilities else 0.0,
                        'detection_time': result.analysis_time,
                        'details': {
                            'vulnerabilities': len(result.vulnerabilities),
                            'warnings': len(result.warnings)
                        }
                    })
                else:
                    result = detector.detect(
                        contract['code'],
                        contract['id']
                    )
                    
                    if hasattr(result, 'has_vulnerability'):
                        # LLM or Hybrid result
                        results.append({
                            'contract_id': contract['id'],
                            'ground_truth': contract.get('label') == 'vulnerable',
                            'prediction': result.has_vulnerability,
                            'confidence': result.confidence,
                            'detection_time': getattr(result, 'detection_time', 0) or \
                                             getattr(result, 'total_time', 0),
                            'vulnerability_type': getattr(result, 'vulnerability_type', None) or \
                                                 (result.vulnerability_types[0] if hasattr(result, 'vulnerability_types') and result.vulnerability_types else None),
                            'reasoning': getattr(result, 'reasoning', '')
                        })
                    
            except Exception as e:
                logger.error(f"Error processing {contract['id']}: {e}")
                results.append({
                    'contract_id': contract['id'],
                    'ground_truth': contract.get('label') == 'vulnerable',
                    'prediction': False,
                    'confidence': 0.0,
                    'detection_time': 0.0,
                    'error': str(e)
                })
        
        return results
    
    def evaluate_results(
        self,
        results: List[Dict],
        method_name: str
    ) -> Dict:
        """
        Evaluate detection results.
        
        Args:
            results: Detection results
            method_name: Method name for logging
            
        Returns:
            Evaluation metrics dictionary
        """
        calculator = MetricsCalculator()
        
        for result in results:
            calculator.add_result(
                ground_truth=result['ground_truth'],
                prediction=result['prediction'],
                confidence=result.get('confidence', 1.0),
                detection_time=result.get('detection_time', 0.0),
                vulnerability_type=result.get('vulnerability_type')
            )
        
        metrics = calculator.calculate()
        
        logger.info(f"\n{method_name} Results:")
        logger.info(f"  Accuracy: {metrics.accuracy:.4f}")
        logger.info(f"  Precision: {metrics.precision:.4f}")
        logger.info(f"  Recall: {metrics.recall:.4f}")
        logger.info(f"  F1-Score: {metrics.f1_score:.4f}")
        
        return metrics.to_dict()
    
    def run_experiment(
        self,
        dataset_path: str,
        methods: Optional[List[str]] = None
    ):
        """
        Run complete experiment.
        
        Args:
            dataset_path: Path to dataset
            methods: List of methods to run (None = all)
        """
        # Load dataset
        contracts = self.load_dataset(dataset_path)
        
        if not contracts:
            logger.error("No contracts loaded!")
            return
        
        # Determine methods to run
        if methods is None:
            methods = list(self.detectors.keys())
        
        # Run each method
        for method in methods:
            if method not in self.detectors:
                logger.warning(f"Skipping unknown method: {method}")
                continue
            
            logger.info(f"\n{'='*50}")
            logger.info(f"Running {method} detection...")
            logger.info(f"{'='*50}")
            
            # Run detection
            results = self.run_detection(contracts, method)
            self.results[method] = results
            
            # Evaluate
            metrics = self.evaluate_results(results, method)
            self.metrics[method] = metrics
        
        # Save results
        self._save_results()
        
        # Generate comparison
        self._generate_comparison()
    
    def _save_results(self):
        """Save all results to files."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save raw results
        results_file = self.output_dir / f"results_{timestamp}.json"
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        logger.info(f"Results saved to {results_file}")
        
        # Save metrics
        metrics_file = self.output_dir / f"metrics_{timestamp}.json"
        with open(metrics_file, 'w') as f:
            json.dump(self.metrics, f, indent=2)
        logger.info(f"Metrics saved to {metrics_file}")
    
    def _generate_comparison(self):
        """Generate method comparison table."""
        if len(self.metrics) < 2:
            return
        
        # Create comparison table
        headers = ["Method", "Accuracy", "Precision", "Recall", "F1", "FPR", "Avg Time"]
        rows = []
        
        for method, metrics in self.metrics.items():
            rows.append([
                method,
                f"{metrics['accuracy']:.4f}",
                f"{metrics['precision']:.4f}",
                f"{metrics['recall']:.4f}",
                f"{metrics['f1_score']:.4f}",
                f"{metrics['false_positive_rate']:.4f}",
                f"{metrics['avg_detection_time']:.2f}s"
            ])
        
        # Print table
        print("\n" + "="*80)
        print("METHOD COMPARISON")
        print("="*80)
        
        # Header
        print("| " + " | ".join(f"{h:^12}" for h in headers) + " |")
        print("|" + "|".join(["-"*14] * len(headers)) + "|")
        
        # Data
        for row in rows:
            print("| " + " | ".join(f"{v:^12}" for v in row) + " |")
        
        print("="*80)


def main():
    parser = argparse.ArgumentParser(
        description="Run smart contract vulnerability detection experiments"
    )
    parser.add_argument(
        "--config",
        type=str,
        default="configs/config.yaml",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--dataset",
        type=str,
        required=True,
        help="Path to dataset directory or file"
    )
    parser.add_argument(
        "--methods",
        type=str,
        nargs="+",
        choices=["llm", "static", "hybrid"],
        help="Methods to run (default: all)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="results",
        help="Output directory for results"
    )
    
    args = parser.parse_args()
    
    # Run experiment
    runner = ExperimentRunner(
        config_path=args.config,
        output_dir=args.output
    )
    
    runner.run_experiment(
        dataset_path=args.dataset,
        methods=args.methods
    )


if __name__ == "__main__":
    main()
