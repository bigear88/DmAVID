"""
Evaluation Metrics for Smart Contract Vulnerability Detection

This module provides comprehensive evaluation metrics for assessing
the performance of vulnerability detection methods.

Author: Curtis Chang
"""

import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
import numpy as np


@dataclass
class ConfusionMatrix:
    """Confusion matrix for binary classification."""
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    
    @property
    def total(self) -> int:
        return self.true_positives + self.true_negatives + \
               self.false_positives + self.false_negatives
    
    def to_dict(self) -> Dict:
        return {
            "TP": self.true_positives,
            "TN": self.true_negatives,
            "FP": self.false_positives,
            "FN": self.false_negatives,
            "total": self.total
        }


@dataclass
class EvaluationMetrics:
    """Comprehensive evaluation metrics."""
    # Basic metrics
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    
    # Additional metrics
    specificity: float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    
    # ROC/AUC (if confidence scores available)
    auc_roc: Optional[float] = None
    
    # Timing metrics
    avg_detection_time: float = 0.0
    total_detection_time: float = 0.0
    
    # Confusion matrix
    confusion_matrix: ConfusionMatrix = field(default_factory=ConfusionMatrix)
    
    # Per-class metrics
    per_vulnerability_metrics: Dict[str, Dict] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "specificity": self.specificity,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "auc_roc": self.auc_roc,
            "avg_detection_time": self.avg_detection_time,
            "total_detection_time": self.total_detection_time,
            "confusion_matrix": self.confusion_matrix.to_dict(),
            "per_vulnerability_metrics": self.per_vulnerability_metrics
        }


class MetricsCalculator:
    """
    Calculator for evaluation metrics.
    
    Computes various performance metrics for vulnerability detection
    including accuracy, precision, recall, F1-score, and more.
    """
    
    def __init__(self):
        self.results = []
        self.ground_truths = []
        self.predictions = []
        self.confidences = []
        self.detection_times = []
        self.vulnerability_types = []
    
    def add_result(
        self,
        ground_truth: bool,
        prediction: bool,
        confidence: float = 1.0,
        detection_time: float = 0.0,
        vulnerability_type: Optional[str] = None
    ):
        """
        Add a single detection result.
        
        Args:
            ground_truth: True if contract has vulnerability
            prediction: Model's prediction
            confidence: Model's confidence score
            detection_time: Time taken for detection
            vulnerability_type: Type of vulnerability (if any)
        """
        self.ground_truths.append(ground_truth)
        self.predictions.append(prediction)
        self.confidences.append(confidence)
        self.detection_times.append(detection_time)
        self.vulnerability_types.append(vulnerability_type)
    
    def add_batch_results(
        self,
        results: List[Dict]
    ):
        """
        Add multiple results from a batch.
        
        Args:
            results: List of result dictionaries
        """
        for result in results:
            self.add_result(
                ground_truth=result.get('ground_truth', False),
                prediction=result.get('prediction', False),
                confidence=result.get('confidence', 1.0),
                detection_time=result.get('detection_time', 0.0),
                vulnerability_type=result.get('vulnerability_type')
            )
    
    def _compute_confusion_matrix(self) -> ConfusionMatrix:
        """Compute confusion matrix from results."""
        cm = ConfusionMatrix()
        
        for gt, pred in zip(self.ground_truths, self.predictions):
            if gt and pred:
                cm.true_positives += 1
            elif not gt and not pred:
                cm.true_negatives += 1
            elif not gt and pred:
                cm.false_positives += 1
            else:  # gt and not pred
                cm.false_negatives += 1
        
        return cm
    
    def _compute_basic_metrics(self, cm: ConfusionMatrix) -> Dict[str, float]:
        """Compute basic classification metrics."""
        # Accuracy
        accuracy = (cm.true_positives + cm.true_negatives) / cm.total \
                   if cm.total > 0 else 0.0
        
        # Precision
        precision = cm.true_positives / (cm.true_positives + cm.false_positives) \
                    if (cm.true_positives + cm.false_positives) > 0 else 0.0
        
        # Recall (Sensitivity)
        recall = cm.true_positives / (cm.true_positives + cm.false_negatives) \
                 if (cm.true_positives + cm.false_negatives) > 0 else 0.0
        
        # F1 Score
        f1 = 2 * (precision * recall) / (precision + recall) \
             if (precision + recall) > 0 else 0.0
        
        # Specificity
        specificity = cm.true_negatives / (cm.true_negatives + cm.false_positives) \
                      if (cm.true_negatives + cm.false_positives) > 0 else 0.0
        
        # False Positive Rate
        fpr = cm.false_positives / (cm.false_positives + cm.true_negatives) \
              if (cm.false_positives + cm.true_negatives) > 0 else 0.0
        
        # False Negative Rate
        fnr = cm.false_negatives / (cm.false_negatives + cm.true_positives) \
              if (cm.false_negatives + cm.true_positives) > 0 else 0.0
        
        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "specificity": specificity,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr
        }
    
    def _compute_auc_roc(self) -> Optional[float]:
        """Compute AUC-ROC if confidence scores are available."""
        if not self.confidences or len(set(self.confidences)) <= 1:
            return None
        
        try:
            from sklearn.metrics import roc_auc_score
            return roc_auc_score(self.ground_truths, self.confidences)
        except ImportError:
            # Manual AUC calculation
            return self._manual_auc_calculation()
        except ValueError:
            return None
    
    def _manual_auc_calculation(self) -> float:
        """Manual AUC calculation without sklearn."""
        pairs = list(zip(self.confidences, self.ground_truths))
        pairs.sort(key=lambda x: x[0], reverse=True)
        
        n_pos = sum(self.ground_truths)
        n_neg = len(self.ground_truths) - n_pos
        
        if n_pos == 0 or n_neg == 0:
            return 0.5
        
        auc = 0.0
        tp = 0
        
        for conf, label in pairs:
            if label:
                tp += 1
            else:
                auc += tp
        
        return auc / (n_pos * n_neg)
    
    def _compute_per_vulnerability_metrics(self) -> Dict[str, Dict]:
        """Compute metrics per vulnerability type."""
        type_results = {}
        
        for gt, pred, vtype in zip(
            self.ground_truths, 
            self.predictions, 
            self.vulnerability_types
        ):
            if vtype is None:
                continue
            
            if vtype not in type_results:
                type_results[vtype] = {
                    "tp": 0, "tn": 0, "fp": 0, "fn": 0
                }
            
            if gt and pred:
                type_results[vtype]["tp"] += 1
            elif not gt and not pred:
                type_results[vtype]["tn"] += 1
            elif not gt and pred:
                type_results[vtype]["fp"] += 1
            else:
                type_results[vtype]["fn"] += 1
        
        # Calculate metrics for each type
        per_type_metrics = {}
        for vtype, counts in type_results.items():
            tp, tn, fp, fn = counts["tp"], counts["tn"], counts["fp"], counts["fn"]
            total = tp + tn + fp + fn
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * (precision * recall) / (precision + recall) \
                 if (precision + recall) > 0 else 0.0
            
            per_type_metrics[vtype] = {
                "count": total,
                "precision": precision,
                "recall": recall,
                "f1_score": f1
            }
        
        return per_type_metrics
    
    def calculate(self) -> EvaluationMetrics:
        """
        Calculate all evaluation metrics.
        
        Returns:
            EvaluationMetrics object with all computed metrics
        """
        if not self.ground_truths:
            return EvaluationMetrics()
        
        # Confusion matrix
        cm = self._compute_confusion_matrix()
        
        # Basic metrics
        basic = self._compute_basic_metrics(cm)
        
        # AUC-ROC
        auc = self._compute_auc_roc()
        
        # Per-vulnerability metrics
        per_vuln = self._compute_per_vulnerability_metrics()
        
        # Timing metrics
        total_time = sum(self.detection_times)
        avg_time = total_time / len(self.detection_times) if self.detection_times else 0.0
        
        return EvaluationMetrics(
            accuracy=basic["accuracy"],
            precision=basic["precision"],
            recall=basic["recall"],
            f1_score=basic["f1_score"],
            specificity=basic["specificity"],
            false_positive_rate=basic["false_positive_rate"],
            false_negative_rate=basic["false_negative_rate"],
            auc_roc=auc,
            avg_detection_time=avg_time,
            total_detection_time=total_time,
            confusion_matrix=cm,
            per_vulnerability_metrics=per_vuln
        )
    
    def reset(self):
        """Reset all stored results."""
        self.ground_truths = []
        self.predictions = []
        self.confidences = []
        self.detection_times = []
        self.vulnerability_types = []


def compare_methods(
    method_results: Dict[str, List[Dict]],
    ground_truths: List[bool]
) -> Dict[str, EvaluationMetrics]:
    """
    Compare multiple detection methods.
    
    Args:
        method_results: Dict mapping method name to list of predictions
        ground_truths: List of ground truth labels
        
    Returns:
        Dict mapping method name to EvaluationMetrics
    """
    comparisons = {}
    
    for method_name, predictions in method_results.items():
        calculator = MetricsCalculator()
        
        for gt, pred in zip(ground_truths, predictions):
            calculator.add_result(
                ground_truth=gt,
                prediction=pred.get('prediction', False),
                confidence=pred.get('confidence', 1.0),
                detection_time=pred.get('detection_time', 0.0),
                vulnerability_type=pred.get('vulnerability_type')
            )
        
        comparisons[method_name] = calculator.calculate()
    
    return comparisons


def generate_comparison_table(
    comparisons: Dict[str, EvaluationMetrics]
) -> str:
    """
    Generate a comparison table in Markdown format.
    
    Args:
        comparisons: Dict mapping method name to metrics
        
    Returns:
        Markdown table string
    """
    headers = ["Method", "Accuracy", "Precision", "Recall", "F1-Score", "FPR", "Avg Time"]
    
    rows = []
    for method, metrics in comparisons.items():
        row = [
            method,
            f"{metrics.accuracy:.4f}",
            f"{metrics.precision:.4f}",
            f"{metrics.recall:.4f}",
            f"{metrics.f1_score:.4f}",
            f"{metrics.false_positive_rate:.4f}",
            f"{metrics.avg_detection_time:.2f}s"
        ]
        rows.append(row)
    
    # Build table
    header_line = "| " + " | ".join(headers) + " |"
    separator = "| " + " | ".join(["---"] * len(headers)) + " |"
    data_lines = ["| " + " | ".join(row) + " |" for row in rows]
    
    return "\n".join([header_line, separator] + data_lines)


if __name__ == "__main__":
    # Example usage
    calculator = MetricsCalculator()
    
    # Simulate some results
    test_data = [
        {"ground_truth": True, "prediction": True, "confidence": 0.9},
        {"ground_truth": True, "prediction": True, "confidence": 0.8},
        {"ground_truth": True, "prediction": False, "confidence": 0.3},
        {"ground_truth": False, "prediction": False, "confidence": 0.1},
        {"ground_truth": False, "prediction": True, "confidence": 0.6},
        {"ground_truth": False, "prediction": False, "confidence": 0.2},
    ]
    
    calculator.add_batch_results(test_data)
    metrics = calculator.calculate()
    
    print("Evaluation Metrics:")
    print(f"  Accuracy: {metrics.accuracy:.4f}")
    print(f"  Precision: {metrics.precision:.4f}")
    print(f"  Recall: {metrics.recall:.4f}")
    print(f"  F1-Score: {metrics.f1_score:.4f}")
    print(f"  Specificity: {metrics.specificity:.4f}")
    print(f"  FPR: {metrics.false_positive_rate:.4f}")
    print(f"  FNR: {metrics.false_negative_rate:.4f}")
    print(f"\nConfusion Matrix:")
    print(f"  TP: {metrics.confusion_matrix.true_positives}")
    print(f"  TN: {metrics.confusion_matrix.true_negatives}")
    print(f"  FP: {metrics.confusion_matrix.false_positives}")
    print(f"  FN: {metrics.confusion_matrix.false_negatives}")
