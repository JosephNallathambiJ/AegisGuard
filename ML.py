"""
ML.py - Machine Learning Inference, Deduplication & False-Positive Layer
Utilizes scikit-learn and PyTorch models for:
- Finding prioritization
- Severity estimation
- Confidence estimation
- Duplicate finding detection
- False-positive reduction

CRITICAL CONSTRAINT:
The ML model strictly analyzes passive scanner findings. It never autonomously
decides to weaponize, generate payloads, bypass security controls, increase request
volume, or label unconfirmed findings as 'confirmed'.
"""

import os
import json
import hashlib
from typing import Dict, List, Any, Optional, Tuple
import numpy as np

try:
    import joblib
except ImportError:
    joblib = None

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

FEATURE_NAMES = [
    "missing_hsts",
    "missing_csp",
    "missing_xfo",
    "missing_xcto",
    "cookie_unsecured",
    "cookie_no_httponly",
    "cors_wildcard",
    "banner_exposed",
    "weak_tls",
    "dangerous_methods",
    "debug_info_exposed",
    "plain_http_open",
    "epss_proxy"
]

SEVERITY_CLASSES = ["Informational", "Low", "Medium", "High", "Critical"]
SEVERITY_WEIGHTS = {"Informational": 1, "Low": 2, "Medium": 5, "High": 8, "Critical": 10}

if TORCH_AVAILABLE:
    class VulnerabilityClassifierNN(nn.Module):
        """PyTorch Multi-Layer Perceptron for Vulnerability Prioritization."""
        def __init__(self, input_dim: int = 13, num_classes: int = 5):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(input_dim, 64),
                nn.BatchNorm1d(64),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(64, 32),
                nn.BatchNorm1d(32),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(32, num_classes)
            )

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            return self.net(x)
else:
    VulnerabilityClassifierNN = None


class VulnerabilityMLPipeline:
    """
    ML Inference Engine for Finding Prioritization, Deduplication & False-Positive Filtering.
    """
    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        self.baseline_model = None
        self.preprocessor = None
        self.neural_model = None
        self.metrics = {}
        self.load_models()

    def load_models(self) -> bool:
        """Attempts to load trained scikit-learn and PyTorch artifacts."""
        baseline_path = os.path.join(self.models_dir, "baseline_model.joblib")
        preprocessor_path = os.path.join(self.models_dir, "preprocessor.joblib")
        neural_path = os.path.join(self.models_dir, "neural_model.pth")
        metrics_path = os.path.join(self.models_dir, "metrics.json")

        loaded_any = False

        if joblib and os.path.exists(baseline_path) and os.path.exists(preprocessor_path):
            try:
                self.baseline_model = joblib.load(baseline_path)
                self.preprocessor = joblib.load(preprocessor_path)
                loaded_any = True
            except Exception as e:
                print(f"[ML.py] Could not load scikit-learn model: {e}")

        if TORCH_AVAILABLE and os.path.exists(neural_path):
            try:
                model = VulnerabilityClassifierNN(input_dim=len(FEATURE_NAMES), num_classes=len(SEVERITY_CLASSES))
                model.load_state_dict(torch.load(neural_path, map_location=torch.device("cpu")))
                model.eval()
                self.neural_model = model
                loaded_any = True
            except Exception as e:
                print(f"[ML.py] Could not load PyTorch neural model: {e}")

        if os.path.exists(metrics_path):
            try:
                with open(metrics_path, "r", encoding="utf-8") as f:
                    self.metrics = json.load(f)
            except Exception:
                pass

        return loaded_any

    def is_trained(self) -> bool:
        return (self.baseline_model is not None) or (self.neural_model is not None)

    def extract_features(self, finding: Dict[str, Any], all_findings: List[Dict[str, Any]]) -> np.ndarray:
        """Converts finding attributes into a normalized feature vector."""
        feat = {k: 0.0 for k in FEATURE_NAMES}

        title = finding.get("title", "").lower()
        cvss = float(finding.get("cvss") or finding.get("cvss_score") or 4.0)

        if "strict-transport-security" in title: feat["missing_hsts"] = 1.0
        if "content-security-policy" in title: feat["missing_csp"] = 1.0
        if "x-frame-options" in title: feat["missing_xfo"] = 1.0
        if "x-content-type-options" in title: feat["missing_xcto"] = 1.0
        if "secure" in title and "cookie" in title: feat["cookie_unsecured"] = 1.0
        if "httponly" in title: feat["cookie_no_httponly"] = 1.0
        if "cors" in title or "wildcard" in title: feat["cors_wildcard"] = 1.0
        if "server" in title or "banner" in title or "technology" in title: feat["banner_exposed"] = 1.0
        if "tls" in title or "ssl" in title: feat["weak_tls"] = 1.0
        if "method" in title: feat["dangerous_methods"] = 1.0
        if "trace" in title or "error" in title or "debug" in title: feat["debug_info_exposed"] = 1.0
        if "plaintext" in title or "redirect" in title: feat["plain_http_open"] = 1.0

        feat["epss_proxy"] = min(round((cvss / 10.0) ** 2, 4), 1.0)
        return np.array([[feat[name] for name in FEATURE_NAMES]], dtype=np.float32)

    def detect_duplicates(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicates repeated scanner observations across identical endpoints and parameters.
        Prevents redundant noise in bug-bounty triage.
        """
        seen_hashes = set()
        deduped = []

        for f in findings:
            sig = f"{f.get('title')}:{f.get('cwe')}:{f.get('endpoint')}:{f.get('parameter')}"
            f_hash = hashlib.md5(sig.encode("utf-8")).hexdigest()

            if f_hash in seen_hashes:
                f_copy = dict(f)
                f_copy["is_duplicate"] = True
                f_copy["duplicate_signature"] = f_hash
                deduped.append(f_copy)
            else:
                seen_hashes.add(f_hash)
                f_copy = dict(f)
                f_copy["is_duplicate"] = False
                f_copy["duplicate_signature"] = f_hash
                deduped.append(f_copy)

        return deduped

    def predict_finding_assessment(
        self,
        finding: Dict[str, Any],
        all_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Estimates severity, confidence, false-positive probability, and priority score.
        IMPORTANT: Never changes verification_status to 'confirmed'.
        """
        features_vec = self.extract_features(finding, all_findings)
        cvss = float(finding.get("cvss") or finding.get("cvss_score") or 4.0)
        base_sev = finding.get("severity", "Low")
        base_conf = float(finding.get("confidence", 0.90))

        predicted_sev = base_sev
        confidence = base_conf
        source = "Defensive Heuristics"
        is_fp = False

        # 1. Scikit-Learn Model
        if self.baseline_model is not None:
            try:
                processed_vec = self.preprocessor.transform(features_vec) if self.preprocessor else features_vec
                pred_label = self.baseline_model.predict(processed_vec)[0]
                probs = self.baseline_model.predict_proba(processed_vec)[0]
                classes = list(self.baseline_model.classes_)
                class_idx = classes.index(pred_label)

                if isinstance(pred_label, (int, np.integer)) or (isinstance(pred_label, str) and pred_label.isdigit()):
                    idx = int(pred_label)
                    if 0 <= idx < len(SEVERITY_CLASSES):
                        predicted_sev = SEVERITY_CLASSES[idx]
                    else:
                        predicted_sev = str(pred_label)
                else:
                    predicted_sev = str(pred_label)

                confidence = float(probs[class_idx])
                source = "Scikit-Learn (RandomForest)"
                # False positive indicator for trivial disclosures
                is_fp = bool(predicted_sev in ("Informational", "Low") and confidence > 0.88 and cvss < 2.5)
            except Exception:
                pass

        # 2. PyTorch Model
        elif TORCH_AVAILABLE and self.neural_model is not None:
            try:
                with torch.no_grad():
                    inputs = torch.tensor(features_vec, dtype=torch.float32)
                    logits = self.neural_model(inputs)
                    probs = torch.softmax(logits, dim=1).numpy()[0]
                    pred_idx = int(np.argmax(probs))
                    predicted_sev = SEVERITY_CLASSES[pred_idx]
                    confidence = float(probs[pred_idx])
                    source = "PyTorch MLP"
                    is_fp = bool(predicted_sev == "Informational" and confidence > 0.88 and cvss < 2.5)
            except Exception:
                pass

        # Compute Prioritization Score (0 - 100)
        weight = SEVERITY_WEIGHTS.get(predicted_sev, 3)
        priority_score = min(100, int((weight * 7.0) + (cvss * 2.5) + (confidence * 5.0)))

        return {
            "ml_adjusted_severity": str(predicted_sev),
            "ml_confidence": float(round(confidence, 2)),
            "priority_score": int(priority_score),
            "is_likely_false_positive": bool(is_fp),
            "inference_source": str(source)
        }

    def enrich_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enriches findings with deduplication, ML prioritization, and false-positive filtering.
        """
        # 1. Run deduplication
        deduped = self.detect_duplicates(findings)

        enriched = []
        for f in deduped:
            assessment = self.predict_finding_assessment(f, deduped)
            f_copy = dict(f)
            f_copy["ml_assessment"] = assessment
            f_copy["severity"] = assessment["ml_adjusted_severity"]
            f_copy["confidence"] = assessment["ml_confidence"]
            f_copy["priority_score"] = assessment["priority_score"]

            # If marked likely false-positive, update verification_status without ever claiming confirmed
            if assessment["is_likely_false_positive"]:
                f_copy["verification_status"] = "false_positive"
                f_copy["false_positive_risk"] = "High"
            else:
                f_copy["false_positive_risk"] = "Low"

            enriched.append(f_copy)

        # 2. Sort by priority score descending (Critical & high-impact first)
        enriched.sort(key=lambda x: x.get("priority_score", 0), reverse=True)
        return enriched
