"""Provider-independent TF-IDF/logistic training, evaluation, and inference."""

import hashlib
import hmac
import json
import math
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Protocol

import joblib
import numpy as np
import sklearn
from django.conf import settings
from django.utils import timezone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    brier_score_loss, confusion_matrix, f1_score, log_loss,
    precision_score, recall_score,
)
from sklearn.pipeline import Pipeline

from .ml_dataset import (
    DatasetError, chronological_split, deduplicate_campaigns,
    load_selection, validate_dataset,
)
from .ml_features import FEATURE_SCHEMA_VERSION, TextDocument


ARTIFACT_SCHEMA = "yphish.classifier.v1"
DEFAULT_THRESHOLD = 0.5
SUPPORTED_FPRS = (0.01, 0.05, 0.10)
MAX_MODEL_BYTES = 250 * 1024 * 1024


class ModelError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ClassificationResult:
    status: str
    code: str
    probability_phishing: float | None = None
    threshold: float | None = None
    version: str = ""
    model_sha256: str = ""


class Predictor(Protocol):
    def predict(self, document: TextDocument) -> ClassificationResult: ...


def _signing_key():
    key = settings.CLASSIFIER_SIGNING_KEY
    if not isinstance(key, str) or len(key) < 32:
        raise ModelError("model_signing_key_missing")
    return key.encode("utf-8")


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _signature(payload):
    unsigned = {key: value for key, value in payload.items() if key != "signature"}
    return hmac.new(_signing_key(), _canonical(unsigned), hashlib.sha256).hexdigest()


def _texts(items):
    return [item.document.as_feature_text() for item in items]


def _labels(items):
    return np.asarray([item.label for item in items], dtype=int)


def _prevalence(items):
    positive = sum(item.label == 1 for item in items)
    return {"count": len(items), "phishing": positive,
            "legitimate": len(items) - positive,
            "phishing_fraction": positive / len(items) if items else None}


def _reliability(y, probabilities):
    bins = []
    total = len(y)
    ece = 0.0
    for index in range(10):
        lower, upper = index / 10, (index + 1) / 10
        mask = (probabilities >= lower) & (probabilities < upper if index < 9 else probabilities <= upper)
        count = int(mask.sum())
        average = float(probabilities[mask].mean()) if count else None
        observed = float(y[mask].mean()) if count else None
        if count:
            ece += count / total * abs(average - observed)
        bins.append({"lower": lower, "upper": upper, "count": count,
                     "mean_probability": average, "observed_fraction": observed})
    return {"brier": float(brier_score_loss(y, probabilities)),
            "log_loss": float(log_loss(y, probabilities, labels=[0, 1])),
            "expected_calibration_error": ece, "reliability_bins": bins}


def _split_report(items, probabilities, threshold):
    labels = _labels(items)
    predictions = (probabilities >= threshold).astype(int)
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    return {
        "prevalence": _prevalence(items),
        "date_min": min(item.decision_at for item in items).isoformat(),
        "date_max": max(item.decision_at for item in items).isoformat(),
        "threshold": threshold,
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "confusion_matrix": matrix.tolist(),
        "calibration": _reliability(labels, probabilities),
    }


def _recall_at_supported_fprs(calibration, calibration_probabilities, test, test_probabilities):
    calibration_labels, test_labels = _labels(calibration), _labels(test)
    negatives = sorted((float(value) for value in calibration_probabilities[calibration_labels == 0]), reverse=True)
    test_negatives = int((test_labels == 0).sum())
    result = {}
    for target in SUPPORTED_FPRS:
        key = f"{target:.2f}"
        required = math.ceil(1 / target)
        if len(negatives) < required or test_negatives < required:
            result[key] = {"supported": False, "reason": "insufficient_negative_support",
                           "required_negatives_per_split": required,
                           "calibration_negatives": len(negatives), "test_negatives": test_negatives}
            continue
        allowed = math.floor(target * len(negatives))
        boundary = negatives[allowed] if allowed < len(negatives) else 0.0
        threshold = float(np.nextafter(boundary, np.inf))
        predictions = test_probabilities >= threshold
        positive_mask = test_labels == 1
        negative_mask = ~positive_mask
        result[key] = {
            "supported": True, "threshold_from_calibration": threshold,
            "test_recall": float(predictions[positive_mask].mean()),
            "test_false_positive_rate": float(predictions[negative_mask].mean()),
            "calibration_negative_count": len(negatives),
            "test_negative_count": test_negatives,
        }
    return result


def evaluate_model(model, splits, selection, *, original_prevalence, duplicates_removed):
    calibration, test = splits["calibration"], splits["test"]
    calibration_probabilities = model.predict_proba(_texts(calibration))[:, 1]
    test_probabilities = model.predict_proba(_texts(test))[:, 1]
    return {
        "evaluation_kind": "held_out_chronological",
        "dataset_kind": selection["source_kind"],
        "original_prevalence": original_prevalence,
        "duplicates_removed": duplicates_removed,
        "split_cutoffs": {"train_before": selection["train_before"],
                          "calibration_before": selection["calibration_before"]},
        "splits": {
            "train": {"prevalence": _prevalence(splits["train"]),
                      "date_min": min(item.decision_at for item in splits["train"]).isoformat(),
                      "date_max": max(item.decision_at for item in splits["train"]).isoformat()},
            "calibration": _split_report(calibration, calibration_probabilities, DEFAULT_THRESHOLD),
            "test": _split_report(test, test_probabilities, DEFAULT_THRESHOLD),
        },
        "recall_at_false_positive_rates": _recall_at_supported_fprs(
            calibration, calibration_probabilities, test, test_probabilities,
        ),
    }


def train_from_selection(selection_path=None):
    selection, path = load_selection(selection_path)
    raw_examples = validate_dataset(path, selection)
    examples, duplicates_removed = deduplicate_campaigns(raw_examples)
    splits = chronological_split(examples, selection)
    base = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True, strip_accents="unicode", ngram_range=(1, 2),
            min_df=1, max_features=50_000, sublinear_tf=True,
        )),
        ("logistic", LogisticRegression(
            solver="liblinear", max_iter=1000, random_state=42,
        )),
    ])
    try:
        base.fit(_texts(splits["train"]), _labels(splits["train"]))
        # FrozenEstimator prevents a second fit of TF-IDF or logistic regression.
        model = CalibratedClassifierCV(FrozenEstimator(base), method="sigmoid")
        model.fit(_texts(splits["calibration"]), _labels(splits["calibration"]))
    except (ValueError, RuntimeError):
        raise DatasetError("Model fitting failed for the selected dataset") from None
    metrics = evaluate_model(model, splits, selection,
                             original_prevalence=_prevalence(raw_examples), duplicates_removed=duplicates_removed)
    return model, metrics, selection


def _version(version):
    if not isinstance(version, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", version):
        raise ModelError("model_version_invalid")
    return version


def export_model(model, metrics, selection, *, version):
    version = _version(version)
    root = Path(settings.CLASSIFIER_MODEL_ROOT).resolve()
    root.mkdir(parents=True, exist_ok=True)
    target = root / version
    if target.exists():
        raise ModelError("model_version_exists")
    temporary = Path(tempfile.mkdtemp(prefix=".model-", dir=root))
    try:
        model_file = temporary / "model.joblib"
        joblib.dump(model, model_file, compress=3)
        if model_file.stat().st_size > MAX_MODEL_BYTES:
            raise ModelError("model_artifact_too_large")
        digest = hashlib.sha256(model_file.read_bytes()).hexdigest()
        manifest = {
            "schema": ARTIFACT_SCHEMA, "version": version,
            "feature_schema": FEATURE_SCHEMA_VERSION,
            "sklearn_version": sklearn.__version__,
            "dataset_kind": selection["source_kind"],
            "dataset_sha256": selection["dataset_sha256"],
            "selection_signature": selection["signature"],
            "authorization_reference": selection["authorization_reference"],
            "model_sha256": digest, "threshold": DEFAULT_THRESHOLD,
            "trained_at": timezone.now().isoformat(), "metrics": metrics,
        }
        manifest["signature"] = _signature(manifest)
        (temporary / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8",
        )
        os.replace(temporary, target)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return target, manifest


@lru_cache(maxsize=4)
def _trusted_joblib(path, digest):
    try:
        return joblib.load(path)
    except Exception:
        raise ModelError("model_load_failed") from None


def load_model(version=None):
    version = version if version is not None else settings.CLASSIFIER_ACTIVE_VERSION
    if not version:
        raise ModelError("model_not_configured")
    version = _version(version)
    root = Path(settings.CLASSIFIER_MODEL_ROOT).resolve()
    directory = (root / version).resolve()
    if directory.parent != root:
        raise ModelError("model_path_invalid")
    manifest_file, model_file = directory / "manifest.json", directory / "model.joblib"
    try:
        if manifest_file.stat().st_size > 2_000_000 or model_file.stat().st_size > MAX_MODEL_BYTES:
            raise ModelError("model_artifact_too_large")
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ModelError("model_missing") from None
    if not isinstance(manifest, dict) or manifest.get("schema") != ARTIFACT_SCHEMA or manifest.get("version") != version:
        raise ModelError("model_schema_incompatible")
    signature = manifest.get("signature")
    if not isinstance(signature, str) or not hmac.compare_digest(signature, _signature(manifest)):
        raise ModelError("model_signature_invalid")
    if manifest.get("feature_schema") != FEATURE_SCHEMA_VERSION:
        raise ModelError("model_schema_incompatible")
    if manifest.get("sklearn_version") != sklearn.__version__:
        raise ModelError("model_library_incompatible")
    if manifest.get("dataset_kind") == "synthetic" and not settings.CLASSIFIER_ALLOW_SYNTHETIC:
        raise ModelError("model_synthetic_disabled")
    if manifest.get("dataset_kind") not in {"synthetic", "curated"}:
        raise ModelError("model_schema_incompatible")
    digest = hashlib.sha256(model_file.read_bytes()).hexdigest()
    if not hmac.compare_digest(digest, str(manifest.get("model_sha256", ""))):
        raise ModelError("model_hash_mismatch")
    threshold = manifest.get("threshold")
    if not isinstance(threshold, (float, int)) or not 0 < threshold < 1:
        raise ModelError("model_schema_incompatible")
    return _trusted_joblib(str(model_file), digest), manifest


def evaluate_from_selection(version):
    selection, path = load_selection()
    model, manifest = load_model(version)
    if (manifest.get("dataset_sha256") != selection["dataset_sha256"]
            or manifest.get("selection_signature") != selection["signature"]
            or manifest.get("dataset_kind") != selection["source_kind"]):
        raise ModelError("model_selection_incompatible")
    original = validate_dataset(path, selection)
    unique, duplicates_removed = deduplicate_campaigns(original)
    splits = chronological_split(unique, selection)
    metrics = evaluate_model(
        model, splits, selection, original_prevalence=_prevalence(original),
        duplicates_removed=duplicates_removed,
    )
    return {"version": version, "matches_exported_report": metrics == manifest.get("metrics"),
            "metrics": metrics}


def classify_document(document: TextDocument):
    if not document.has_content():
        return ClassificationResult("unavailable", "empty_content")
    try:
        model, manifest = load_model()
        probability = float(model.predict_proba([document.as_feature_text()])[0, 1])
        if not math.isfinite(probability) or not 0 <= probability <= 1:
            raise ModelError("model_prediction_invalid")
        return ClassificationResult(
            "observed", "", probability, float(manifest["threshold"]),
            manifest["version"], manifest["model_sha256"],
        )
    except ModelError as exc:
        return ClassificationResult("unavailable", exc.code)
    except Exception:
        return ClassificationResult("unavailable", "model_prediction_failed")
