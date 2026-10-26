"""Signed, explicit dataset selection and leakage-resistant corpus validation."""

import hashlib
import hmac
import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from .ml_features import TextDocument, MAX_TEXT_CHARS


SELECTION_SCHEMA = "yphish.dataset-selection.v1"
DATASET_FIELDS = {
    "sample_id", "subject", "body_text", "label", "label_source",
    "campaign_id", "content_captured_at", "decision_at", "label_assigned_at",
}
LABELS = {"legitimate": 0, "phishing": 1}
MAX_DATASET_BYTES = 100 * 1024 * 1024
MAX_ROWS = 100_000


class DatasetError(ValueError):
    pass


@dataclass(frozen=True)
class TrainingExample:
    sample_id: str
    document: TextDocument
    label: int
    campaign_id: str
    content_captured_at: datetime
    decision_at: datetime
    label_assigned_at: datetime


def _timestamp(value, name):
    if not isinstance(value, str):
        raise DatasetError(f"{name} must be an ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise DatasetError(f"{name} is invalid") from None
    if timezone.is_naive(parsed):
        raise DatasetError(f"{name} must include a timezone")
    return parsed


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _key():
    key = settings.CLASSIFIER_APPROVAL_KEY
    if not isinstance(key, str) or len(key) < 32:
        raise DatasetError("CLASSIFIER_APPROVAL_KEY must contain at least 32 characters")
    return key.encode("utf-8")


def sign_selection(payload):
    unsigned = {name: value for name, value in payload.items() if name != "signature"}
    return hmac.new(_key(), _canonical(unsigned), hashlib.sha256).hexdigest()


def create_selection(*, dataset_path, selection_path, source_kind, approved_by,
                     authorization_reference, expires_at, train_before,
                     calibration_before, private_mailbox_content):
    """Operator action; caller attests that dataset selection was authorized."""
    dataset_path = Path(dataset_path).resolve()
    selection_path = Path(selection_path).resolve()
    if dataset_path.parent != selection_path.parent or not re.fullmatch(r"[A-Za-z0-9_.-]+\.jsonl", dataset_path.name):
        raise DatasetError("Dataset and selection must share a directory; dataset must be JSONL")
    if source_kind not in {"curated", "synthetic"}:
        raise DatasetError("source_kind must be curated or synthetic")
    if source_kind == "synthetic" and not settings.DEBUG:
        raise DatasetError("Synthetic training requires DJANGO_DEBUG=1")
    if not approved_by or not authorization_reference:
        raise DatasetError("Approver and authorization reference are required")
    if not isinstance(private_mailbox_content, bool):
        raise DatasetError("private_mailbox_content must be explicit")
    if not dataset_path.is_file() or dataset_path.stat().st_size > MAX_DATASET_BYTES:
        raise DatasetError("Dataset is missing or exceeds the byte limit")
    digest = hashlib.sha256(dataset_path.read_bytes()).hexdigest()
    now = timezone.now()
    expiry = _timestamp(expires_at, "expires_at")
    train = _timestamp(train_before, "train_before")
    calibration = _timestamp(calibration_before, "calibration_before")
    if expiry <= now or train >= calibration:
        raise DatasetError("Selection expiry or chronological cutoffs are invalid")
    payload = {
        "schema": SELECTION_SCHEMA, "dataset_file": dataset_path.name,
        "dataset_sha256": digest, "source_kind": source_kind,
        "private_mailbox_content": private_mailbox_content,
        "approved_by": approved_by, "authorization_reference": authorization_reference,
        "approved_at": now.isoformat(), "expires_at": expiry.isoformat(),
        "train_before": train.isoformat(), "calibration_before": calibration.isoformat(),
    }
    payload["signature"] = sign_selection(payload)
    if selection_path.exists():
        raise DatasetError("Selection file already exists; choose a new approval file")
    selection_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def load_selection(path=None):
    path = Path(path or settings.CLASSIFIER_DATASET_SELECTION_FILE) if (path or settings.CLASSIFIER_DATASET_SELECTION_FILE) else None
    if not path:
        raise DatasetError("CLASSIFIER_DATASET_SELECTION_FILE is required")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise DatasetError("Dataset selection file is unavailable or invalid") from None
    if not isinstance(payload, dict) or payload.get("schema") != SELECTION_SCHEMA:
        raise DatasetError("Dataset selection schema is incompatible")
    signature = payload.get("signature", "")
    if not isinstance(signature, str) or not hmac.compare_digest(signature, sign_selection(payload)):
        raise DatasetError("Dataset selection signature is invalid")
    if payload.get("source_kind") not in {"curated", "synthetic"}:
        raise DatasetError("Dataset selection kind is invalid")
    if payload["source_kind"] == "synthetic" and not settings.DEBUG:
        raise DatasetError("Synthetic training requires DJANGO_DEBUG=1")
    if not isinstance(payload.get("private_mailbox_content"), bool):
        raise DatasetError("Dataset privacy attestation is missing")
    if not payload.get("approved_by") or not payload.get("authorization_reference"):
        raise DatasetError("Dataset authorization is missing")
    approved_at = _timestamp(payload.get("approved_at"), "approved_at")
    if approved_at > timezone.now():
        raise DatasetError("Dataset approval timestamp is in the future")
    if _timestamp(payload.get("expires_at"), "expires_at") <= timezone.now():
        raise DatasetError("Dataset selection authorization has expired")
    train = _timestamp(payload.get("train_before"), "train_before")
    calibration = _timestamp(payload.get("calibration_before"), "calibration_before")
    if train >= calibration:
        raise DatasetError("Dataset chronological cutoffs are invalid")
    name = payload.get("dataset_file")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+\.jsonl", name):
        raise DatasetError("Dataset filename is invalid")
    dataset_path = path.resolve().parent / name
    if not dataset_path.is_file() or dataset_path.stat().st_size > MAX_DATASET_BYTES:
        raise DatasetError("Selected dataset is unavailable or oversized")
    approved_digest = payload.get("dataset_sha256")
    if not isinstance(approved_digest, str) or not hmac.compare_digest(hashlib.sha256(dataset_path.read_bytes()).hexdigest(), approved_digest):
        raise DatasetError("Selected dataset digest differs from approval")
    return payload, dataset_path


def validate_dataset(path, selection):
    examples = []
    seen_ids = set()
    source_kind = selection["source_kind"]
    try:
        with Path(path).open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if line_number > MAX_ROWS or len(line) > 1_000_000:
                    raise DatasetError("Dataset exceeds row or line limit")
                try:
                    row = json.loads(line)
                except ValueError:
                    raise DatasetError(f"Invalid JSON at line {line_number}") from None
                if not isinstance(row, dict) or set(row) != DATASET_FIELDS:
                    raise DatasetError(f"Dataset schema or forbidden feature at line {line_number}")
                sample_id = row["sample_id"]
                if not isinstance(sample_id, str) or not sample_id or len(sample_id) > 200 or sample_id in seen_ids:
                    raise DatasetError(f"Invalid or duplicate sample ID at line {line_number}")
                seen_ids.add(sample_id)
                label = row["label"]
                if not isinstance(label, str) or label not in LABELS:
                    raise DatasetError(f"Missing or invalid label at line {line_number}")
                if not isinstance(row["label_source"], str) or row["label_source"] not in ({"synthetic"} if source_kind == "synthetic" else {"curated_review", "incident_confirmation"}):
                    raise DatasetError(f"Unapproved label source at line {line_number}")
                subject, body = row["subject"], row["body_text"]
                if not isinstance(subject, str) or not isinstance(body, str) or len(subject) > MAX_TEXT_CHARS or len(body) > MAX_TEXT_CHARS:
                    raise DatasetError(f"Invalid extracted content at line {line_number}")
                document = TextDocument(subject, body)
                if not document.has_content():
                    raise DatasetError(f"Empty content at line {line_number}")
                campaign = row["campaign_id"]
                if not isinstance(campaign, str) or len(campaign) > 200:
                    raise DatasetError(f"Invalid campaign ID at line {line_number}")
                captured = _timestamp(row["content_captured_at"], "content_captured_at")
                decision = _timestamp(row["decision_at"], "decision_at")
                assigned = _timestamp(row["label_assigned_at"], "label_assigned_at")
                if captured > decision or assigned < decision:
                    raise DatasetError(f"Content or label chronology is invalid at line {line_number}")
                if assigned > timezone.now():
                    raise DatasetError(f"Label is not yet available at line {line_number}")
                examples.append(TrainingExample(sample_id, document, LABELS[label], campaign, captured, decision, assigned))
    except UnicodeDecodeError:
        raise DatasetError("Dataset must be UTF-8") from None
    if not examples:
        raise DatasetError("Dataset is empty")
    return examples


def deduplicate_campaigns(examples):
    """One earliest representative per linked campaign/content cluster."""
    parent = list(range(len(examples)))

    def find(index):
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left, right):
        parent[find(right)] = find(left)

    by_campaign, by_content = {}, {}
    for index, item in enumerate(examples):
        if item.campaign_id:
            if item.campaign_id in by_campaign:
                union(index, by_campaign[item.campaign_id])
            by_campaign[item.campaign_id] = index
        normalized_text = re.sub(r"\s+", " ", item.document.as_feature_text().casefold()).strip()
        digest = hashlib.sha256(normalized_text.encode("utf-8")).hexdigest()
        if digest in by_content:
            union(index, by_content[digest])
        by_content[digest] = index
    groups = {}
    for index, item in enumerate(examples):
        groups.setdefault(find(index), []).append(item)
    representatives = []
    for members in groups.values():
        if len({item.label for item in members}) != 1:
            raise DatasetError("Conflicting labels occur within a campaign or duplicate-content group")
        representatives.append(min(members, key=lambda item: (item.decision_at, item.sample_id)))
    representatives.sort(key=lambda item: (item.decision_at, item.sample_id))
    return representatives, len(examples) - len(representatives)


def chronological_split(examples, selection):
    train_before = _timestamp(selection["train_before"], "train_before")
    calibration_before = _timestamp(selection["calibration_before"], "calibration_before")
    splits = {"train": [], "calibration": [], "test": []}
    for item in examples:
        name = "train" if item.decision_at < train_before else (
            "calibration" if item.decision_at < calibration_before else "test"
        )
        if name == "train" and item.label_assigned_at >= train_before:
            raise DatasetError("Training label was unavailable at the training cutoff")
        if name == "calibration" and item.label_assigned_at >= calibration_before:
            raise DatasetError("Calibration label was unavailable at the calibration cutoff")
        splits[name].append(item)
    for name, minimum in (("train", 2), ("calibration", 2), ("test", 1)):
        counts = Counter(item.label for item in splits[name])
        if counts[0] < minimum or counts[1] < minimum:
            raise DatasetError(f"{name} split needs at least {minimum} examples of each class")
    return splits
