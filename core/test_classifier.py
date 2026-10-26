"""Synthetic classifier pipeline tests; no claim of detection performance."""

import json
import tempfile
from io import StringIO
from datetime import datetime, timedelta, timezone as dt_timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from unittest.mock import patch

import numpy as np
from django.core.management import call_command
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.utils import timezone

from .analysis_runtime import run_analysis
from .gmail_runtime import ingest_message
from .ml_dataset import (
    DatasetError, chronological_split, create_selection, deduplicate_campaigns,
    load_selection, validate_dataset,
)
from .ml_features import TextDocument, extract_document
from .ml_pipeline import (
    ModelError, classify_document, evaluate_from_selection, export_model,
    load_model, train_from_selection,
)
from .models import AnalysisRun, Artifact, EmailCase, Evidence, Mailbox, Organization
from .test_gmail import FakeGmail


def _stamp(year, month, day):
    return datetime(year, month, day, tzinfo=dt_timezone.utc).isoformat()


def synthetic_rows():
    rows = []
    for split, (year, month) in {"train": (2025, 12), "calibration": (2026, 1), "test": (2026, 2)}.items():
        for index in range(20):
            phishing = index % 2 == 0
            day = index + 1
            rows.append({
                "sample_id": f"gmail-secret-id-{split}-{index}",
                "subject": f"{'Urgent account verification' if phishing else 'Team meeting notes'} {index:02d}",
                "body_text": (
                    f"{'verify password login credential request' if phishing else 'project agenda report routine update'} "
                    f"{split}onlyword message{index:02d}"
                ),
                "label": "phishing" if phishing else "legitimate",
                "label_source": "synthetic", "campaign_id": f"campaign-{split}-{index}",
                "content_captured_at": _stamp(year, month, day),
                "decision_at": _stamp(year, month, day),
                "label_assigned_at": _stamp(year, month, day + 1),
            })
    return rows


@override_settings(DEBUG=True, CLASSIFIER_APPROVAL_KEY="A" * 40,
                   CLASSIFIER_SIGNING_KEY="B" * 40, CLASSIFIER_ALLOW_SYNTHETIC=True)
class ClassifierPipelineTests(SimpleTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dataset = self.root / "training.jsonl"
        self.selection_path = self.root / "selection.json"
        self.rows = synthetic_rows()
        self._write_rows()
        create_selection(
            dataset_path=self.dataset, selection_path=self.selection_path,
            source_kind="synthetic", approved_by="synthetic-test",
            authorization_reference="synthetic-fixture-only",
            expires_at=(timezone.now() + timedelta(days=7)).isoformat(),
            train_before=_stamp(2026, 1, 1), calibration_before=_stamp(2026, 2, 1),
            private_mailbox_content=False,
        )

    def _write_rows(self):
        self.dataset.write_text("\n".join(json.dumps(row, sort_keys=True) for row in self.rows) + "\n", encoding="utf-8")

    def _selection(self):
        return load_selection(self.selection_path)[0]

    def test_reproducibility_training_only_vocabulary_and_metrics(self):
        model_a, metrics_a, selection = train_from_selection(self.selection_path)
        model_b, metrics_b, _ = train_from_selection(self.selection_path)
        documents = [TextDocument("Urgent account verification", "verify password request")]
        features = [document.as_feature_text() for document in documents]
        self.assertTrue(np.allclose(model_a.predict_proba(features), model_b.predict_proba(features)))
        vocabulary = model_a.calibrated_classifiers_[0].estimator.named_steps["tfidf"].vocabulary_
        self.assertNotIn("calibrationonlyword", vocabulary)
        self.assertNotIn("testonlyword", vocabulary)
        self.assertNotIn("gmail-secret-id", vocabulary)
        self.assertEqual(metrics_a, metrics_b)
        self.assertEqual(metrics_a["splits"]["test"]["prevalence"]["count"], 20)
        self.assertEqual(len(metrics_a["splits"]["test"]["confusion_matrix"]), 2)
        self.assertIn("brier", metrics_a["splits"]["test"]["calibration"])
        self.assertTrue(metrics_a["recall_at_false_positive_rates"]["0.10"]["supported"])
        self.assertFalse(metrics_a["recall_at_false_positive_rates"]["0.01"]["supported"])
        self.assertEqual(selection["source_kind"], "synthetic")

    def test_signed_export_evaluation_and_incompatible_artifact(self):
        model, metrics, selection = train_from_selection(self.selection_path)
        with self.settings(CLASSIFIER_MODEL_ROOT=self.root / "models",
                           CLASSIFIER_DATASET_SELECTION_FILE=str(self.selection_path),
                           CLASSIFIER_ACTIVE_VERSION="synthetic-v1"):
            target, manifest = export_model(model, metrics, selection, version="synthetic-v1")
            self.assertTrue((target / "model.joblib").exists())
            self.assertEqual(manifest["feature_schema"], "mime-content-v1")
            self.assertTrue(evaluate_from_selection("synthetic-v1")["matches_exported_report"])
            result = classify_document(TextDocument("Urgent account", "verify password"))
            self.assertEqual(result.status, "observed")
            self.assertGreaterEqual(result.probability_phishing, 0)
            with self.assertRaises(ModelError):
                export_model(model, metrics, selection, version="synthetic-v1")
            with self.settings(CLASSIFIER_ALLOW_SYNTHETIC=False):
                self.assertEqual(classify_document(TextDocument("hello", "message")).code,
                                 "model_synthetic_disabled")
            (target / "model.joblib").write_bytes(b"tampered")
            self.assertEqual(classify_document(TextDocument("hello", "message")).code,
                             "model_hash_mismatch")

    def test_training_and_evaluation_management_commands(self):
        with self.settings(CLASSIFIER_MODEL_ROOT=self.root / "models",
                           CLASSIFIER_DATASET_SELECTION_FILE=str(self.selection_path)):
            training_output = StringIO()
            call_command("train_classifier", model_version="cli-v1", stdout=training_output)
            self.assertIn("Exported classifier cli-v1", training_output.getvalue())
            evaluation_output = StringIO()
            call_command("evaluate_classifier", model_version="cli-v1", stdout=evaluation_output)
            report = json.loads(evaluation_output.getvalue())
            self.assertTrue(report["matches_exported_report"])

    def test_missing_labels_empty_content_and_forbidden_metadata(self):
        selection = self._selection()
        cases = [
            {"label": ""}, {"subject": "", "body_text": ""},
            {"gmail_label_ids": ["SPAM"]}, {"gmail_message_id": "id"},
            {"organization_id": "org"}, {"analyst_disposition": "phishing"},
            {"future_indicator": "bad"}, {"label_source": "gmail_spam"},
            {"label_assigned_at": _stamp(2999, 1, 1)},
            {"content_captured_at": _stamp(2026, 10, 1)},
        ]
        for change in cases:
            altered = [dict(row) for row in self.rows]
            altered[0].update(change)
            self.dataset.write_text("\n".join(json.dumps(row) for row in altered) + "\n", encoding="utf-8")
            with self.assertRaises(DatasetError):
                validate_dataset(self.dataset, selection)
        self.assertEqual(classify_document(TextDocument("", "")).code, "empty_content")

    def test_selection_signature_digest_and_cutoff_guards(self):
        selection = self._selection()
        selection["train_before"] = _stamp(2026, 3, 1)
        self.selection_path.write_text(json.dumps(selection), encoding="utf-8")
        with self.assertRaises(DatasetError):
            load_selection(self.selection_path)
        self.selection_path.unlink()
        create_selection(
            dataset_path=self.dataset, selection_path=self.selection_path,
            source_kind="synthetic", approved_by="synthetic-test",
            authorization_reference="synthetic-fixture-only",
            expires_at=(timezone.now() + timedelta(days=7)).isoformat(),
            train_before=_stamp(2026, 1, 1), calibration_before=_stamp(2026, 2, 1),
            private_mailbox_content=False,
        )
        self.dataset.write_text(self.dataset.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        with self.assertRaises(DatasetError):
            load_selection(self.selection_path)

    def test_campaign_duplicate_and_future_label_leakage(self):
        selection = self._selection()
        examples = validate_dataset(self.dataset, selection)
        duplicate = examples[0].__class__(
            "different-id", examples[0].document, examples[0].label,
            examples[0].campaign_id, examples[0].content_captured_at,
            _stamp_datetime(2026, 2, 10), _stamp_datetime(2026, 2, 11),
        )
        unique, removed = deduplicate_campaigns([*examples, duplicate])
        self.assertEqual(removed, 1)
        splits = chronological_split(unique, selection)
        self.assertLess(max(item.decision_at for item in splits["train"]),
                        min(item.decision_at for item in splits["calibration"]))
        future = examples[0].__class__(
            examples[0].sample_id, examples[0].document, examples[0].label,
            examples[0].campaign_id, examples[0].content_captured_at,
            examples[0].decision_at, _stamp_datetime(2026, 2, 10),
        )
        with self.assertRaises(DatasetError):
            chronological_split([future, *examples[1:]], selection)

    def test_mime_extraction_ignores_provider_and_header_metadata(self):
        message = EmailMessage()
        message["From"] = "Sender <sender@tenant.example>"
        message["Subject"] = "Review the invoice"
        message["X-Gmail-Message-ID"] = "provider-secret-id"
        message["Authentication-Results"] = "mx.example; spf=pass"
        message.set_content("Please review the attached invoice.")
        parsed = BytesParser(policy=policy.default).parsebytes(message.as_bytes())
        feature_text = extract_document(parsed).as_feature_text()
        self.assertIn("Review the invoice", feature_text)
        self.assertIn("attached invoice", feature_text)
        for forbidden in ("provider-secret-id", "sender@tenant.example", "spf=pass"):
            self.assertNotIn(forbidden, feature_text)


def _stamp_datetime(year, month, day):
    return datetime(year, month, day, tzinfo=dt_timezone.utc)


class GmailClassifierIntegrationTests(TransactionTestCase):
    def setUp(self):
        self.org = Organization.objects.create(
            slug="classifier", name="Classifier", gmail_service_account_client_id="client-1",
            gmail_access_verified_at=timezone.now(),
        )
        self.mailbox = Mailbox.objects.create(
            organization=self.org, address="inbox@example.test", state=Mailbox.State.ACTIVE,
            gmail_sync_status=Mailbox.GmailSyncStatus.READY,
            gmail_enrolled_at=timezone.now(), gmail_enrollment_history_id="100", gmail_history_id="100",
        )

    def _ingest(self, message_id):
        message = EmailMessage()
        message["From"] = "Notice <notice@example.test>"
        message["To"] = "inbox@example.test"
        message["Subject"] = "Verify your account"
        message.set_content("Please verify your password immediately.")

        class Client(FakeGmail):
            def get_raw_message(self, requested_id):
                metadata, _ = super().get_raw_message(requested_id)
                return metadata, message.as_bytes()

        return ingest_message(self.mailbox.pk, message_id, client=Client())

    def test_unavailable_model_preserves_rule_workflow(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            Artifact._meta.get_field("file").storage, "_location", directory,
        ), override_settings(CLASSIFIER_ACTIVE_VERSION=""):
            case = self._ingest("gmail-without-model")
            self.assertTrue(run_analysis(AnalysisRun.objects.get(case=case).pk))
        run = AnalysisRun.objects.get(case=case)
        self.assertEqual(run.state, AnalysisRun.State.SUCCEEDED)
        self.assertEqual(run.summary["classifier"]["code"], "model_not_configured")
        self.assertEqual(EmailCase.objects.get(pk=case.pk).state, EmailCase.State.ANALYZED)
        self.assertEqual(EmailCase.objects.get(pk=case.pk).verdict, EmailCase.Verdict.UNKNOWN)
        self.assertTrue(Evidence.objects.filter(case=case, source=Evidence.Source.RULE).exists())
        self.assertTrue(Evidence.objects.filter(case=case, source=Evidence.Source.MODEL,
                                                state=Evidence.State.UNAVAILABLE).exists())

    def test_gmail_case_inference_uses_signed_synthetic_model(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dataset = root / "training.jsonl"
            dataset.write_text("\n".join(json.dumps(row) for row in synthetic_rows()) + "\n", encoding="utf-8")
            selection_path = root / "selection.json"
            with override_settings(DEBUG=True, CLASSIFIER_ALLOW_SYNTHETIC=True,
                                   CLASSIFIER_APPROVAL_KEY="A" * 40,
                                   CLASSIFIER_SIGNING_KEY="B" * 40,
                                   CLASSIFIER_MODEL_ROOT=root / "models",
                                   CLASSIFIER_ACTIVE_VERSION="synthetic-v1"):
                create_selection(
                    dataset_path=dataset, selection_path=selection_path,
                    source_kind="synthetic", approved_by="synthetic-test",
                    authorization_reference="synthetic-fixture-only",
                    expires_at=(timezone.now() + timedelta(days=7)).isoformat(),
                    train_before=_stamp(2026, 1, 1), calibration_before=_stamp(2026, 2, 1),
                    private_mailbox_content=False,
                )
                model, metrics, selection = train_from_selection(selection_path)
                export_model(model, metrics, selection, version="synthetic-v1")
                with patch.object(Artifact._meta.get_field("file").storage, "_location", directory):
                    case = self._ingest("gmail-with-model")
                    self.assertTrue(run_analysis(AnalysisRun.objects.get(case=case).pk))
            run = AnalysisRun.objects.get(case=case)
            self.assertEqual(run.summary["classifier"]["status"], "observed")
            self.assertIsInstance(run.summary["classifier"]["probability_phishing"], float)
            self.assertEqual(EmailCase.objects.get(pk=case.pk).verdict, EmailCase.Verdict.UNKNOWN)
            evidence = Evidence.objects.get(case=case, source=Evidence.Source.MODEL)
            self.assertEqual(evidence.analysis_run_id, run.pk)
            self.assertEqual(evidence.state, Evidence.State.OBSERVED)
