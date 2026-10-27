import hashlib
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from django.core.files.base import ContentFile
from django.test import TestCase, override_settings
from django.utils import timezone

from core.management.commands.trial_readiness import assess_trial
from core.models import Artifact, AuditEvent, EmailCase, Mailbox, Organization, ServiceHeartbeat
from core.retention import prune_private_artifacts
from core.tasks import scheduler_heartbeat


class TrialOperationsTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Trial", slug="trial", retention_days=1)
        self.mailbox = Mailbox.objects.create(
            organization=self.organization, address="test@example.test", state=Mailbox.State.ACTIVE,
        )
        self.case = EmailCase.objects.create(
            organization=self.organization, mailbox=self.mailbox,
            provider_immutable_id="synthetic-id", gmail_message_id="synthetic-id",
        )

    def test_retention_dry_run_and_resumable_private_file_deletion(self):
        with TemporaryDirectory() as directory:
            storage = Artifact._meta.get_field("file").storage
            with mock.patch.object(storage, "_location", directory):
                artifact = Artifact(
                    organization=self.organization, case=self.case,
                    kind=Artifact.Kind.ORIGINAL_MIME, state=Artifact.State.STORED,
                    size_bytes=9, sha256=hashlib.sha256(b"synthetic").hexdigest(),
                )
                artifact.file.save("synthetic.eml", ContentFile(b"synthetic"), save=False)
                artifact.save()
                saved_path = Path(storage.path(artifact.file.name))
                Artifact.objects.filter(pk=artifact.pk).update(created_at=timezone.now() - timedelta(days=2))
                self.assertEqual(prune_private_artifacts(dry_run=True)["eligible"], 1)
                self.assertTrue(saved_path.exists())
                self.assertEqual(prune_private_artifacts()["deleted"], 1)
                artifact.refresh_from_db()
                self.assertEqual(artifact.state, Artifact.State.DELETED)
                self.assertEqual(artifact.file.name, "")
                self.assertFalse(saved_path.exists())
                self.assertEqual(AuditEvent.objects.filter(event_type="private_artifact_retention_deleted").count(), 1)
                self.assertEqual(prune_private_artifacts()["deleted"], 0)

    def test_retention_preserves_recent_file(self):
        with TemporaryDirectory() as directory:
            storage = Artifact._meta.get_field("file").storage
            with mock.patch.object(storage, "_location", directory):
                artifact = Artifact(
                    organization=self.organization, case=self.case,
                    kind=Artifact.Kind.ORIGINAL_MIME, state=Artifact.State.STORED,
                    size_bytes=9, sha256=hashlib.sha256(b"synthetic").hexdigest(),
                )
                artifact.file.save("synthetic.eml", ContentFile(b"synthetic"), save=False)
                artifact.save()
                self.assertEqual(prune_private_artifacts()["eligible"], 0)
                self.assertTrue(Path(storage.path(artifact.file.name)).exists())

    def test_readiness_detects_missing_security_and_enrollment(self):
        with override_settings(
            DEBUG=True, SECURE_SSL_REDIRECT=False, SECURE_PROXY_SSL_HEADER=None,
            CSRF_TRUSTED_ORIGINS=[], GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE="",
            GMAIL_RESPONSE_ENABLED=False, ARTIFACT_RETENTION_ENABLED=False,
        ):
            report = assess_trial(require_enrollment=True)
        self.assertFalse(report["ready"])
        self.assertIn("debug_enabled", report["failures"])
        self.assertIn("ingestion_key_unavailable", report["failures"])
        self.assertIn("no_enrolled_mailboxes", report["failures"])

    def test_readiness_detects_shared_response_identity(self):
        with TemporaryDirectory() as directory:
            key = Path(directory) / "synthetic.json"
            key.write_text("{}", encoding="utf-8")
            with override_settings(
                DEBUG=False, SECURE_SSL_REDIRECT=True,
                SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
                CSRF_TRUSTED_ORIGINS=["https://trial.example.test"],
                ALLOWED_HOSTS=["trial.example.test"],
                GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE=str(key),
                GOOGLE_RESPONSE_SERVICE_ACCOUNT_FILE=str(key),
                GMAIL_RESPONSE_ENABLED=True, ARTIFACT_RETENTION_ENABLED=True,
            ):
                report = assess_trial()
        self.assertIn("response_identity_not_isolated", report["failures"])

    def test_scheduler_heartbeat_is_durable_and_repeatable(self):
        scheduler_heartbeat()
        first = ServiceHeartbeat.objects.get(name="beat").last_seen_at
        scheduler_heartbeat()
        self.assertEqual(ServiceHeartbeat.objects.filter(name="beat").count(), 1)
        self.assertGreaterEqual(ServiceHeartbeat.objects.get(name="beat").last_seen_at, first)
