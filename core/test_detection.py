"""Deterministic rule fixtures and PostgreSQL evidence integration."""

import hashlib
import json
import tempfile
from datetime import timedelta
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from unittest.mock import patch
from types import SimpleNamespace
from uuid import uuid4

from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.utils import timezone

from .analysis_runtime import RULES_KEY, ensure_rule_backfill_run, run_analysis
from .detection import detect, summarize
from .gmail_runtime import ingest_message
from .indicators import import_snapshot, normalize_indicator
from .models import (
    ActionExecution, AnalysisRun, Artifact, EmailCase, Evidence,
    Indicator, IndicatorSnapshot, Mailbox, Organization,
)
from .test_gmail import FakeGmail


def mime(*, sender="Support <support@example.com>", reply_to=None, subject="Notice", body="Hello", html=None, auth=None):
    message = EmailMessage()
    message["From"] = sender
    message["To"] = "recipient@example.test"
    message["Subject"] = subject
    if reply_to:
        message["Reply-To"] = reply_to
    if auth:
        message["Authentication-Results"] = auth
    message.set_content(body)
    if html:
        message.add_alternative(html, subtype="html")
    return message


def observations(message, **kwargs):
    parsed = BytesParser(policy=policy.default).parsebytes(message.as_bytes())
    return detect(parsed, indicator_matches={}, indicator_cache_available=True, **kwargs)


class DetectionRuleTests(SimpleTestCase):
    def _signals(self, items):
        return {item.rule_id for item in items if item.category == "signal"}

    def test_legitimate_reset_does_not_infer_safety_or_risk(self):
        items = observations(mime(subject="Password reset", body="Reset at https://example.com/reset"))
        self.assertEqual(self._signals(items), set())
        self.assertEqual(summarize(items)["verdict"], "not_assigned")

    def test_ordinary_invoice_and_unfamiliar_supplier_are_not_fraud_findings(self):
        invoice = observations(mime(
            sender="Accounts <billing@new-supplier.example>", subject="Invoice 123",
            body="Please pay invoice 123 to account 12345678 by 30 November.",
        ))
        self.assertNotIn("PAYMENT_CHANGE_CLAIM", self._signals(invoice))
        self.assertNotIn("PAYMENT_REDIRECTION_NO_LINK", self._signals(invoice))
        self.assertEqual(summarize(invoice)["verdict"], "not_assigned")

    def test_newsletter_reply_address_is_observed_with_limitation(self):
        items = observations(mime(
            sender="Newsletter <news@example.com>", reply_to="help@mailer.example",
            body="Read this month's updates at https://example.com/news",
        ))
        reply = next(item for item in items if item.rule_id == "IDENTITY_REPLY_TO")
        self.assertIn("lists", reply.limitations[0])
        self.assertEqual(summarize(items)["verdict"], "not_assigned")

    def test_same_domain_reply_mailbox_difference_is_context_only(self):
        items = observations(mime(
            sender="Support <support@example.com>", reply_to="help@example.com",
        ))
        reply = next(item for item in items if item.rule_id == "IDENTITY_REPLY_TO_ADDRESS")
        self.assertEqual(reply.category, "context")
        self.assertEqual(reply.facts["addresses_differ"], True)

    def test_display_claim_reply_to_and_visible_link_difference(self):
        items = observations(mime(
            sender='"Accounts bank.example" <alerts@other.example>',
            reply_to="payments@third.example", body="Please review.",
            html='<a href="https://evil.example/pay">https://bank.example/pay</a>',
        ))
        self.assertTrue({"IDENTITY_DISPLAY_FROM", "IDENTITY_REPLY_TO", "LINK_VISIBLE_DESTINATION"}.issubset(self._signals(items)))
        link = next(item for item in items if item.rule_id == "LINK_VISIBLE_DESTINATION")
        self.assertEqual(link.facts["visible_host"], "bank.example")
        self.assertEqual(link.facts["destination_host"], "evil.example")
        self.assertIn("line", link.source_span)

    def test_url_structure_is_observation_not_https_safety(self):
        items = observations(mime(body="Open https://user@192.0.2.10:8443/login"))
        url = next(item for item in items if item.rule_id == "URL_STRUCTURE")
        self.assertEqual(url.facts["flags"], ["userinfo", "ip_literal", "unusual_port"])
        self.assertEqual(summarize(items)["verdict"], "not_assigned")

    def test_link_free_payment_redirection_and_change_claim(self):
        items = observations(mime(
            subject="Updated bank details",
            body="Our bank account has changed. Urgently wire the invoice payment to the new account number 12345678 today.",
        ))
        self.assertIn("PAYMENT_CHANGE_CLAIM", self._signals(items))
        self.assertIn("PAYMENT_REDIRECTION_NO_LINK", self._signals(items))
        self.assertFalse(any("fraud confirmed" in item.label.lower() for item in items))

    def test_forwarded_content_is_not_attributed_to_current_sender(self):
        items = observations(mime(
            sender="Colleague <colleague@example.com>", subject="Fwd: invoice",
            body="For awareness.\n----- Forwarded message -----\nOur bank account changed. Urgently wire to new account 12345678.",
        ))
        self.assertIn("FORWARDED_CONTEXT", {item.rule_id for item in items})
        self.assertNotIn("PAYMENT_CHANGE_CLAIM", self._signals(items))
        self.assertNotIn("PAYMENT_REDIRECTION_NO_LINK", self._signals(items))

    def test_authenticated_phishing_keeps_authentication_untrusted(self):
        items = observations(mime(
            sender="Security <security@evil.example>",
            auth="mx.example; spf=pass smtp.mailfrom=evil.example; dkim=pass",
            html='<a href="https://evil.example/login">https://bank.example/login</a>',
        ), auth_results_mode="untrusted_context")
        self.assertIn("LINK_VISIBLE_DESTINATION", self._signals(items))
        auth = next(item for item in items if item.rule_id == "AUTH_RESULTS_CONTEXT")
        self.assertEqual(auth.category, "context")
        self.assertIn("untrusted", auth.facts["trust_configuration"])
        self.assertEqual(summarize(items)["verdict"], "not_assigned")
        ignored = observations(mime(auth="mx.example; spf=pass"), auth_results_mode="ignore")
        self.assertNotIn("AUTH_RESULTS_CONTEXT", {item.rule_id for item in ignored})

    def test_attachment_extension_and_signature_conflict(self):
        message = mime(body="Attached document.")
        message.add_attachment(b"MZsynthetic-executable", maintype="application", subtype="pdf", filename="invoice.pdf")
        items = observations(message)
        attachment = next(item for item in items if item.rule_id == "ATTACHMENT_TYPE")
        self.assertIn("signature_mismatch", attachment.facts["flags"])

    def test_absent_indicator_cache_is_explicitly_unavailable(self):
        parsed = BytesParser(policy=policy.default).parsebytes(mime().as_bytes())
        items = detect(parsed, indicator_matches={}, indicator_cache_available=False)
        unavailable = next(item for item in items if item.rule_id == "INDICATOR_CACHE")
        self.assertEqual(unavailable.status, "unavailable")
        self.assertEqual(unavailable.category, "coverage")

    def test_exact_indicator_types_do_not_use_domain_suffix_matching(self):
        message = mime(sender="Sender <sender@evil.example>", body="Open https://evil.example/login")
        payload = b"%PDF-synthetic"
        message.add_attachment(payload, maintype="application", subtype="pdf", filename="document.pdf")
        parsed = BytesParser(policy=policy.default).parsebytes(message.as_bytes())
        now = timezone.now()
        snapshot = SimpleNamespace(
            id=uuid4(), source_name="local", kind="operational", fetched_at=now,
            expires_at=now + timedelta(days=1), sha256="a" * 64,
        )
        matches = {
            (Indicator.Type.DOMAIN, "evil.example"): [snapshot],
            (Indicator.Type.EMAIL, "sender@evil.example"): [snapshot],
            (Indicator.Type.URL, "https://evil.example/login"): [snapshot],
            (Indicator.Type.SHA256, hashlib.sha256(payload).hexdigest()): [snapshot],
        }
        items = detect(parsed, indicator_matches=matches, indicator_cache_available=True)
        self.assertEqual(
            {item.facts["indicator_type"] for item in items if item.rule_id == "INDICATOR_EXACT"},
            {"domain", "email", "url", "sha256"},
        )
        subdomain = BytesParser(policy=policy.default).parsebytes(
            mime(sender="Sender <sender@sub.evil.example>").as_bytes(),
        )
        sub_items = detect(subdomain, indicator_matches=matches, indicator_cache_available=True)
        self.assertFalse(any(item.rule_id == "INDICATOR_EXACT" for item in sub_items))


class DetectionPersistenceTests(TransactionTestCase):
    def setUp(self):
        self.org = Organization.objects.create(
            slug="detector", name="Detector", gmail_service_account_client_id="client-1",
            gmail_access_verified_at=timezone.now(),
        )
        self.mailbox = Mailbox.objects.create(
            organization=self.org, address="inbox@example.test", state=Mailbox.State.ACTIVE,
            gmail_sync_status=Mailbox.GmailSyncStatus.READY,
            gmail_enrolled_at=timezone.now(), gmail_enrollment_history_id="100", gmail_history_id="100",
        )

    def _snapshot(self, kind, entries, source="local-feed"):
        now = timezone.now()
        raw = json.dumps({
            "source_name": source, "kind": kind,
            "fetched_at": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "indicators": entries,
        }, sort_keys=True).encode()
        return import_snapshot(raw, expected_kind=kind)

    def _ingest(self, message_id, message):
        class Client(FakeGmail):
            def get_raw_message(self, requested_id):
                metadata, _ = super().get_raw_message(requested_id)
                return metadata, message.as_bytes()
        return ingest_message(self.mailbox.pk, message_id, client=Client())

    def test_exact_operational_indicator_and_structured_evidence(self):
        snapshot, _ = self._snapshot(IndicatorSnapshot.Kind.OPERATIONAL, [
            {"type": "domain", "value": "evil.example"},
        ])
        message = mime(
            sender="Security <security@evil.example>",
            auth="mx.example; spf=pass smtp.mailfrom=evil.example",
            html='<a href="https://evil.example/login">https://bank.example/login</a>',
        )
        with tempfile.TemporaryDirectory() as directory, patch.object(
            Artifact._meta.get_field("file").storage, "_location", directory,
        ):
            case = self._ingest("gmail-1", message)
            artifact = Artifact.objects.get(case=case)
            before = hashlib.sha256(artifact.file.read()).hexdigest()
            self.assertTrue(run_analysis(AnalysisRun.objects.get(case=case).pk))
            artifact.file.open("rb")
            after = hashlib.sha256(artifact.file.read()).hexdigest()
        self.assertEqual(before, after)
        self.assertEqual(before, artifact.sha256)
        run = AnalysisRun.objects.get(case=case)
        self.assertEqual(run.summary["detection"]["verdict"], "not_assigned")
        self.assertEqual(run.summary["detection"]["indicator_snapshot_ids"], [str(snapshot.pk)])
        self.assertEqual(case.verdict, EmailCase.Verdict.UNKNOWN)
        self.assertFalse(ActionExecution.objects.exists())
        rule_evidence = Evidence.objects.filter(case=case, source=Evidence.Source.RULE)
        self.assertTrue(rule_evidence.exists())
        for evidence in rule_evidence:
            self.assertEqual(evidence.analysis_run_id, run.pk)
            self.assertEqual(evidence.source_version, "1")
            self.assertTrue(evidence.rule_id)
            self.assertTrue(evidence.source_field)
            self.assertIn(evidence.state, Evidence.State.values)
            self.assertIsInstance(evidence.source_span, dict)
            self.assertIsInstance(evidence.provenance, dict)
            self.assertEqual(evidence.provenance["artifact_sha256"], artifact.sha256)
            self.assertIsInstance(evidence.limitations, list)
        exact = rule_evidence.filter(rule_id="INDICATOR_EXACT").first()
        self.assertIsNotNone(exact)
        self.assertEqual(exact.provenance["snapshot_id"], str(snapshot.pk))

    def test_synthetic_feed_does_not_enter_operational_matches(self):
        with override_settings(DEBUG=True):
            self._snapshot(IndicatorSnapshot.Kind.SYNTHETIC, [
                {"type": "domain", "value": "evil.example"},
            ], source="synthetic-only")
        message = mime(sender="Sender <sender@evil.example>")
        with tempfile.TemporaryDirectory() as directory, patch.object(
            Artifact._meta.get_field("file").storage, "_location", directory,
        ):
            case = self._ingest("gmail-2", message)
            run_analysis(AnalysisRun.objects.get(case=case).pk)
        self.assertFalse(Evidence.objects.filter(case=case, rule_id="INDICATOR_EXACT").exists())
        self.assertTrue(Evidence.objects.filter(case=case, rule_id="INDICATOR_CACHE", state=Evidence.State.UNAVAILABLE).exists())

    def test_backfill_run_does_not_duplicate_parser_run(self):
        message = mime(body="Our bank account changed. Urgently wire to the new account number 12345678 today.")
        with tempfile.TemporaryDirectory() as directory, patch.object(
            Artifact._meta.get_field("file").storage, "_location", directory,
        ):
            case = self._ingest("gmail-3", message)
            old = AnalysisRun.objects.get(case=case)
            old.state = AnalysisRun.State.SUCCEEDED
            old.engine_version = "mime-v1"
            old.finished_at = timezone.now()
            old.save(update_fields=["state", "engine_version", "finished_at"])
            EmailCase.objects.filter(pk=case.pk).update(state=EmailCase.State.ANALYZED)
            backfill, created = ensure_rule_backfill_run(case)
            self.assertTrue(created)
            self.assertEqual(backfill.idempotency_key, RULES_KEY)
            self.assertTrue(run_analysis(backfill.pk))
            self.assertFalse(run_analysis(backfill.pk))
        self.assertEqual(AnalysisRun.objects.filter(case=case).count(), 2)
        self.assertFalse(Evidence.objects.filter(case=case, source=Evidence.Source.PARSER).exists())
        self.assertTrue(Evidence.objects.filter(case=case, rule_id="PAYMENT_REDIRECTION_NO_LINK").exists())
        self.assertEqual(EmailCase.objects.get(pk=case.pk).state, EmailCase.State.ANALYZED)

    def test_indicator_normalization_and_snapshot_isolation(self):
        self.assertEqual(normalize_indicator(Indicator.Type.DOMAIN, "EXAMPLE.COM."), "example.com")
        snapshot, created = self._snapshot(IndicatorSnapshot.Kind.OPERATIONAL, [
            {"type": "domain", "value": "EXAMPLE.COM."},
        ])
        self.assertTrue(created)
        self.assertEqual(Indicator.objects.get(snapshot=snapshot).value, "example.com")
        self.assertNotEqual(Indicator.objects.get(snapshot=snapshot).value, "sub.example.com")
        old = json.dumps({
            "source_name": "local-feed", "kind": "operational",
            "fetched_at": (snapshot.fetched_at - timedelta(minutes=1)).isoformat(),
            "expires_at": (timezone.now() + timedelta(hours=1)).isoformat(),
            "indicators": [],
        }).encode()
        with self.assertRaises(ValueError):
            import_snapshot(old, expected_kind=IndicatorSnapshot.Kind.OPERATIONAL)
        with override_settings(DEBUG=False):
            with self.assertRaises(ValueError):
                self._snapshot(IndicatorSnapshot.Kind.SYNTHETIC, [], source="blocked-synthetic")
