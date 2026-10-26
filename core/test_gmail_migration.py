from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


OLD = ("core", "0003_transactional_service_keys")
GMAIL_BASE = ("core", "0004_emailcase_gmail_message_id_emailcase_gmail_thread_id_and_more")
BOUNDARY = ("core", "0005_emailcase_gmail_internal_date_ms_and_more")
NEW = ("core", "0007_evidence_limitations_evidence_provenance_and_more")


class GmailUpgradeTests(TransactionTestCase):
    def test_existing_mailbox_and_case_remain_legacy(self):
        executor = MigrationExecutor(connection)
        executor.migrate([OLD])
        try:
            old_apps = executor.loader.project_state([OLD]).apps
            org = old_apps.get_model("core", "Organization").objects.create(name="Legacy", slug="legacy-migration")
            mailbox = old_apps.get_model("core", "Mailbox").objects.create(
                organization_id=org.pk, address="legacy@example.test",
            )
            case = old_apps.get_model("core", "EmailCase").objects.create(
                organization_id=org.pk, mailbox_id=mailbox.pk,
                provider_immutable_id="pre-gmail-id",
            )
            executor = MigrationExecutor(connection)
            executor.migrate([GMAIL_BASE])
            new_apps = executor.loader.project_state([GMAIL_BASE]).apps
            migrated_mailbox = new_apps.get_model("core", "Mailbox").objects.get(pk=mailbox.pk)
            migrated_case = new_apps.get_model("core", "EmailCase").objects.get(pk=case.pk)
            self.assertEqual(migrated_mailbox.provider, "legacy")
            self.assertEqual(migrated_case.provider_immutable_id, "pre-gmail-id")
            self.assertEqual(migrated_case.gmail_message_id, "")
            gmail_mailbox = new_apps.get_model("core", "Mailbox").objects.create(
                organization_id=org.pk, address="prior-gmail@example.test",
                provider="gmail", state="active", gmail_history_id="7654321",
            )
            gmail_case = new_apps.get_model("core", "EmailCase").objects.create(
                organization_id=org.pk, mailbox_id=gmail_mailbox.pk,
                provider_immutable_id="gmail-before-boundary", gmail_message_id="gmail-before-boundary",
            )
            executor = MigrationExecutor(connection)
            executor.migrate([BOUNDARY])
            latest_apps = executor.loader.project_state([BOUNDARY]).apps
            final_mailbox = latest_apps.get_model("core", "Mailbox").objects.get(pk=mailbox.pk)
            self.assertEqual(final_mailbox.gmail_sync_status, "not_enrolled")
            prior_mailbox = latest_apps.get_model("core", "Mailbox").objects.get(pk=gmail_mailbox.pk)
            prior_case = latest_apps.get_model("core", "EmailCase").objects.get(pk=gmail_case.pk)
            self.assertEqual(prior_mailbox.gmail_history_id, "7654321")
            self.assertEqual(prior_mailbox.gmail_enrollment_history_id, "7654321")
            self.assertEqual(prior_mailbox.gmail_sync_status, "coverage_gap")
            self.assertTrue(prior_case.gmail_is_historical)
        finally:
            MigrationExecutor(connection).migrate([NEW])
