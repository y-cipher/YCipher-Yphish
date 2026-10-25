from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


OLD = ("core", "0003_transactional_service_keys")
NEW = ("core", "0004_emailcase_gmail_message_id_emailcase_gmail_thread_id_and_more")


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
            executor.migrate([NEW])
            new_apps = executor.loader.project_state([NEW]).apps
            migrated_mailbox = new_apps.get_model("core", "Mailbox").objects.get(pk=mailbox.pk)
            migrated_case = new_apps.get_model("core", "EmailCase").objects.get(pk=case.pk)
            self.assertEqual(migrated_mailbox.provider, "legacy")
            self.assertEqual(migrated_case.provider_immutable_id, "pre-gmail-id")
            self.assertEqual(migrated_case.gmail_message_id, "")
        finally:
            MigrationExecutor(connection).migrate([NEW])
