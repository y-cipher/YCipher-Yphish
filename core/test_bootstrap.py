from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from .models import ActionExecution, Artifact, EmailCase, Evidence, Mailbox, Membership, Organization


@override_settings(DEBUG=True)
class BootstrapDevTests(TestCase):
    def test_repeatable_synthetic_setup_without_credentials_or_content(self):
        output = StringIO()
        call_command("bootstrap_dev", with_sample_cases=True, stdout=output)
        call_command("bootstrap_dev", with_sample_cases=True, stdout=output)

        organization = Organization.objects.get(slug="demo-org")
        owner = get_user_model().objects.get(username="demo_owner")
        self.assertTrue(owner.is_staff)
        self.assertFalse(owner.has_usable_password())
        self.assertEqual(Membership.objects.filter(organization=organization, user=owner).count(), 1)
        self.assertEqual(Mailbox.objects.filter(organization=organization).count(), 2)
        self.assertEqual(EmailCase.objects.filter(organization=organization).count(), 2)
        self.assertEqual(Evidence.objects.filter(organization=organization).count(), 2)
        self.assertEqual(Artifact.objects.filter(organization=organization).count(), 2)
        self.assertEqual(ActionExecution.objects.filter(organization=organization).count(), 2)
        self.assertTrue(all(
            mailbox.address.endswith("@example.test")
            and mailbox.state == Mailbox.State.PENDING
            and not mailbox.provider_mailbox_id
            for mailbox in Mailbox.objects.filter(organization=organization)
        ))
        self.assertTrue(all(
            not case.subject and not case.sender_address and not case.internet_message_id
            for case in EmailCase.objects.filter(organization=organization)
        ))
        self.assertTrue(all(
            not artifact.file.name for artifact in Artifact.objects.filter(organization=organization)
        ))
        self.assertTrue(all(
            action.state == ActionExecution.State.SKIPPED
            for action in ActionExecution.objects.filter(organization=organization)
        ))

    def test_rejects_non_synthetic_mailbox_without_writing_rows(self):
        with self.assertRaises(CommandError):
            call_command("bootstrap_dev", mailboxes=["real@example.com"])
        self.assertFalse(Organization.objects.filter(slug="demo-org").exists())

    def test_does_not_promote_an_existing_unrelated_user(self):
        user = get_user_model().objects.create_user("demo_owner", password="existing-password")
        with self.assertRaises(CommandError):
            call_command("bootstrap_dev")
        user.refresh_from_db()
        self.assertFalse(user.is_staff)
        self.assertTrue(user.has_usable_password())
        self.assertFalse(Organization.objects.filter(slug="demo-org").exists())

    @override_settings(DEBUG=False)
    def test_refuses_to_run_outside_debug_mode(self):
        with self.assertRaises(CommandError):
            call_command("bootstrap_dev")
