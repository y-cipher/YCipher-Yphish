from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .models import Artifact, AuditEvent, EmailCase, Mailbox, Membership, Organization


class TenantAdminTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.owner = user_model.objects.create_user("owner", is_staff=True)
        self.analyst = user_model.objects.create_user("analyst", is_staff=True)
        self.viewer = user_model.objects.create_user("viewer", is_staff=True)
        self.outsider = user_model.objects.create_user("outsider", is_staff=True)
        self.org = Organization.objects.create(name="One", slug="admin-one")
        self.other_org = Organization.objects.create(name="Two", slug="admin-two")
        for user, role in (
            (self.owner, Membership.Role.OWNER),
            (self.analyst, Membership.Role.ANALYST),
            (self.viewer, Membership.Role.VIEWER),
        ):
            Membership.objects.create(organization=self.org, user=user, role=role)
        self.mailbox = Mailbox.objects.create(organization=self.org, address="one@example.test")
        self.other_mailbox = Mailbox.objects.create(
            organization=self.other_org, address="two@example.test"
        )
        self.case = EmailCase.objects.create(
            organization=self.org, mailbox=self.mailbox, provider_immutable_id="admin-one-case"
        )
        self.other_case = EmailCase.objects.create(
            organization=self.other_org, mailbox=self.other_mailbox,
            provider_immutable_id="admin-two-case",
        )
        self.artifact = Artifact.objects.create(
            organization=self.org, case=self.case, kind=Artifact.Kind.DERIVED,
            file="private/opaque-file-key",
        )
        AuditEvent.objects.create(
            organization=self.org, case=self.case,
            event_type="fixture.created", occurred_at=timezone.now(),
        )

    def test_case_changelist_and_object_are_scoped_to_membership(self):
        self.client.force_login(self.owner)
        response = self.client.get(reverse("admin:core_emailcase_changelist"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, str(self.case.pk))
        self.assertNotContains(response, str(self.other_case.pk))
        other_url = reverse("admin:core_emailcase_change", args=[self.other_case.pk])
        self.assertNotEqual(self.client.get(other_url).status_code, 200)
        self.assertEqual(
            list(admin.site._registry[EmailCase].get_queryset(response.wsgi_request).values_list("pk", flat=True)),
            [self.case.pk],
        )

    def test_viewer_can_inspect_cases_but_not_sensitive_artifacts_or_audit(self):
        self.client.force_login(self.viewer)
        self.assertEqual(self.client.get(reverse("admin:core_emailcase_changelist")).status_code, 200)
        self.assertEqual(self.client.get(reverse("admin:core_artifact_changelist")).status_code, 403)
        self.assertEqual(self.client.get(reverse("admin:core_auditevent_changelist")).status_code, 403)
        self.assertEqual(self.client.get(reverse("admin:core_organization_changelist")).status_code, 403)

    def test_artifact_detail_never_generates_a_file_url(self):
        self.client.force_login(self.analyst)
        response = self.client.get(reverse("admin:core_artifact_change", args=[self.artifact.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "private/opaque-file-key")
        self.assertNotContains(response, 'href="private/opaque-file-key"')

    def test_only_owner_or_admin_can_create_a_mailbox_in_their_org(self):
        add_url = reverse("admin:core_mailbox_add")
        self.client.force_login(self.analyst)
        self.assertEqual(self.client.get(add_url).status_code, 403)

        self.client.force_login(self.owner)
        allowed = self.client.post(add_url, {
            "organization": str(self.org.pk),
            "address": "new@example.test",
            "display_name": "New",
            "_save": "Save",
        })
        self.assertEqual(allowed.status_code, 302)
        self.assertTrue(Mailbox.objects.filter(organization=self.org, address="new@example.test").exists())
        denied = self.client.post(add_url, {
            "organization": str(self.other_org.pk),
            "address": "cross@example.test",
            "display_name": "Cross",
            "_save": "Save",
        })
        self.assertEqual(denied.status_code, 200)
        self.assertFalse(Mailbox.objects.filter(address="cross@example.test").exists())

    def test_unmapped_staff_cannot_browse_domain_models(self):
        self.client.force_login(self.outsider)
        self.assertEqual(self.client.get(reverse("admin:core_emailcase_changelist")).status_code, 403)

    def test_django_auth_admin_remains_superuser_only(self):
        permission = Permission.objects.get(codename="view_user", content_type__app_label="auth")
        self.owner.user_permissions.add(permission)
        self.client.force_login(self.owner)
        self.assertEqual(self.client.get(reverse("admin:auth_user_changelist")).status_code, 403)

