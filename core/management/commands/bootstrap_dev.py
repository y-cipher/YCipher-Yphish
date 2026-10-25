"""Idempotent, synthetic development data with no provider credentials or mail."""

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.core.validators import validate_email, validate_slug
from django.db import transaction

from core.models import (
    ActionExecution, AnalysisRun, Artifact, EmailCase, Feedback, Mailbox,
    Membership, Organization,
)
from core.services import (
    create_action_execution, create_email_case, mark_action_skipped,
    record_evidence,
)


DEFAULT_MAILBOXES = ("security@example.test", "finance@example.test")


class Command(BaseCommand):
    help = "Create repeatable, synthetic Module 1 development records. Requires DEBUG=1."

    def add_arguments(self, parser):
        parser.add_argument("--slug", default="demo-org", help="Development organization slug")
        parser.add_argument("--name", default="Yphish Demo", help="Development organization name")
        parser.add_argument("--owner", default="demo_owner", help="New or existing local staff username")
        parser.add_argument(
            "--mailbox", action="append", dest="mailboxes",
            help="Synthetic address under example.test; repeat for multiple mailboxes",
        )
        parser.add_argument(
            "--with-sample-cases", action="store_true",
            help="Also create synthetic cases, evidence, and non-executed actions",
        )

    def handle(self, *args, **options):
        if not settings.DEBUG:
            raise CommandError("bootstrap_dev requires DJANGO_DEBUG=1")
        slug = options["slug"].strip()
        name = options["name"].strip()
        username = options["owner"].strip()
        if not slug or not name or not username:
            raise CommandError("Slug, name, and owner username must be nonblank")
        try:
            validate_slug(slug)
        except ValidationError as exc:
            raise CommandError("Organization slug is invalid") from exc

        addresses = options["mailboxes"] or DEFAULT_MAILBOXES
        normalized = []
        for address in addresses:
            value = address.strip().lower()
            try:
                validate_email(value)
            except ValidationError as exc:
                raise CommandError(f"Invalid synthetic mailbox address: {address}") from exc
            if not value.endswith("@example.test"):
                raise CommandError("Development mailboxes must use the reserved example.test domain")
            if value not in normalized:
                normalized.append(value)

        with transaction.atomic():
            organization, _ = Organization.objects.get_or_create(
                slug=slug, defaults={"name": name}
            )
            if organization.name != name:
                raise CommandError("The organization slug already has a different name")
            if not organization.is_active:
                raise CommandError("The development organization is inactive")

            user_model = get_user_model()
            owner, owner_created = user_model.objects.get_or_create(username=username)
            if owner_created:
                owner.is_active = True
                owner.is_staff = True
                owner.set_unusable_password()
                owner.save(update_fields=["is_active", "is_staff", "password"])
            else:
                existing_owner = Membership.objects.filter(
                    organization=organization, user=owner,
                    role=Membership.Role.OWNER, is_active=True,
                ).exists()
                if not owner.is_active or not owner.is_staff or not existing_owner:
                    raise CommandError(
                        "Existing username is not an active staff owner of this organization"
                    )
            Membership.objects.get_or_create(
                organization=organization, user=owner,
                defaults={"role": Membership.Role.OWNER, "is_active": True},
            )

            mailboxes = []
            for address in normalized:
                mailbox = Mailbox.objects.filter(
                    organization=organization, address__iexact=address
                ).first()
                if mailbox is None:
                    mailbox = Mailbox.objects.create(
                        organization=organization, address=address,
                        state=Mailbox.State.PENDING,
                    )
                mailboxes.append(mailbox)

            if options["with_sample_cases"]:
                for mailbox in mailboxes:
                    self._create_sample_case(organization, owner, mailbox)

        self.stdout.write(self.style.SUCCESS(
            f"Development organization '{organization.slug}' is ready with "
            f"{len(mailboxes)} synthetic mailbox(es)."
        ))
        if owner_created:
            self.stdout.write(
                f"Staff owner '{username}' has an unusable password. "
                f"Run 'python manage.py changepassword {username}' locally before admin login."
            )
        if options["with_sample_cases"]:
            self.stdout.write("Synthetic cases contain no message body, MIME, or provider credentials.")

    def _create_sample_case(self, organization, owner, mailbox):
        case, _ = create_email_case(
            organization=organization,
            mailbox=mailbox,
            gmail_message_id=f"fixture:{organization.slug}:{mailbox.address}",
        )
        run, _ = AnalysisRun.objects.get_or_create(
            case=case, attempt=1,
            defaults={
                "organization": organization,
                "idempotency_key": "fixture:analysis:1",
                "engine_version": "fixture-only",
            },
        )
        if run.engine_version != "fixture-only":
            raise CommandError("A sample case already has a non-fixture analysis run")
        record_evidence(
            organization=organization,
            case=case,
            analysis_run=run,
            idempotency_key="fixture:enrollment",
            source="ingestion",
            label="Synthetic enrollment marker",
            observed_at=case.created_at,
            trust="internal",
            source_version="fixture-only",
            details={"synthetic": True, "message_content_present": False},
        )
        Artifact.objects.get_or_create(
            organization=organization,
            case=case,
            kind=Artifact.Kind.DERIVED,
            original_filename="synthetic-placeholder-no-file",
            defaults={"state": Artifact.State.PENDING},
        )
        action, _ = create_action_execution(
            organization=organization,
            case=case,
            analysis_run=run,
            idempotency_key=f"fixture:action:{case.pk}",
            action=ActionExecution.Action.MOVE,
            policy_version="fixture-only",
        )
        mark_action_skipped(execution=action, reason_code="synthetic_fixture")
        Feedback.objects.get_or_create(
            organization=organization,
            case=case,
            submitted_by=owner,
            proposed_verdict=EmailCase.Verdict.UNKNOWN,
            reason="Synthetic fixture only; no email content was collected.",
        )
