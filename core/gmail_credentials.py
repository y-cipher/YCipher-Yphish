"""Delegated identities for Gmail ingestion and future response work.

The interface accepts a persisted mailbox ID, never a caller-supplied subject.
No key material or access token is stored in a model or emitted in an error.
"""

import json
from enum import StrEnum
from typing import Protocol

from django.conf import settings
from google.oauth2 import service_account

from .models import Mailbox


INGESTION_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
ADMIN_RESPONSE_SCOPE = "https://www.googleapis.com/auth/gmail.modify.restricted"


class CredentialPurpose(StrEnum):
    INGESTION = "ingestion"
    RESPONSE = "response"


class CredentialProviderError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class CredentialProvider(Protocol):
    def for_mailbox(self, mailbox_id, purpose: CredentialPurpose): ...


def enrolled_mailbox(mailbox_id, *, allow_verification=False):
    """Return only a persisted, explicitly enrolled mailbox for impersonation."""
    try:
        mailbox = Mailbox.objects.select_related("organization").get(pk=mailbox_id)
    except (Mailbox.DoesNotExist, ValueError, TypeError):
        raise CredentialProviderError("gmail_mailbox_not_enrolled") from None
    if not mailbox.organization.is_active or mailbox.provider != Mailbox.Provider.GMAIL or not mailbox.gmail_enrolled_at:
        raise CredentialProviderError("gmail_mailbox_not_enrolled")
    if allow_verification and mailbox.gmail_sync_status == Mailbox.GmailSyncStatus.ENROLLING:
        if mailbox.state != Mailbox.State.PENDING:
            raise CredentialProviderError("gmail_mailbox_not_enrolled")
        return mailbox
    if (mailbox.state != Mailbox.State.ACTIVE or not mailbox.gmail_enrollment_history_id
            or not mailbox.organization.gmail_access_verified_at
            or mailbox.gmail_sync_status not in {
                Mailbox.GmailSyncStatus.INITIALIZING, Mailbox.GmailSyncStatus.READY,
                Mailbox.GmailSyncStatus.COVERAGE_GAP, Mailbox.GmailSyncStatus.ERROR,
                Mailbox.GmailSyncStatus.DISCONNECTED,
                Mailbox.GmailSyncStatus.AUTHORIZATION_FAILED,
                Mailbox.GmailSyncStatus.THROTTLED,
                Mailbox.GmailSyncStatus.UNAVAILABLE,
            }):
        raise CredentialProviderError("gmail_mailbox_not_enrolled")
    return mailbox


class WorkspaceDelegatedCredentialProvider:
    def for_mailbox(self, mailbox_id, purpose: CredentialPurpose):
        try:
            purpose = CredentialPurpose(purpose)
        except ValueError:
            raise CredentialProviderError("gmail_credential_purpose_invalid")
        mailbox = enrolled_mailbox(
            mailbox_id, allow_verification=purpose == CredentialPurpose.INGESTION,
        )
        organization = mailbox.organization
        if purpose == CredentialPurpose.INGESTION:
            path = settings.GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE
            expected_client_id = organization.gmail_service_account_client_id
            scope = INGESTION_SCOPE
        else:
            path = settings.GOOGLE_RESPONSE_SERVICE_ACCOUNT_FILE
            expected_client_id = organization.gmail_response_service_account_client_id
            scope = organization.gmail_response_scope
            if scope != ADMIN_RESPONSE_SCOPE:
                raise CredentialProviderError("gmail_response_scope_invalid")
            if not path or path == settings.GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE:
                raise CredentialProviderError("gmail_response_identity_not_separate")
            if not expected_client_id or expected_client_id == organization.gmail_service_account_client_id:
                raise CredentialProviderError("gmail_response_identity_not_separate")
        if not path or not expected_client_id:
            raise CredentialProviderError("gmail_credentials_not_configured")
        try:
            with open(path, encoding="utf-8") as stream:
                info = json.load(stream)
            if str(info["client_id"]) != expected_client_id:
                raise CredentialProviderError("gmail_client_id_mismatch")
            return service_account.Credentials.from_service_account_info(
                info, scopes=[scope],
            ).with_subject(mailbox.address)
        except CredentialProviderError:
            raise
        except (OSError, ValueError, TypeError, KeyError):
            raise CredentialProviderError("gmail_credentials_invalid") from None
