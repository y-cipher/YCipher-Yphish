"""Narrow Gmail response capability: label management and one-message modify."""

import httplib2

from google.auth.exceptions import GoogleAuthError
from googleapiclient.discovery import build
from googleapiclient.errors import Error, HttpError

from .gmail import GmailError, _http_error
from .gmail_credentials import (
    CredentialProviderError, CredentialPurpose,
    WorkspaceDelegatedCredentialProvider, enrolled_mailbox,
)
from .models import EmailCase, Mailbox


SUSPICIOUS_LABEL = "Yphish/Suspicious"


class GmailResponseClient:
    """Never exposes thread, trash, filter, search, or account-setting calls."""

    def __init__(self, mailbox_id, *, credential_provider=None, service=None):
        self.mailbox_id = mailbox_id
        mailbox = self._mailbox()
        provider = credential_provider or WorkspaceDelegatedCredentialProvider()
        try:
            credentials = provider.for_mailbox(mailbox.pk, CredentialPurpose.RESPONSE)
        except CredentialProviderError as exc:
            raise GmailError(exc.code) from None
        self._service = service or build("gmail", "v1", credentials=credentials, cache_discovery=False)

    def _mailbox(self):
        try:
            mailbox = enrolled_mailbox(self.mailbox_id)
        except CredentialProviderError as exc:
            raise GmailError(exc.code) from None
        if not mailbox.organization.gmail_response_enabled or not mailbox.gmail_response_enabled:
            raise GmailError("gmail_response_not_enabled")
        return mailbox

    def _execute(self, request):
        self._mailbox()
        try:
            return request.execute(num_retries=0)
        except HttpError as exc:
            raise _http_error(exc) from None
        except GoogleAuthError:
            raise GmailError("gmail_authorization_failed") from None
        except (OSError, TimeoutError, httplib2.HttpLib2Error):
            raise GmailError("gmail_transport_error", retryable=True) from None
        except Error:
            raise GmailError("gmail_api_error", retryable=True) from None

    def list_labels(self):
        mailbox = self._mailbox()
        data = self._execute(self._service.users().labels().list(userId=mailbox.address))
        labels = data.get("labels", [])
        if not isinstance(labels, list):
            raise GmailError("gmail_labels_invalid")
        return labels

    def ensure_suspicious_label(self):
        mailbox = self._mailbox()
        labels = self.list_labels()
        matches = [item for item in labels if item.get("name") == SUSPICIOUS_LABEL and item.get("type", "").lower() == "user"]
        if len(matches) > 1:
            raise GmailError("gmail_response_label_ambiguous")
        if matches:
            label_id = matches[0].get("id")
        else:
            try:
                created = self._execute(self._service.users().labels().create(
                    userId=mailbox.address,
                    body={"name": SUSPICIOUS_LABEL, "labelListVisibility": "labelShow",
                          "messageListVisibility": "show"},
                ))
                label_id = created.get("id")
            except GmailError as exc:
                if exc.code not in {"gmail_http_409", "gmail_transport_error"}:
                    raise
                matches = [item for item in self.list_labels() if item.get("name") == SUSPICIOUS_LABEL
                           and item.get("type", "").lower() == "user"]
                if len(matches) != 1:
                    raise
                label_id = matches[0].get("id")
        if not isinstance(label_id, str) or not label_id or len(label_id) > 255:
            raise GmailError("gmail_response_label_invalid")
        # A renamed/deleted old ID is not reused; retain history in each action.
        Mailbox.objects.filter(pk=mailbox.pk).update(gmail_label_id=label_id)
        return label_id

    def canonical_label_exists(self, label_id):
        return any(item.get("id") == label_id and item.get("name") == SUSPICIOUS_LABEL
                   and item.get("type", "").lower() == "user" for item in self.list_labels())

    def modify_case(self, case_id, *, add_label_ids, remove_label_ids, yphish_label_id):
        mailbox = self._mailbox()
        case = EmailCase.objects.filter(
            pk=case_id, organization_id=mailbox.organization_id, mailbox_id=mailbox.pk,
        ).first()
        if not case or not case.gmail_message_id or case.gmail_deleted_at:
            raise GmailError("gmail_response_case_outside_mailbox")
        add, remove = set(add_label_ids), set(remove_label_ids)
        if (not add and not remove) or add & remove or not isinstance(yphish_label_id, str) or not yphish_label_id or yphish_label_id == "INBOX":
            raise GmailError("gmail_response_changes_invalid")
        if not add.issubset({"INBOX", yphish_label_id}) or not remove.issubset({"INBOX", yphish_label_id}):
            raise GmailError("gmail_response_changes_invalid")
        if add & {"SPAM", "TRASH", "UNREAD"} or remove & {"SPAM", "TRASH", "UNREAD"}:
            raise GmailError("gmail_response_changes_invalid")
        valid_apply = add.issubset({yphish_label_id}) and remove.issubset({"INBOX"})
        valid_restore = add.issubset({"INBOX"}) and remove.issubset({yphish_label_id})
        if not (valid_apply or valid_restore):
            raise GmailError("gmail_response_changes_invalid")
        if yphish_label_id in add | remove and not self.canonical_label_exists(yphish_label_id):
            raise GmailError("gmail_response_label_changed")
        result = self._execute(self._service.users().messages().modify(
            userId=mailbox.address, id=case.gmail_message_id,
            body={"addLabelIds": sorted(add), "removeLabelIds": sorted(remove)},
        ))
        if result.get("id") != case.gmail_message_id:
            raise GmailError("gmail_response_message_id_mismatch")
        return result
