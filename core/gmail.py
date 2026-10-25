"""Read-only Gmail API client built on Google's maintained Python libraries."""

import base64
import binascii

from google.auth.exceptions import GoogleAuthError
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from .gmail_credentials import (
    CredentialPurpose, CredentialProviderError,
    WorkspaceDelegatedCredentialProvider, enrolled_mailbox,
)


MAX_MIME_BYTES = 40 * 1024 * 1024


class GmailError(Exception):
    def __init__(self, code, *, retryable=False):
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class GmailHistoryExpired(GmailError):
    def __init__(self):
        super().__init__("gmail_history_expired")


class GmailClient:
    """A client tied to one persisted enrolled mailbox and the ingestion identity."""

    def __init__(self, mailbox_id, *, credential_provider=None, service=None):
        self.mailbox_id = mailbox_id
        enrolled_mailbox(mailbox_id, allow_verification=True)
        provider = credential_provider or WorkspaceDelegatedCredentialProvider()
        try:
            credentials = provider.for_mailbox(mailbox_id, CredentialPurpose.INGESTION)
        except CredentialProviderError as exc:
            raise GmailError(exc.code) from None
        self.service = service or build(
            "gmail", "v1", credentials=credentials, cache_discovery=False,
        )

    def _execute(self, request, *, history=False):
        # Recheck enrollment immediately before every provider operation.
        try:
            enrolled_mailbox(self.mailbox_id, allow_verification=True)
        except CredentialProviderError as exc:
            raise GmailError(exc.code) from None
        try:
            return request.execute(num_retries=0)
        except HttpError as exc:
            status = int(exc.resp.status)
            if history and status == 404:
                raise GmailHistoryExpired() from None
            raise GmailError(
                f"gmail_http_{status}",
                retryable=status in {429, 500, 502, 503, 504},
            ) from None
        except (OSError, TimeoutError, GoogleAuthError):
            raise GmailError("gmail_transport_error", retryable=True) from None

    def profile(self):
        return self._execute(self.service.users().getProfile(userId="me"))

    def list_messages(self):
        token = None
        while True:
            params = {"userId": "me", "maxResults": 500, "includeSpamTrash": True}
            if token:
                params["pageToken"] = token
            data = self._execute(self.service.users().messages().list(**params))
            yield from data.get("messages", [])
            token = data.get("nextPageToken")
            if not token:
                break

    def history_messages(self, start_history_id):
        token = None
        while True:
            params = {"userId": "me", "startHistoryId": str(start_history_id), "maxResults": 500}
            if token:
                params["pageToken"] = token
            data = self._execute(
                self.service.users().history().list(**params), history=True,
            )
            for entry in data.get("history", []):
                for change in entry.get("messagesAdded", []):
                    message_id = change.get("message", {}).get("id")
                    if message_id:
                        yield message_id, "added"
                for field in ("labelsAdded", "labelsRemoved"):
                    for change in entry.get(field, []):
                        message_id = change.get("message", {}).get("id")
                        if message_id:
                            yield message_id, "labels"
            token = data.get("nextPageToken")
            if not token:
                history_id = data.get("historyId")
                if not isinstance(history_id, str) or not history_id:
                    raise GmailError("gmail_history_cursor_missing", retryable=True)
                yield None, history_id
                break

    def get_raw_message(self, message_id):
        data = self._execute(self.service.users().messages().get(
            userId="me", id=message_id, format="raw",
        ))
        if data.get("id") != message_id:
            raise GmailError("gmail_message_id_mismatch")
        try:
            encoded = data["raw"]
            if not isinstance(encoded, str):
                raise ValueError
            padded = encoded + "=" * (-len(encoded) % 4)
            raw = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
        except (KeyError, TypeError, ValueError, UnicodeEncodeError, binascii.Error):
            raise GmailError("gmail_invalid_mime") from None
        if len(raw) > MAX_MIME_BYTES:
            raise GmailError("gmail_mime_too_large")
        return data, raw