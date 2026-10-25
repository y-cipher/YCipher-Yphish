"""Automatic mailbox polling and execution of already authorized actions."""

from celery import shared_task

from .gmail import GmailError
from .gmail_runtime import authorize_automatic_responses, execute_action, sync_mailbox
from .models import ActionExecution, Mailbox


@shared_task
def poll_gmail_and_respond():
    for mailbox_id in Mailbox.objects.filter(
        provider=Mailbox.Provider.GMAIL, state=Mailbox.State.ACTIVE,
        organization__is_active=True, organization__gmail_access_verified_at__isnull=False,
    ).values_list("id", flat=True).iterator():
        sync_gmail_mailbox.delay(str(mailbox_id))
    authorize_automatic_responses()
    for execution_id in ActionExecution.objects.filter(
        state__in=[ActionExecution.State.AUTHORIZED, ActionExecution.State.RECONCILING],
        organization__is_active=True,
    ).values_list("id", flat=True).iterator():
        execute_gmail_action.delay(str(execution_id))


@shared_task
def sync_gmail_mailbox(mailbox_id):
    try:
        return sync_mailbox(mailbox_id)
    except GmailError as exc:
        # Store only a stable code. Never include provider response bodies or MIME.
        Mailbox.objects.filter(pk=mailbox_id).update(last_error_code=exc.code)
        if exc.retryable:
            raise sync_gmail_mailbox.retry(countdown=60, max_retries=3) from None
        return 0


@shared_task
def execute_gmail_action(execution_id):
    return execute_action(execution_id)
