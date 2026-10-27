# Module 10: Gmail operator dashboard

Open `/dashboard/` after signing in with a Django user that has an active Yphish organization membership. Dashboard authentication uses Django sessions and CSRF protection; it never grants Gmail access. Gmail ingestion and response continue to use separately configured Workspace delegated identities.

The overview shows enrolled mailboxes, last successful synchronization, lag, authorization and coverage states, analysis backlog, automatic actions, worker/broker health, and open response circuits. Queue health is checked with a short timeout and cached for 30 seconds. A queue error is shown as a fixed status; connection URLs and credentials are never displayed.

The case list searches only the selected organization. It supports mailbox, verdict, processing, Gmail label, and response filters, and paginates 25 messages at a time. List previews contain only a truncated subject and sender domain; no body or original MIME is exposed. A case represents **one Gmail message**, even when several messages share a thread ID.

The detail page shows the stored message fields, first-ingestion labels, latest stored labels, the before-action snapshot, evidence with provenance and limitations, parser/rule/model versions, investigation trace, action/restoration history, feedback, and audit events. Investigation traces and audit details require an analyst or manager role. A bounded 2,500-character plain-text preview is available to those roles only. It reads no more than 1 MB of private original MIME, extracts text with the existing provider-independent parser, and escapes all output. HTML is never inserted as rendered message markup. Cases ingested before migration `0012` show original labels as unavailable instead of reconstructing them from later state.

Gmail settings show enrollment and authorization health, history cursor and coverage gap, deployment polling intervals, the fixed `Yphish/Suspicious` label and its current ID, policy version, rate limits, and circuits. Owners and administrators can enable or pause response per enrolled mailbox and configure optional `INBOX` removal. The page rejects enabling response until the mailbox is ready and the separate response scopes are configured. Enrollment itself remains administrator-managed through the existing Django admin and `enroll_gmail_mailbox` command; the dashboard does not store keys or tokens. Global polling intervals and policy code remain deployment settings.

## Roles and feedback

| Role | Read scoped dashboard | Message preview | Submit feedback | Review feedback / request restoration | Edit mailbox response settings |
| --- | --- | --- | --- | --- | --- |
| Viewer | Yes | No | No | No | No |
| Analyst | Yes | Yes | Yes | No | No |
| Owner / administrator | Yes | Yes | Yes | Yes | Yes |

Every operator write requires an active organization membership and is checked again in the transactional service. Feedback needs a proposed verdict and a reason of 10–1,000 characters. The submitting and reviewing actors, review reason, and timestamps are audited. Feedback does **not** change the case verdict or train a model. An approved legitimate correction is a durable restoration trigger for the periodic response worker; the dashboard can also request dispatch while response is enabled. The worker verifies live Gmail state and reverses only the message-level changes Yphish recorded. A failed broker dispatch remains recoverable by the scheduled sweep. A recorded failed or skipped restoration requires inspection of its action history; the dashboard does not promise a duplicate request will retry it. Neither approval nor dashboard request calls Gmail directly from the web process.

Status wording distinguishes Yphish label application, `INBOX` removal, restoration, unavailable messages, and failed actions. It makes no claim of secure quarantine, pre-delivery blocking, or containment of a whole conversation. Stored current labels may lag Gmail until the next synchronization.

## Run and test

```powershell
docker compose up --build -d
docker compose exec web python manage.py migrate
docker compose exec web python manage.py test core.test_dashboard
docker compose exec web python manage.py test core
```

For a host setup with `.env` exported and PostgreSQL running, use `python manage.py migrate`, `python manage.py runserver`, and `python manage.py test core.test_dashboard`. Bootstrap 5.3.8 CSS is pinned and served locally from `core/static/core/bootstrap.min.css`; the dashboard does not require a third-party CDN at runtime. The [Bootstrap download documentation](https://getbootstrap.com/docs/5.3/getting-started/download/) supplies the version and distribution.

Tests use synthetic message records and PostgreSQL. Live Gmail authorization, synchronization, and message modification still require the separate [Gmail setup](gmail.md) and [response checklist](module9-response.md).
