# Module 6 — deterministic Gmail detection evidence

Module 6 extends the existing Celery MIME analysis run. It reads the privately stored **original MIME** with Python's `BytesParser(policy=policy.default)`, records versioned `Evidence` rows, and leaves the artifact bytes and SHA-256 unchanged. Gmail message ID, label IDs, and timestamps supplement the MIME record; they do not rewrite headers or body. There are no response actions, URL visits, attachment executions, or automatic safety verdicts.

## Observations

| Rule ID (version `1`) | Observation | Material limitation |
| --- | --- | --- |
| `IDENTITY_DISPLAY_FROM`, `IDENTITY_REPLY_TO`, `IDENTITY_REPLY_TO_ADDRESS` | An email/domain claim in the display name differs from From, or Reply-To differs by domain or mailbox address. | Names and reply routing can differ legitimately; this is not identity verification. |
| `LINK_VISIBLE_DESTINATION` | URL/domain text inside an HTML anchor differs from the anchor's destination host. | Redirects and visual rendering are not checked; differing hosts can be intentional. |
| `URL_STRUCTURE` | Userinfo, IP literal, punycode host, deep subdomain, unusual port, or malformed HTTP(S) URL. | Structure alone does not prove maliciousness; HTTPS does not prove safety. |
| `PAYMENT_CHANGE_CLAIM`, `PAYMENT_REDIRECTION_NO_LINK` | Current-message text claims changed bank/payment instructions, or asks to redirect a payment with no extracted HTTP(S) link. | No verified bank baseline or recipient action is known. These are review signals, not a fraud finding. |
| `ATTACHMENT_TYPE` | Attachment extension, declared MIME type, and known magic bytes conflict; also flags executable double extensions. | All three attributes can be spoofed; files are not executed. |
| `INDICATOR_EXACT` | Exact normalized URL, domain, email address, or attachment SHA-256 match in an active local snapshot. | A match is a lead, not proof of malicious activity. No suffix, fuzzy, or live lookup is done. |
| `INDICATOR_CACHE`, `RULE_COVERAGE_LIMIT`, `RULE_OBSERVATION_LIMIT` | Coverage could not be completed because a current cache was absent or an extraction limit was reached. | Absence of a finding cannot be interpreted as safety. |
| `GMAIL_LABEL_CONTEXT`, `AUTH_RESULTS_CONTEXT`, `FORWARDED_CONTEXT` | Gmail labels, MIME authentication header presence, and excluded quoted/forwarded text are preserved as context. | None is a Yphish verdict or proof of trustworthy authentication. |

Every rule observation records `rule_id`, `source_version`, `source_field`, optional `source_span`, `provenance`, `state`, `limitations`, and a foreign key to its `AnalysisRun`. MIME provenance includes the original artifact ID and digest. An exact indicator match also records snapshot ID, source name/kind, fetch and expiry times, and snapshot SHA-256. Evidence stores compact facts (such as hostnames and extension types), not body excerpts, account numbers, or claims about clicks, credential submission, or compromise. The run summary contains deterministic counts by rule/category/status and `verdict: not_assigned`; `EmailCase.verdict` stays `unknown`.

`DETECTION_AUTH_RESULTS_MODE=untrusted_context` records only the presence of `Authentication-Results` headers from retrieved MIME. `ignore` omits that context. There is deliberately no configuration value that treats these headers as verified: [RFC 8601](https://www.rfc-editor.org/rfc/rfc8601.html) describes forged headers and trust boundaries. A future trusted ingress must establish provenance outside the retrieved MIME before authentication results can be trusted. SPF, DKIM, or DMARC success is never a safe verdict. Gmail [label IDs](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages) remain contextual and mutable; INBOX placement and absence of SPAM do not imply safety.

The parser excludes text after recognized inline forward markers and nested `message/rfc822` parts from current-message body rules. It records a context observation when doing so. This is a bounded heuristic: other quotation styles may require review. Text extraction is capped at 500,000 characters per part, 500 URLs, and 1,000 observations; coverage-limit evidence makes truncation visible.

## Local indicator snapshots

Indicators are read from PostgreSQL cache tables, never fetched by the analysis worker. An operator curates a local UTF-8 JSON file, supplies its source timestamp and expiry, and imports it as a complete snapshot. Import atomically deactivates the previous snapshot of the same source/kind while retaining it for audit. Only active, unexpired snapshots of `DETECTION_INDICATOR_MODE` are used. The default is `operational`; `synthetic` requires `DJANGO_DEBUG=1`. Synthetic rows cannot match in operational mode. The file digest detects a changed file at the same source timestamp but is **not** a signature or proof that the upstream feed is trustworthy.

Example synthetic file for local development (use an actual recent UTC timestamp and future expiry):

```json
{
  "source_name": "demo-indicators",
  "kind": "synthetic",
  "fetched_at": "2026-10-26T00:00:00Z",
  "expires_at": "2026-11-26T00:00:00Z",
  "indicators": [
    {"type": "domain", "value": "training.example"},
    {"type": "url", "value": "https://training.example/login"},
    {"type": "email", "value": "alerts@training.example"},
    {"type": "sha256", "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
  ]
}
```

```powershell
docker compose exec web python manage.py load_indicator_snapshot /app/snapshots/indicators.json --operational
# For a local debug-only synthetic file, set DETECTION_INDICATOR_MODE=synthetic and use --synthetic.
```

Mount a trusted local `snapshots/` directory read-only into the web container or run the command on the host with a local path. The worker needs only database access to the imported cache. Supported exact normalizations: domains use lowercase IDNA with a trailing dot removed; emails use case-folded local/domain parts; URLs use lowercase scheme/host, preserve path/query case, and omit fragments; SHA-256 is lowercase hex. Domain matching does not include subdomains. An absent or expired cache yields `INDICATOR_CACHE` with state `unavailable`, never a negative reputation claim.

## Run, test, and backfill

```powershell
docker compose up --build -d
docker compose exec web python manage.py migrate --noinput
docker compose exec web python manage.py test core.test_detection core.test_module5 --noinput
docker compose exec web python manage.py gmail_health
docker compose exec web python manage.py enqueue_detection_backfill --organization YOUR_SLUG --limit 100
```

New Gmail messages are analyzed automatically by Module 5's queued task. The backfill command queues versioned rule runs for already ingested cases; Celery's existing sweep dispatches them. Pass `--include-historical` to evaluate initial-sync baseline cases without creating response actions. Repeating backfill does not create another rule run for a case already evaluated with `rules-v1`. The test suite uses synthetic MIME and local indicator snapshots; it does not verify a live Workspace mailbox or a real operational feed.
