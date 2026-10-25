# Module 1 data model and database rules

All ten domain tables use UUID primary keys and `created_at`. Tenant-owned rows carry an `organization` foreign key. Foreign keys use `PROTECT` for investigation history unless noted; user references in `Feedback` use `SET_NULL`. PostgreSQL constraints are defined in `core.models`, with tenant and audit triggers in migrations `0002` and `0003`.

| Model | Purpose | Unique and check constraints | Query indexes |
| --- | --- | --- | --- |
| `Organization` | Tenant identity, activation, retention setting. | Unique `slug`; `org_retention_days_range` requires 1–3650 days. | Primary key and unique slug. |
| `Membership` | A Django user’s role in one organization. | `membership_org_user_unique` allows one membership per user and organization; `membership_role_valid` permits owner, admin, analyst, or viewer. | `membership_user_active_idx` for active role checks; foreign-key indexes. |
| `Mailbox` | Enrolled address and enrollment state; no provider credential. | `mailbox_org_address_ci_unique` uses lowercase address per organization; `mailbox_org_provider_unique` applies to nonblank provider mailbox IDs; `mailbox_state_valid` permits pending, active, paused, or error. | `mailbox_org_state_idx`; foreign-key indexes. |
| `EmailCase` | One provider message within a mailbox, with processing state and verdict. | `case_org_mailbox_immutable_id_unique` applies to nonblank immutable IDs; `case_state_valid`, `case_verdict_valid`, and `case_completion_state_valid` restrict states and completion timestamps. Migration `0003` rejects blank immutable IDs on new inserts. | `case_org_state_created_idx`, `case_mailbox_received_idx`; foreign-key indexes. |
| `Artifact` | Private original, attachment, derived item, or report metadata. | `artifact_kind_valid`, `artifact_state_valid`, `artifact_size_nonnegative`, and `artifact_stored_metadata_required` require a file key, size, and digest for stored items. | `artifact_case_kind_idx`, `artifact_org_sha256_idx`; foreign-key indexes. |
| `AnalysisRun` | One analysis attempt for a case. | `run_case_attempt_unique`; conditional `run_case_idempotency_unique` for nonblank keys; `run_attempt_positive`, `run_state_valid`, and `run_finish_state_valid`. | `run_org_state_created_idx`; foreign-key indexes. |
| `Evidence` | Time-stamped observation or unavailable/error result with source and trust. | Conditional `evidence_case_idempotency_unique` for nonblank keys; `evidence_source_valid`, `evidence_state_valid`, and `evidence_trust_valid`. Migration `0003` rejects blank keys on new inserts. | `evidence_case_observed_idx`; foreign-key indexes. |
| `ActionExecution` | Idempotent response intent and execution outcome. | `action_org_idempotency_unique`, `action_idempotency_required`, `action_type_valid`, `action_state_valid`, `action_verified_success_only`, and `action_failure_code_required`. Failed, reconciling, and skipped rows require an error/reason code. | `action_case_requested_idx`; foreign-key indexes. |
| `Feedback` | Proposed verdict correction and review state. | `feedback_verdict_valid`, `feedback_state_valid`, and `feedback_review_state_valid`. | `feedback_case_created_idx`; foreign-key indexes. |
| `AuditEvent` | Append-only event history with optional actor, case, and correlation ID. | `audit_event_type_required`; migration `0002` rejects updates and deletes. | `audit_org_occurred_idx`, `audit_case_occurred_idx`, `audit_correlation_idx`; foreign-key indexes. |

## Relationship guards

Migration `0002_tenant_integrity` rejects a case whose mailbox belongs to another organization, and rejects artifacts, runs, evidence, actions, feedback, or audit events linked to a case in another organization. Evidence and actions must also reference an analysis run in their own case; evidence artifacts must belong to that case. An existing tenant-owned row cannot change organizations, and artifacts and analysis runs cannot move to another case. The application services validate these relationships before insertion; the triggers remain the database backstop.

## Processing and storage boundaries

`EmailCase` states are queued, processing, analyzed, action_pending, completed, and failed. `AnalysisRun` states are queued, running, succeeded, failed, and cancelled. `ActionExecution` states are proposed, authorized, running, reconciling, succeeded, failed, and skipped. The check constraints validate values and a few timestamp relationships; they do not implement the full workflow transition policy.

`Artifact.file` uses a private filesystem storage class, a random path under organization/case UUIDs, and no public URL. Neither raw email content nor provider credentials belong in the fixture command or admin setup. A real deployment also needs encryption, retention jobs, and tenant-aware application APIs before ingesting messages.
