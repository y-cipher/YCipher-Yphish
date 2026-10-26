# Module 7 — TF-IDF classifier

Module 7 adds an optional, provider-independent text classifier to the existing MIME analysis run. It reads the preserved original MIME artifact and extracts only its subject and visible body text. `TextDocument` is the shared training/inference boundary; the fitted pipeline is TF-IDF followed by logistic regression. Gmail IDs, threads, labels, inbox placement, mailbox and organization IDs, sender history, indicator observations, rule evidence, analyst feedback, and dispositions are not model inputs. Gmail `SPAM` is neither a feature nor a ground-truth label. The classifier records probability and artifact identity as `Evidence.Source.MODEL`; it does not set a case verdict or trigger a response. Rules, parser evidence, and the preserved MIME continue when the model is unavailable or incompatible.

## Authorized dataset selection

Training never queries Yphish mailboxes or the case database. An operator must prepare a reviewed UTF-8 JSONL corpus locally, obtain documented authorization for its use, and sign an explicit selection file. Keep both the corpus and approval file private in `datasets/` (ignored by Git). The selected dataset must be immutable after approval: its SHA-256 is signed with `CLASSIFIER_APPROVAL_KEY`, and training checks the digest, signature, expiry, schema, and split cutoffs. Use a separate, long random `CLASSIFIER_SIGNING_KEY` for exported models. Restrict access to these keys and the dataset to approved operators. Signing is an operator attestation; Yphish cannot independently verify an external approval reference or detect sensitive text embedded in a subject/body. Review and minimize the corpus before authorizing it. The `--private-mailbox-content` switch must be passed only when the documented authorization explicitly covers private mailbox content. No default selection or automatic export from Gmail exists.

Each JSONL object must have **exactly** these fields:

| Field | Meaning |
| --- | --- |
| `sample_id` | Unique opaque audit ID; never a Gmail/provider ID. It is never a feature. |
| `subject`, `body_text` | Content captured from the original message at or before the decision. These alone become features. |
| `label` | `phishing` or `legitimate`; missing labels are rejected. |
| `label_source` | `curated_review` or `incident_confirmation` for curated data; `synthetic` for debug fixtures. Gmail `SPAM` is rejected. |
| `campaign_id` | Reviewed campaign cluster ID, or empty string when unknown. It is never a feature. |
| `content_captured_at` | Time the content was captured; cannot be later than `decision_at`. |
| `decision_at` | Time at which the historical prediction would have been made; controls chronological splits. |
| `label_assigned_at` | Time ground truth became available; must not be in the future. Training and calibration labels must precede their respective cutoffs. |

All timestamps must be ISO 8601 with a timezone. Export only content available by `decision_at`. Do not append post-decision corrections, sender history, indicator matches, organization-specific routing hints, Gmail metadata, or analyst dispositions to `subject` or `body_text`. The strict field allowlist rejects extra metadata columns; content review remains necessary to catch shortcuts embedded in free text. Exact normalized content duplicates and common `campaign_id` values are clustered before splitting. One earliest representative per cluster is kept; conflicting labels within a cluster fail validation. This prevents a known campaign or exact duplicate from spanning the train, calibration, and test sets. Near-duplicate campaigns require an accurate `campaign_id` from the dataset curator.

`train_before` and `calibration_before` define three chronological periods: earlier decisions for training, decisions between cutoffs for independent calibration, and later decisions for test. Each of train and calibration needs at least two examples per class; test needs at least one per class. TF-IDF vocabulary and logistic weights are fitted only on training. A frozen estimator is then sigmoid-calibrated on the separate calibration period. Test data is used only for the final report.

## Commands

Set up Django/PostgreSQL as in the [README](../README.md). Add long, different random values for `CLASSIFIER_APPROVAL_KEY` and `CLASSIFIER_SIGNING_KEY` to the private `.env`, and set `CLASSIFIER_DATASET_SELECTION_FILE=datasets/selection.json` for host commands. The Compose web service uses `/app/datasets/selection.json` and mounts the host `datasets/` directory read-only. Create `datasets/training.jsonl` only after the data review and authorization. On PowerShell, load the edited `.env` into the current process using the README's host-environment snippet, then run:

```powershell
$expiry = (Get-Date).ToUniversalTime().AddDays(30).ToString('yyyy-MM-ddTHH:mm:ssZ')
.\.venv\Scripts\python.exe manage.py authorize_classifier_dataset `
  --dataset datasets/training.jsonl --selection datasets/selection.json `
  --curated --approved-by "approved-operator" `
  --authorization-reference "approved-ticket-or-policy-reference" `
  --expires-at $expiry `
  --train-before "2026-01-01T00:00:00Z" `
  --calibration-before "2026-04-01T00:00:00Z"
```

Choose cutoffs that match **your** approved corpus. Add `--private-mailbox-content` only when the referenced authorization covers that content. The selection command refuses to overwrite an existing approval; a changed dataset requires a new approval file. With Docker Compose running, train and evaluate the approved selection:

```powershell
docker compose exec web python manage.py train_classifier --model-version curated-2026-10-v1
docker compose exec web python manage.py evaluate_classifier --model-version curated-2026-10-v1
docker compose exec web python manage.py test core.test_classifier --noinput
```

For a host-only setup use `.\.venv\Scripts\python.exe manage.py train_classifier --model-version curated-2026-10-v1`, then the analogous `evaluate_classifier` and `test core.test_classifier` commands. Each model version is immutable under `CLASSIFIER_MODEL_ROOT`. Training reports JSON metrics and creates a signed manifest and joblib artifact. Evaluate reloads the signed model and recomputes the held-out report from the same selected corpus. To activate a reviewed model, set `CLASSIFIER_ACTIVE_VERSION=curated-2026-10-v1` in `.env` and restart web and worker (`docker compose up -d --force-recreate web worker`). Do not activate a model until its report and data authorization have been reviewed. Back up and access-control the model volume; fitted vocabulary can contain private terms. Never load model files from an untrusted source: joblib uses Python object deserialization. The loader checks artifact HMAC, SHA-256, feature schema, and exact scikit-learn version before deserialization.

Synthetic pipeline tests run with `DJANGO_DEBUG=1` and explicit `CLASSIFIER_ALLOW_SYNTHETIC=1`. Synthetic model artifacts are refused outside that mode. The test corpus proves wiring, reproducibility, leakage guards, signed export, and Gmail case inference; its scores are **not representative detection-performance measurements**. Production precision, recall, F1, and calibration require a separately authorized and representative curated corpus.

## Evaluation and operational behavior

The report includes per-split class counts/prevalence and date ranges, precision, recall, F1, a confusion matrix ordered `[legitimate, phishing]`, Brier score, log loss, expected calibration error, ten reliability bins, and holdout recall at supported target false-positive rates. Thresholds for 1%, 5%, and 10% targets are selected from calibration negatives only, then measured on test. Each target is marked unsupported unless **both** calibration and test contain at least `ceil(1/target)` negatives (100, 20, or 10 respectively). Test false-positive rate is reported alongside recall; a target is not a guarantee on future traffic. Report class prevalence and dates when comparing models because both affect interpretation.

For each MIME run, the model evidence records status, reason code, probability, threshold, model version, artifact digest, and feature-schema version. An empty message, absent active version, missing or altered artifact, missing signing key, incompatible library/schema, disabled synthetic model, or prediction error produces explicit `unavailable` model evidence while the deterministic rule workflow succeeds. No probability is treated as a final safety verdict. A successful inference against a Gmail-ingested case is tested with synthetic MIME and a signed synthetic artifact. Live Gmail ingestion, real-world classifier quality, and operational authorization have not been verified by these tests.

The calibration implementation follows scikit-learn's [frozen-estimator calibration API](https://scikit-learn.org/stable/modules/generated/sklearn.calibration.CalibratedClassifierCV.html), with preprocessing in a [TF-IDF vectorizer](https://scikit-learn.org/stable/modules/generated/sklearn.feature_extraction.text.TfidfVectorizer.html).
