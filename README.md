# HackerRank Orchestrate - October 2026

## Ghost Data Still Exists

This submission implements an offline, deterministic deletion-audit agent. It
investigates current and historical identifiers, searches the supplied evidence
corpus, applies the deletion policy, and emits an ordered remediation or
verification plan for every deletion request.

See [`problem_statement.md`](./problem_statement.md) for the challenge contract
and the complete operation/state vocabulary.

## Setup

The solution uses only the Python standard library; no package installation,
API key, network access, or model provider is required.

### Windows PowerShell

From the repository root:

```powershell
py -3 code\main.py
py -3 code\evaluation\main.py
```

If `py` is unavailable, use an installed Python 3.10+ executable:

```powershell
python code\main.py
python code\evaluation\main.py
```

### macOS/Linux

From the repository root:

```bash
python3 code/main.py
python3 code/evaluation/main.py
```

The default run reads `dataset/deletion_requests.csv` and writes
`output.csv` in the repository root. A different request file or output path
can be supplied when testing:

```bash
python3 code/main.py \
  --requests dataset/sample_deletion_requests.csv \
  --output sample_pred.csv
```

The evaluation command validates the generated row count, exact header, JSON
shape, allowed statuses, empty `NOT_APPLICABLE` plans, and consecutive step
numbers. It also compares `sample_pred.csv` with the supplied sample oracle
when that file exists.

## Approach

### 1. Load and index the evidence

`code/main.py` loads the request, identity, audit-history, activity, policy,
and evidence manifest CSV files. Evidence files are read from the paths in
`evidence_files.csv`, including:

- SQL snapshots and replicas;
- JSON records and exports;
- plain-text handover records;
- application and service logs; and
- other readable evidence supplied by the challenge.

The evidence index precomputes identifier-to-file matches so the full
518-request run remains reproducible and practical without external services.

### 2. Resolve identity

For each request, the agent:

1. normalizes the requested email;
2. finds the current identity in `user_identities.csv`;
3. falls back to email changes in `user_audit_log.csv` when necessary; and
4. searches using the user ID, name, current email, phone, email hash, request
   email, and historical field values.

Identifier matching is token-aware, so an identifier such as `user_01` cannot
accidentally match `user_010`.

### 3. Reconstruct resource state

The parser extracts resource IDs and maps them to systems and policy
categories. It understands structured records, SQL inserts, and log records
joined by trace/correlation IDs. Activity records are used to recover resource
handles from deletion-worker events, but reported operation results are not
treated as proof that a record is absent.

The agent distinguishes:

- remaining records;
- exposed identifiers requiring redaction;
- analytics or telemetry requiring anonymization;
- active data flows that can recreate data;
- backup restore risks; and
- retained security records and permitted account tombstones.

### 4. Apply the deletion rules

Each observation is translated into the allowed operation for its category:

| Situation | Finding | Remediation | Verification |
| --- | --- | --- | --- |
| User profile, search, export, cache, or marketing copy remains | `REPORT_REMAINING_RECORD` | `DELETE_RECORD` | `VERIFY_RECORD_ABSENT` |
| Support message or email log exposes PII | `REPORT_EXPOSED_PII` | `REDACT_RECORD` | `VERIFY_RECORD_REDACTED` |
| Analytics or product telemetry remains attributable | `REPORT_EXPOSED_PII` | `ANONYMIZE_RECORD` | `VERIFY_RECORD_ANONYMIZED` |
| Active synchronization/integration path exists | `REPORT_ACTIVE_DATA_FLOW` | `DISABLE_DATA_FLOW` | `VERIFY_DATA_FLOW_DISABLED` |
| Backup can restore the deleted data | `REPORT_RESTORE_RISK` | `BLOCK_RESTORE` | `VERIFY_RESTORE_BLOCKED` |
| Retained security audit record is required | — | retain | `VERIFY_RECORD_PRESENT` |
| Tombstone contains direct identifiers | `REPORT_EXPOSED_PII` | `REDACT_RECORD` | `VERIFY_RECORD_REDACTED` |

Requests that do not actually ask for account or personal-data deletion return
`NOT_APPLICABLE` with `[]`.

### 5. Render ordered plans

For `INCOMPLETE` cases, the output contains findings, remediation actions, and
future verification checks. For `COMPLETE` cases, it contains only
evidence-backed verification checks. Steps are ordered by:

1. phase: `FINDING`, `REMEDIATION`, `VERIFICATION`;
2. operation order defined by the problem statement; and
3. `system_id`, then `resource_id`.

Remediation and future verification steps intentionally use an empty
`evidence_id`; observed findings and completed-case checks cite evidence IDs.

## Output

The generated root-level `output.csv` has exactly these columns:

```text
case_id,deletion_status,steps_json
```

It contains one sorted row for each request in
`dataset/deletion_requests.csv`. Each `steps_json` value is a JSON array with
consecutive `step_no` values beginning at `1`.

## Evaluation reports

The code archive includes:

- [`code/evaluation/evaluation_report.md`](./code/evaluation/evaluation_report.md)
  with validation metrics, additional regression cases, failures, and fixes;
- [`code/evaluation/usage_report.md`](./code/evaluation/usage_report.md)
  with the final run's model and token/cost accounting; and
- [`code/evaluation/main.py`](./code/evaluation/main.py), the offline
  evaluation workflow.

The final implementation is model-free, so the usage report records zero model
calls and zero token cost.

## Packaging

Create the submission archive from the repository root without including the
dataset:

### Windows PowerShell

```powershell
Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
```

### macOS/Linux

```bash
zip -r code.zip README.md code \
  -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/node_modules/*"
```

Do not include `dataset/`, virtual environments, build caches, nested archives,
credentials, or API keys in the submission.
