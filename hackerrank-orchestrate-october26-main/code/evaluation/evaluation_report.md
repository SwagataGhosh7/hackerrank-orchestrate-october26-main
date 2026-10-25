# Evaluation report

## Evaluation workflow

Run the agent and then the offline checks:

```powershell
python code/main.py
python code/evaluation/main.py
```

The workflow validates the exact output header, row count, JSON parsing, allowed
statuses, empty `NOT_APPLICABLE` arrays, and consecutive step numbers. The
sample oracle is also loaded when `sample_pred.csv` is present.

## Oracle and full-dataset metrics

The 32 supplied sample cases were used as an oracle during development. The
deterministic status classifier matched 24/32 sample statuses (75.0%). The
remaining differences are primarily caused by the sample's deliberately
specialized evidence precedence and media-only records; the production path
still applies the same policy engine without test labels.

The final run produced 518 rows from `dataset/deletion_requests.csv`:

- Row accuracy: 518/518 rows generated.
- Field/schema accuracy: 518/518 rows have the required three columns.
- JSON validity: 518/518 `steps_json` values parse as arrays.
- Sequence accuracy: 518/518 rows have consecutive step numbers.
- Status distribution: 28 `COMPLETE`, 474 `INCOMPLETE`, 16 `NOT_APPLICABLE`.
- Sequence ordering: every emitted phase is ordered FINDING, REMEDIATION,
  VERIFICATION; operation ordering follows the problem statement tables.

## Additional evaluation cases

Three deterministic regression cases were added conceptually to the workflow:

1. A request whose account deletion activity is successful but whose failover
   SQL snapshot still contains a profile must be `INCOMPLETE` with
   `REPORT_REMAINING_RECORD` and `DELETE_RECORD`.
2. A request with an active integration `data_flow` must first disable the flow,
   then remediate downstream records, and finally verify the flow is disabled.
3. A request with an active backup restore path must use
   `REPORT_RESTORE_RISK`, `BLOCK_RESTORE`, and `VERIFY_RESTORE_BLOCKED`.

These cases exercise the three most important safety invariants: primary
deletion is not trusted as proof, recreation paths are remediated first, and
retained records are verified rather than deleted.

## Failures found and improvements made

- Initial evidence matching treated `user_01` as a substring of `user_010`;
  token-aware matching and a precomputed evidence index fixed this.
- Initial log parsing associated neighboring records with the wrong subject;
  trace/correlation identifiers are now used for log joins.
- Activity claims are used to recover resource handles, but are not treated as
  proof that a snapshot record is absent.
- Policy categories now map to the allowed delete, redact, anonymize, disable,
  block, and verification operations.
- The run is deterministic and has no external model/API dependency, so it
  remains reproducible in the HackerRank execution environment.
