import csv, json
from collections import defaultdict, Counter
from pathlib import Path

base = Path(__file__).parent / "dataset"

with open(base / "sample_output.csv", newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

print("=== CASE SUMMARIES ===")
for r in rows:
    steps = json.loads(r["steps_json"])
    phases = Counter(s["phase"] for s in steps) if steps else {}
    ops = [f"{s['phase']}:{s['operation']}" for s in steps]
    print(f"{r['case_id']}: {r['deletion_status']} n={len(steps)} phases={dict(phases)}")

print("\n=== DETAILED CASES ===")
for cid in ["case_01", "case_05", "case_11", "case_31", "case_32"]:
    r = next(x for x in rows if x["case_id"] == cid)
    steps = json.loads(r["steps_json"])
    print(f"\n----- {cid} {r['deletion_status']} -----")
    for s in steps:
        print(json.dumps(s, ensure_ascii=False))

print("\n=== ALL CASES FULL STEPS (compact) ===")
for r in rows:
    steps = json.loads(r["steps_json"])
    print(f"\n===== {r['case_id']} {r['deletion_status']} =====")
    for s in steps:
        print(
            f"  {s['step_no']:2d} {s['phase']:12s} {s['operation']:28s} "
            f"{s['state']:12s} sys={s['system_id']:25s} res={s['resource_id']:30s} "
            f"ev={s.get('evidence_id','')!r}"
        )

print("\n=== OP ORDER ANALYSIS PER PHASE ===")
# Check within each case whether ops follow table order
FINDING_ORDER = [
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
]
REMED_ORDER = [
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
]
VERIFY_ORDER = [
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
]
order_maps = {"FINDING": FINDING_ORDER, "REMEDIATION": REMED_ORDER, "VERIFICATION": VERIFY_ORDER}

violations = []
for r in rows:
    steps = json.loads(r["steps_json"])
    by_phase = defaultdict(list)
    for s in steps:
        by_phase[s["phase"]].append(s)
    # phase order
    phase_seq = [s["phase"] for s in steps]
    phase_rank = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
    for a, b in zip(phase_seq, phase_seq[1:]):
        if phase_rank[a] > phase_rank[b]:
            violations.append((r["case_id"], "phase order", a, b))
    for phase, slist in by_phase.items():
        om = order_maps[phase]
        ranks = [om.index(s["operation"]) for s in slist]
        for a, b in zip(ranks, ranks[1:]):
            if a > b:
                violations.append((r["case_id"], phase, "op order"))
        # within same op, system_id then resource_id
        i = 0
        while i < len(slist):
            j = i
            while j < len(slist) and slist[j]["operation"] == slist[i]["operation"]:
                j += 1
            chunk = slist[i:j]
            keys = [(s["system_id"], s["resource_id"]) for s in chunk]
            if keys != sorted(keys):
                violations.append((r["case_id"], phase, slist[i]["operation"], "sys/res sort", keys))
            i = j

print("violations:", violations if violations else "NONE")

print("\n=== FINDING->REMED->VERIFY PAIRING PATTERNS ===")
for r in rows:
    steps = json.loads(r["steps_json"])
    if r["deletion_status"] != "INCOMPLETE":
        continue
    findings = [s for s in steps if s["phase"] == "FINDING"]
    remeds = [s for s in steps if s["phase"] == "REMEDIATION"]
    verifies = [s for s in steps if s["phase"] == "VERIFICATION"]
    print(f"\n{r['case_id']}:")
    print("  FIND:", [(s["operation"], s["system_id"], s["resource_id"], s["evidence_id"]) for s in findings])
    print("  REM: ", [(s["operation"], s["system_id"], s["resource_id"], s["evidence_id"]) for s in remeds])
    print("  VER: ", [(s["operation"], s["system_id"], s["resource_id"], s["evidence_id"]) for s in verifies])

print("\n=== EVIDENCE_ID TYPES ===")
for r in rows:
    steps = json.loads(r["steps_json"])
    evids = Counter()
    for s in steps:
        e = s.get("evidence_id") or ""
        if not e:
            evids["EMPTY"] += 1
        elif e.startswith("evidence_"):
            evids["file_id"] += 1
        elif e.startswith("activity_"):
            evids["activity_id"] += 1
        elif e.startswith("audit_"):
            evids["audit_id"] += 1
        else:
            evids[e] += 1
    print(f"{r['case_id']} {r['deletion_status']}: {dict(evids)}")

print("\n=== UNIQUE (system, resource, ops) across statuses ===")
# Map resource patterns
sys_ops = defaultdict(set)
for r in rows:
    for s in json.loads(r["steps_json"]):
        sys_ops[(s["system_id"], s["resource_id"][:20])].add(
            (r["deletion_status"], s["phase"], s["operation"], s["state"])
        )
