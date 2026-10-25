import csv, json, re
from pathlib import Path
from collections import defaultdict, Counter

base = Path(__file__).parent / "dataset"

def load(name):
    with open(base / name, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

requests = {r["case_id"]: r for r in load("sample_deletion_requests.csv")}
outputs = {r["case_id"]: r for r in load("sample_output.csv")}
identities = {r["email"].lower(): r for r in load("user_identities.csv")}
identities_by_id = {r["user_id"]: r for r in load("user_identities.csv")}
audit = load("user_audit_log.csv")
activity = load("system_activity.csv")

# Evidence id usage: any activity_id or audit_id in sample?
print("=== EVIDENCE_ID PREFIX COUNTS IN SAMPLE ===")
pref = Counter()
for out in outputs.values():
    for s in json.loads(out["steps_json"]):
        e = s.get("evidence_id") or "EMPTY"
        if e == "EMPTY" or e == "":
            pref["EMPTY"] += 1
        else:
            pref[e.split("_")[0]] += 1
print(pref)

# Mapping finding -> remed -> verify by system type
print("\n=== SYSTEM -> FINDING/REMED/VERIFY MAPPING ===")
mapping = defaultdict(set)
for out in outputs.values():
    steps = json.loads(out["steps_json"])
    by_res = defaultdict(list)
    for s in steps:
        by_res[(s["system_id"], s["resource_id"])].append(s)
    for key, slist in by_res.items():
        ops = tuple((s["phase"], s["operation"], s["state"]) for s in slist)
        mapping[key[0]].add(ops)

for sys, opsets in sorted(mapping.items()):
    print(f"\n{sys}:")
    for ops in sorted(opsets):
        print(" ", ops)

# Resource prefix -> category inference
print("\n=== RESOURCE PREFIX PATTERNS ===")
prefix_ops = defaultdict(set)
for out in outputs.values():
    for s in json.loads(out["steps_json"]):
        pref = s["resource_id"].split("_")[0]
        if pref == "audit":
            pref = "audit_record"
        elif pref == "data":
            pref = "data_flow"
        prefix_ops[(s["system_id"], pref)].add((s["phase"], s["operation"]))
for k, v in sorted(prefix_ops.items()):
    print(k, "->", sorted(v))

# COMPLETE cases: which resources appear in verification only
print("\n=== COMPLETE CASE VERIFY SETS ===")
for cid, out in outputs.items():
    if out["deletion_status"] != "COMPLETE":
        continue
    steps = json.loads(out["steps_json"])
    print(cid, [(s["operation"], s["system_id"], s["resource_id"], s["evidence_id"]) for s in steps])

# Email history cases
print("\n=== EMAIL CHANGE HISTORY FOR SAMPLE ===")
for cid, req in requests.items():
    email = req["email"].lower()
    user = identities.get(email)
    if not user:
        # search audit for this email as old or new
        hits = [a for a in audit if a["old_value"].lower() == email or a["new_value"].lower() == email]
        print(cid, "NOT in identities, audit hits:", hits[:3])
        continue
    uid = user["user_id"]
    hist = [a for a in audit if a["user_id"] == uid and a["field_name"] == "email"]
    if hist:
        print(f"{cid} {uid} current={email}")
        for h in hist:
            print(f"  {h['audit_id']} {h['event_time']} {h['old_value']} -> {h['new_value']}")

# case_12 analytics DELETE anomaly - what category?
print("\n=== case_12 special analytics DELETE ===")
# look in evidence_01 for analytics_9914
p = base / "evidence/logs/service_events_ap_south_20260915.log"
text = p.read_text(encoding="utf-8", errors="replace")
for line in text.splitlines():
    if "analytics_9914" in line or "minjun" in line.lower() or "user_12" in line:
        print(line[:300])

# Support DELETE vs REDACT
print("\n=== SUPPORT FINDINGS ===")
for cid, out in outputs.items():
    for s in json.loads(out["steps_json"]):
        if s["system_id"] == "support_platform" and s["phase"] == "FINDING":
            print(cid, s["operation"], s["resource_id"], "-> remeds later")

# When is VERIFY_RECORD_PRESENT used
print("\n=== VERIFY_RECORD_PRESENT always security_service? ===")
for cid, out in outputs.items():
    for s in json.loads(out["steps_json"]):
        if s["operation"] == "VERIFY_RECORD_PRESENT":
            print(cid, s["system_id"], s["resource_id"], s["evidence_id"] or "EMPTY")

# INCOMPLETE verification always includes account ABSENT even if not in findings?
print("\n=== INCOMPLETE: account absent in verify without finding? ===")
for cid, out in outputs.items():
    if out["deletion_status"] != "INCOMPLETE":
        continue
    steps = json.loads(out["steps_json"])
    find_accounts = [s for s in steps if s["phase"]=="FINDING" and s["system_id"]=="account_service"]
    ver_accounts = [s for s in steps if s["phase"]=="VERIFICATION" and s["system_id"]=="account_service"]
    print(f"{cid}: find_acct={len(find_accounts)} ver_acct={[(s['operation'], s['resource_id']) for s in ver_accounts]}")

# security present without finding?
print("\n=== INCOMPLETE: security PRESENT without finding? ===")
for cid, out in outputs.items():
    if out["deletion_status"] != "INCOMPLETE":
        continue
    steps = json.loads(out["steps_json"])
    find_sec = [s for s in steps if s["phase"]=="FINDING" and s["system_id"]=="security_service"]
    ver_sec = [s for s in steps if s["operation"]=="VERIFY_RECORD_PRESENT"]
    print(f"{cid}: find_sec={len(find_sec)} ver_present={[(s['system_id'], s['resource_id']) for s in ver_sec]}")

# NOT_APPLICABLE?
print("\nstatuses:", Counter(o["deletion_status"] for o in outputs.values()))

# Multilingual requests
print("\n=== REQUEST LANGUAGES / NOT DELETION? ===")
for cid, req in requests.items():
    print(f"{cid}: {req['request_text'][:80]}...")
