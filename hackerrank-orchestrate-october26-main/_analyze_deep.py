import csv, json, hashlib
from pathlib import Path
from collections import defaultdict

base = Path(__file__).parent / "dataset"

# Load CSVs
def load(name):
    with open(base / name, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

requests = {r["case_id"]: r for r in load("sample_deletion_requests.csv")}
outputs = {r["case_id"]: r for r in load("sample_output.csv")}
identities = load("user_identities.csv")
audit = load("user_audit_log.csv")
activity = load("system_activity.csv")
evidence_files = {r["file_id"]: r for r in load("evidence_files.csv")}

id_by_email = {r["email"].lower(): r for r in identities}

print("=== IDENTITY RESOLUTION FOR SAMPLE CASES ===")
for cid in sorted(requests):
    req = requests[cid]
    email = req["email"].lower()
    user = id_by_email.get(email)
    # also check audit history
    hist = [a for a in audit if a.get("old_email", "").lower() == email or a.get("new_email", "").lower() == email]
    # find user_id via audit if needed
    uid = user["user_id"] if user else None
    if not uid and hist:
        uid = hist[0].get("user_id")
    print(f"{cid}: email={email} user={uid} name={user['full_name'] if user else None} audit_hits={len(hist)}")
    for h in hist[:5]:
        print(f"    audit: {h}")

print("\n=== EVIDENCE FILES CITED ===")
cited = set()
for cid, out in outputs.items():
    for s in json.loads(out["steps_json"]):
        e = s.get("evidence_id") or ""
        if e.startswith("evidence_"):
            cited.add(e)
for eid in sorted(cited, key=lambda x: int(x.split("_")[1])):
    ef = evidence_files.get(eid, {})
    print(f"{eid}: {ef.get('file_name')} path={ef.get('file_path')} type={ef.get('file_type')} desc={ef.get('description','')[:80]}")

print("\n=== SYSTEM ACTIVITY RELATED TO SAMPLE USERS ===")
# map sample emails to user_ids
sample_uids = {}
for cid, req in requests.items():
    email = req["email"].lower()
    user = id_by_email.get(email)
    uid = user["user_id"] if user else None
    if not uid:
        hist = [a for a in audit if a.get("old_email", "").lower() == email or a.get("new_email", "").lower() == email]
        if hist:
            uid = hist[0]["user_id"]
    sample_uids[cid] = uid

# Check activity columns
print("activity columns:", activity[0].keys() if activity else None)
for cid in ["case_01", "case_05", "case_11", "case_31", "case_32", "case_10", "case_12", "case_29", "case_14", "case_15", "case_17"]:
    uid = sample_uids[cid]
    acts = [a for a in activity if a.get("user_id") == uid]
    print(f"\n{cid} user={uid} activities={len(acts)}")
    for a in acts[:15]:
        print(" ", {k: a[k] for k in list(a.keys())[:12]})

print("\n=== AUDIT LOG SCHEMA + EMAIL CHANGE CASES ===")
print("audit columns:", audit[0].keys() if audit else None)
for cid in ["case_10", "case_12", "case_29"]:
    req = requests[cid]
    email = req["email"].lower()
    user = id_by_email.get(email)
    print(f"\n{cid} request_email={email} current_identity={user}")
    # find all emails for this user
    if user:
        uid = user["user_id"]
        hist = [a for a in audit if a["user_id"] == uid]
        print("  history:", hist)
        # also find other identity rows?
        
print("\n=== HASH CHECK ===")
# email hash sha256?
for cid in ["case_01", "case_05"]:
    user = id_by_email[requests[cid]["email"].lower()]
    h = hashlib.sha256(user["email"].encode()).hexdigest()
    print(cid, "stored", user.get("email_hash") or user.get("email_sha256"), "sha256(email)", h)
    print("  identity fields:", user.keys())
