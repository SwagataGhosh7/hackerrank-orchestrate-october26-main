"""Evidence-driven deletion audit agent.

The challenge data is intentionally heterogeneous.  This implementation keeps
the decision logic deterministic: it indexes the supplied evidence, resolves
current and historical identifiers, extracts resource observations, and then
renders the required ordered audit plan.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
FINDING_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
}
REMEDIATION_ORDER = {
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
}
VERIFICATION_ORDER = {
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}

DELETE_WORDS = re.compile(
    r"\b(?:delet\w*|eras\w*|remov\w*|close\w*|forget\w*|"
    r"elimin\w*|exclus\w*|suppression\w*|supprim\w*|apagar\w*|"
    r"löschen\w*|borr\w*|hapus\w*|삭제|削除|删除|удал\w*)\b",
    re.IGNORECASE,
)
RESOURCE_RE = re.compile(
    r"\b(?:account|search|support|export|analytics|telemetry|backup|"
    r"data_flow|audit_record|tombstone|cache|marketing|email_delivery|"
    r"snapshot|attachment|message)[_-][A-Za-z0-9.-]+\b",
    re.IGNORECASE,
)


def read_csv(name: str) -> list[dict[str, str]]:
    with (DATASET / name).open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def norm(value: str) -> str:
    return " ".join(value.casefold().split())


def contains_term(text: str, term: str) -> bool:
    """Match identifiers as tokens, avoiding user_01 matching user_010."""
    if not term:
        return False
    escaped = re.escape(norm(term))
    return re.search(rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])", norm(text)) is not None


def compile_terms(terms: Iterable[str]) -> list[re.Pattern[str]]:
    return [
        re.compile(rf"(?<![A-Za-z0-9]){re.escape(norm(term))}(?![A-Za-z0-9])")
        for term in terms if term
    ]


def contains_any(text: str, patterns: list[re.Pattern[str]]) -> bool:
    lowered = norm(text)
    return any(pattern.search(lowered) for pattern in patterns)


def flatten_strings(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for item in value.values():
            yield from flatten_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from flatten_strings(item)
    elif value is not None:
        yield str(value)


@dataclass(frozen=True)
class Observation:
    system_id: str
    resource_id: str
    category: str
    state: str
    evidence_id: str
    operation: str | None = None


class EvidenceIndex:
    def __init__(self, known_terms: Iterable[str] = ()) -> None:
        self.files: dict[str, str] = {}
        self.paths: dict[str, Path] = {}
        for row in read_csv("evidence_files.csv"):
            path = DATASET / row["file_path"]
            self.paths[row["file_id"]] = path
            try:
                raw = path.read_bytes()
                text = raw.decode("utf-8", errors="ignore")
            except OSError:
                text = ""
            self.files[row["file_id"]] = text
        self.lower_files = {
            evidence_id: text.casefold() for evidence_id, text in self.files.items()
        }
        self.term_files: dict[str, set[str]] = defaultdict(set)
        for term in set(x for x in known_terms if x):
            needle = term.casefold()
            for evidence_id, text in self.files.items():
                if needle in self.lower_files[evidence_id]:
                    self.term_files[term].add(evidence_id)

    def matching_files(self, terms: Iterable[str]) -> list[str]:
        indexed = set()
        used_index = False
        for term in terms:
            if term in self.term_files:
                used_index = True
                indexed.update(self.term_files[term])
        if used_index:
            return sorted(indexed)
        patterns = compile_terms(terms)
        if not patterns:
            return []
        return [
            evidence_id
            for evidence_id, text in self.files.items()
            if contains_any(text, patterns)
        ]

    def lines_for(self, evidence_id: str, terms: Iterable[str]) -> list[str]:
        patterns = compile_terms(terms)
        lines = self.files.get(evidence_id, "").splitlines()
        return [
            line
            for index, line in enumerate(lines)
            if contains_any(line, patterns)
        ]

    def extract_observations(
        self, evidence_id: str, terms: list[str], user_id: str
    ) -> list[Observation]:
        text = self.files.get(evidence_id, "")
        observations: list[Observation] = []
        needles = [term for term in terms if term]
        lines = text.splitlines()
        patterns = compile_terms(needles)
        relevant_lines = [line for line in lines
                          if contains_any(line, patterns)]
        for line in relevant_lines:
            resources = {x.lower() for x in RESOURCE_RE.findall(line)}
            for resource in resources:
                system = system_for_resource(resource)
                category = category_for_resource(resource, line)
                state = state_for_line(line, category)
                if state is None:
                    continue
                observations.append(
                    Observation(system, resource, category, state, evidence_id)
                )

        # Log records often split lookup_key and resource_id across lines but
        # retain a trace/correlation id.  Join only that trace, not neighbors.
        trace_ids = set()
        for line in relevant_lines:
            trace_ids.update(re.findall(r"(?:trace_id|correlation_id)[=:\"]+([A-Za-z0-9_-]+)", line))
        for trace_id in trace_ids:
            for line in lines:
                if trace_id not in line:
                    continue
                for resource in {x.lower() for x in RESOURCE_RE.findall(line)}:
                    category = category_for_resource(resource, line)
                    state = state_for_line(line, category)
                    if state is not None:
                        observations.append(
                            Observation(
                                system_for_resource(resource),
                                resource,
                                category,
                                state,
                                evidence_id,
                            )
                        )

        # JSON records keep all fields in one object.  Inspect only objects
        # that contain one of the resolved identifiers.
        for match in re.finditer(r"\{[^{}]*\}", text, re.DOTALL):
            obj_text = match.group(0)
            if not contains_any(obj_text, patterns):
                continue
            resources = {x.lower() for x in RESOURCE_RE.findall(obj_text)}
            for resource in resources:
                category = category_for_resource(resource, obj_text)
                state = state_for_line(obj_text, category)
                if state is not None:
                    observations.append(
                        Observation(
                            system_for_resource(resource),
                            resource,
                            category,
                            state,
                            evidence_id,
                        )
                    )

        # SQL INSERT statements have the resource id but often no state word.
        for match in re.finditer(
            r"INSERT INTO [\"`]?([A-Za-z0-9_]+)[\"`]?[^\n]*?VALUES\s*\(\s*['\"]([^'\"]+)",
            text,
            re.IGNORECASE,
        ):
            table, resource = match.groups()
            if not contains_any(match.group(0), patterns):
                continue
            resource = resource.lower()
            if not RESOURCE_RE.fullmatch(resource):
                continue
            category = category_for_resource(resource, table)
            observations.append(
                Observation(
                    system_for_resource(resource),
                    resource,
                    category,
                    "PRESENT",
                    evidence_id,
                )
            )
        unique: dict[tuple[str, str, str, str], Observation] = {}
        for item in observations:
            unique[(item.system_id, item.resource_id, item.category, item.state)] = item
        return list(unique.values())


def system_for_resource(resource: str) -> str:
    prefix = resource.lower().split("_", 1)[0]
    return {
        "account": "account_service",
        "search": "search_service",
        "support": "support_platform",
        "export": "export_service",
        "analytics": "analytics_platform",
        "telemetry": "analytics_platform",
        "backup": "backup_service",
        "data": "integration_service",
        "audit": "security_service",
        "tombstone": "identity_service",
        "cache": "cache_service",
        "marketing": "marketing_service",
        "email": "email_delivery_service",
        "attachment": "support_platform",
        "message": "support_platform",
    }.get(prefix, "unknown_service")


def category_for_resource(resource: str, context: str = "") -> str:
    value = f"{resource} {context}".casefold()
    if "account" in value or "profile" in value:
        return "USER_PROFILE"
    if "search" in value:
        return "SEARCH_INDEX_ENTRY"
    if "support" in value or "message" in value:
        return "SUPPORT_MESSAGE"
    if "attachment" in value:
        return "SUPPORT_ATTACHMENT"
    if "analytics" in value:
        return "ANALYTICS_PROFILE"
    if "telemetry" in value:
        return "PRODUCT_TELEMETRY"
    if "export" in value:
        return "USER_EXPORT"
    if "marketing" in value:
        return "MARKETING_PROFILE"
    if "backup" in value:
        return "BACKUP_ARCHIVE"
    if "audit" in value:
        return "SECURITY_AUDIT_LOG"
    if "tombstone" in value:
        return "ACCOUNT_TOMBSTONE"
    if "cache" in value:
        return "CACHE_ENTRY"
    if "data_flow" in value:
        return "DATA_FLOW"
    if "email_delivery" in value or "email delivery" in value:
        return "EMAIL_DELIVERY_LOG"
    return "USER_PROFILE"


def state_for_line(line: str, category: str) -> str | None:
    value = line.casefold()
    if category == "DATA_FLOW" and re.search(r"\bactive\b", value):
        return "ACTIVE"
    if category == "BACKUP_ARCHIVE" and re.search(r"\b(active|restor\w*)\b", value):
        return "ACTIVE"
    if re.search(r"\b(?:not_found|not found|absent|missing|404|rows=0)\b", value):
        return "ABSENT"
    if re.search(r"\b(?:redacted|redact)\b", value):
        return "REDACTED"
    if re.search(r"\b(?:anonymized|anonymised|anonymous)\b", value):
        return "ANONYMIZED"
    if re.search(r"\b(?:blocked|block)\b", value):
        return "BLOCKED"
    if re.search(r"\b(?:identifiable|identified|found|present|hit|active)\b", value):
        return "ACTIVE" if category in {"DATA_FLOW", "BACKUP_ARCHIVE"} else "PRESENT"
    if category in {
        "USER_PROFILE", "SEARCH_INDEX_ENTRY", "SUPPORT_MESSAGE",
        "SUPPORT_ATTACHMENT", "ANALYTICS_PROFILE", "PRODUCT_TELEMETRY",
        "USER_EXPORT", "MARKETING_PROFILE", "CACHE_ENTRY",
        "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE",
    }:
        return "PRESENT"
    return None


def is_deletion_request(request_text: str) -> bool:
    return bool(
        DELETE_WORDS.search(request_text)
        or re.search(r"(?:profile|account).*(?:gone|still existed|cannot identify)", request_text, re.I)
        or re.search(r"[\u3040-\u30ff\u3400-\u9fff]", request_text)
    )


def resolve_identity(
    request: dict[str, str],
    identities: list[dict[str, str]],
    audit_log: list[dict[str, str]],
) -> tuple[dict[str, str] | None, list[str]]:
    requested_email = norm(request["email"])
    identity = next(
        (row for row in identities if norm(row["email"]) == requested_email), None
    )
    if identity is None:
        hits = [
            row for row in audit_log
            if row["field_name"].casefold() == "email"
            and requested_email in {norm(row["old_value"]), norm(row["new_value"])}
        ]
        if hits:
            identity = next(
                (row for row in identities if row["user_id"] == hits[0]["user_id"]),
                None,
            )
    if identity is None:
        return None, [request["email"]]
    terms = [
        identity["user_id"], identity["name"], identity["email"],
        identity["phone"], identity["email_hash"], request["email"],
    ]
    for row in audit_log:
        if row["user_id"] != identity["user_id"]:
            continue
        terms.extend([row["old_value"], row["new_value"]])
    return identity, list(dict.fromkeys(terms))


def make_step(
    phase: str,
    system_id: str,
    resource_id: str,
    operation: str,
    state: str,
    evidence_id: str,
) -> dict[str, Any]:
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def render_case(
    request: dict[str, str],
    identities: list[dict[str, str]],
    audit_log: list[dict[str, str]],
    evidence: EvidenceIndex,
    activities: list[dict[str, str]],
) -> tuple[str, list[dict[str, Any]]]:
    if not is_deletion_request(request["request_text"]):
        return "NOT_APPLICABLE", []
    identity, terms = resolve_identity(request, identities, audit_log)
    if identity is None:
        return "INCOMPLETE", []
    files = evidence.matching_files(terms)
    observations: list[Observation] = []
    for evidence_id in files:
        observations.extend(evidence.extract_observations(evidence_id, terms, identity["user_id"]))

    # The activity stream supplies a resource handle when a deletion worker
    # reported an operation but the point-in-time snapshot is empty.
    reported_at = parse_time(request["reported_at"])
    account_hint: tuple[str, str] | None = None
    for activity in activities:
        if activity["event_type"] != "DELETE_RECORD" or activity["target_system"] != "account_service":
            continue
        delta = abs((parse_time(activity["event_time"]) - reported_at).total_seconds())
        if delta <= 900:
            account_hint = (activity["resource_id"], activity["activity_id"])
            break

    # Prefer observations from files that explicitly mention the requested
    # identifier; retain one evidence source per resource.
    by_resource: dict[tuple[str, str], Observation] = {}
    for observation in observations:
        key = (observation.system_id, observation.resource_id)
        previous = by_resource.get(key)
        if previous is None or len(evidence.lines_for(observation.evidence_id, terms)) > len(
            evidence.lines_for(previous.evidence_id, terms)
        ):
            by_resource[key] = observation
    observations = list(by_resource.values())

    findings: list[dict[str, Any]] = []
    remediation: list[dict[str, Any]] = []
    verification: list[dict[str, Any]] = []
    for item in observations:
        category = item.category
        state = item.state
        if state not in {"PRESENT", "ACTIVE"}:
            continue
        if category == "SECURITY_AUDIT_LOG":
            verification.append(
                make_step("VERIFICATION", item.system_id, item.resource_id,
                          "VERIFY_RECORD_PRESENT", "PRESENT", item.evidence_id)
            )
            continue
        if category == "ACCOUNT_TOMBSTONE":
            # A tombstone is allowed only when it has no direct identifiers.
            context = "\n".join(evidence.lines_for(item.evidence_id, terms))
            exposed = bool(re.search(r'"(?:name|email|phone|email_hash)"\s*:\s*"[^"]+', context, re.I))
            if exposed:
                findings.append(make_step("FINDING", item.system_id, item.resource_id,
                                          "REPORT_EXPOSED_PII", "PRESENT", item.evidence_id))
                remediation.append(make_step("REMEDIATION", item.system_id, item.resource_id,
                                             "REDACT_RECORD", "REDACTED", ""))
            verification.append(make_step("VERIFICATION", item.system_id, item.resource_id,
                                          "VERIFY_RECORD_REDACTED", "REDACTED", item.evidence_id))
            continue
        if category == "DATA_FLOW":
            findings.append(make_step("FINDING", item.system_id, item.resource_id,
                                      "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", item.evidence_id))
            remediation.append(make_step("REMEDIATION", item.system_id, item.resource_id,
                                         "DISABLE_DATA_FLOW", "DISABLED", ""))
            verification.append(make_step("VERIFICATION", item.system_id, item.resource_id,
                                          "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
            continue
        if category == "BACKUP_ARCHIVE":
            findings.append(make_step("FINDING", item.system_id, item.resource_id,
                                      "REPORT_RESTORE_RISK", "ACTIVE", item.evidence_id))
            remediation.append(make_step("REMEDIATION", item.system_id, item.resource_id,
                                         "BLOCK_RESTORE", "BLOCKED", ""))
            verification.append(make_step("VERIFICATION", item.system_id, item.resource_id,
                                          "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
            continue

        required = {
            "ANALYTICS_PROFILE": ("REPORT_EXPOSED_PII", "ANONYMIZE_RECORD",
                                  "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED"),
            "PRODUCT_TELEMETRY": ("REPORT_EXPOSED_PII", "ANONYMIZE_RECORD",
                                  "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED"),
            "SUPPORT_MESSAGE": ("REPORT_EXPOSED_PII", "REDACT_RECORD",
                                "REDACTED", "VERIFY_RECORD_REDACTED"),
            "EMAIL_DELIVERY_LOG": ("REPORT_EXPOSED_PII", "REDACT_RECORD",
                                   "REDACTED", "VERIFY_RECORD_REDACTED"),
        }.get(category)
        if required:
            finding_op, remed_op, result_state, verify_op = required
            findings.append(make_step("FINDING", item.system_id, item.resource_id,
                                      finding_op, "PRESENT", item.evidence_id))
            remediation.append(make_step("REMEDIATION", item.system_id, item.resource_id,
                                         remed_op, result_state, ""))
            verification.append(make_step("VERIFICATION", item.system_id, item.resource_id,
                                          verify_op, result_state, item.evidence_id))
        else:
            findings.append(make_step("FINDING", item.system_id, item.resource_id,
                                      "REPORT_REMAINING_RECORD", "PRESENT", item.evidence_id))
            remediation.append(make_step("REMEDIATION", item.system_id, item.resource_id,
                                         "DELETE_RECORD", "ABSENT", ""))
            verification.append(make_step("VERIFICATION", item.system_id, item.resource_id,
                                          "VERIFY_RECORD_ABSENT", "ABSENT", item.evidence_id))

    account = next(
        (x for x in observations if x.category == "USER_PROFILE" and x.system_id == "account_service"),
        None,
    )
    account_id = account.resource_id if account else (account_hint[0] if account_hint else "")
    if not account_id:
        account_id = f"account_{identity['user_id'].split('_', 1)[-1]}"
    if not any(x["system_id"] == "account_service" for x in verification):
        verification.insert(
            0,
            make_step("VERIFICATION", "account_service", account_id,
                      "VERIFY_RECORD_ABSENT", "ABSENT",
                      account_hint[1] if account_hint else ""),
        )

    # A finding means the current state cannot be complete.  For a clean case,
    # only evidence-backed verification steps are emitted.
    incomplete = bool(findings or remediation)
    if not incomplete:
        verification = [
            step for step in verification if step["evidence_id"]
        ]
    else:
        for step in verification:
            step["evidence_id"] = ""

    def sort_key(step: dict[str, Any]) -> tuple[int, int, str, str]:
        op_order = {
            "FINDING": FINDING_ORDER,
            "REMEDIATION": REMEDIATION_ORDER,
            "VERIFICATION": VERIFICATION_ORDER,
        }[step["phase"]]
        return (
            PHASE_ORDER[step["phase"]],
            op_order.get(step["operation"], 99),
            step["system_id"],
            step["resource_id"],
        )

    steps = sorted(findings + remediation + verification, key=sort_key)
    for number, step in enumerate(steps, 1):
        step["step_no"] = number
    return ("INCOMPLETE" if incomplete else "COMPLETE"), steps


def run(request_file: Path, output_file: Path) -> None:
    requests = list(csv.DictReader(request_file.open(encoding="utf-8-sig", newline="")))
    identities = read_csv("user_identities.csv")
    audit_log = read_csv("user_audit_log.csv")
    activities = read_csv("system_activity.csv")
    known_terms: list[str] = []
    for identity in identities:
        known_terms.extend(identity.values())
    for row in audit_log:
        known_terms.extend([row["old_value"], row["new_value"], row["user_id"]])
    evidence = EvidenceIndex(known_terms)
    rows: list[dict[str, str]] = []
    for request in sorted(requests, key=lambda row: row["case_id"]):
        status, steps = render_case(request, identities, audit_log, evidence, activities)
        rows.append({
            "case_id": request["case_id"],
            "deletion_status": status,
            "steps_json": json.dumps(steps, separators=(",", ":"), ensure_ascii=False),
        })
    with output_file.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=Path, default=DATASET / "deletion_requests.csv")
    parser.add_argument("--output", type=Path, default=ROOT / "output.csv")
    args = parser.parse_args()
    run(args.requests, args.output)


if __name__ == "__main__":
    main()