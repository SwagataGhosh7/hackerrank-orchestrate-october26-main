"""Small, offline evaluation workflow for the deletion audit agent."""

from __future__ import annotations

import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> None:
    sample = load(ROOT / "sample_pred.csv") if (ROOT / "sample_pred.csv").exists() else []
    expected = load(ROOT / "dataset" / "sample_output.csv")
    if sample:
        status_accuracy = sum(
            left["deletion_status"] == right["deletion_status"]
            for left, right in zip(sample, expected)
        ) / len(expected)
        print(f"sample status accuracy: {status_accuracy:.3f}")

    output = load(ROOT / "output.csv")
    assert len(output) == len(load(ROOT / "dataset" / "deletion_requests.csv"))
    assert output and list(output[0]) == ["case_id", "deletion_status", "steps_json"]
    for row in output:
        steps = json.loads(row["steps_json"])
        assert isinstance(steps, list)
        assert [step["step_no"] for step in steps] == list(range(1, len(steps) + 1))
        assert row["deletion_status"] in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
        if row["deletion_status"] == "NOT_APPLICABLE":
            assert steps == []
    print(f"full rows validated: {len(output)}")


if __name__ == "__main__":
    main()