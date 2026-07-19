import json

from scanner.scan import build_report_payload, main
from scanner.mock_data import MOCK_FINDINGS


def test_build_report_payload_counts_severities():
    payload = build_report_payload(MOCK_FINDINGS, "mock")
    assert payload["total_findings"] == len(MOCK_FINDINGS)
    assert payload["summary"]["HIGH"] + payload["summary"]["MEDIUM"] + payload["summary"]["LOW"] == len(MOCK_FINDINGS)


def test_findings_sorted_by_severity():
    payload = build_report_payload(MOCK_FINDINGS, "mock")
    severities = [f["severity"] for f in payload["findings"]]
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    assert severities == sorted(severities, key=lambda s: order[s])


def test_cli_mock_mode_writes_json(tmp_path):
    output = tmp_path / "findings.json"
    rc = main(["--mode", "mock", "--output", str(output)])
    assert rc == 0
    assert output.exists()
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["total_findings"] == len(MOCK_FINDINGS)
