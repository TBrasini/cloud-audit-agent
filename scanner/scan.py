"""
Orchestrateur du scan de sécurité cloud.

Usage:
    python -m scanner.scan --mode mock --output findings.json
    python -m scanner.scan --mode aws --profile default --region eu-west-3 --output findings.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from scanner.checks import ALL_CHECKS
from scanner.mock_data import MOCK_FINDINGS


def run_aws_scan(profile: str | None, region: str | None) -> list[dict]:
    import boto3  # import local pour ne pas exiger boto3 en mode mock uniquement

    session = boto3.Session(profile_name=profile, region_name=region)
    clients = {
        "s3": session.client("s3"),
        "iam": session.client("iam"),
        "ec2": session.client("ec2"),
        "cloudtrail": session.client("cloudtrail"),
    }

    findings: list[dict] = []
    for client_name, check_fn in ALL_CHECKS:
        client = clients[client_name]
        findings.extend(check_fn(client))
    return findings


def build_report_payload(findings: list[dict], mode: str, account_id: str | None = None) -> dict:
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings_sorted = sorted(findings, key=lambda f: severity_order.get(f["severity"], 3))
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "account_id": account_id,
        "summary": counts,
        "total_findings": len(findings),
        "findings": findings_sorted,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scanner de sécurité cloud (démo audit AWS).")
    parser.add_argument("--mode", choices=["mock", "aws"], default="mock",
                         help="mock = données d'exemple sans credentials, aws = scan réel")
    parser.add_argument("--profile", default=None, help="Profil AWS (mode aws uniquement)")
    parser.add_argument("--region", default=None, help="Région AWS (mode aws uniquement)")
    parser.add_argument("--output", default="findings.json", help="Fichier JSON de sortie")
    args = parser.parse_args(argv)

    if args.mode == "mock":
        findings = MOCK_FINDINGS
        account_id = "000000000000 (mock)"
    else:
        findings = run_aws_scan(args.profile, args.region)
        account_id = None

    payload = build_report_payload(findings, args.mode, account_id)

    Path(args.output).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[OK] {payload['total_findings']} findings -> {args.output}")
    print(f"     HIGH={payload['summary'].get('HIGH', 0)} "
          f"MEDIUM={payload['summary'].get('MEDIUM', 0)} "
          f"LOW={payload['summary'].get('LOW', 0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
