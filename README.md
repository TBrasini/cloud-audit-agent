# Cloud Audit Agent

[![Live Demo](https://img.shields.io/badge/demo-live-brightgreen?logo=streamlit&logoColor=white)](https://cloud-audit-agent-j2appppfzs7un2cshsbyquck.streamlit.app/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)

AWS security scanner that detects misconfigurations using controls inspired by the **CIS AWS Foundations Benchmark**, then generates a **professional audit report** written by the Claude API (Anthropic). Includes a Streamlit interface to run a scan and review the report.

## Why this project

Trained as an engineer, I now work as an IT auditor. I wanted a project that would refresh my cloud, dev, and applied generative AI skills — while staying close to my domain of expertise: audit and compliance. This project reproduces, at a small scale, a real audit workflow: gathering technical facts → analyzing them against a reference framework → producing a structured report with prioritized recommendations.

## What this demonstrates

- **Cloud / AWS**: reading infrastructure state via `boto3` (IAM, S3, EC2, CloudTrail)
- **Security / audit**: controls aligned with a recognized framework (CIS Benchmark), severities, actionable recommendations
- **Applied generative AI**: integrating the Claude API to turn raw findings into a written report, with a resilient design (local fallback when no API key is set)
- **Software engineering**: unit tests (`pytest` + `moto` to mock AWS), linting (`ruff`), CI (`GitHub Actions`), containerization (`Docker`)
- **Infrastructure as Code**: a `Terraform` demo environment intentionally misconfigured, to test the scanner in a reproducible way

## Architecture

```
scanner/   → security checks (checks.py) + orchestrator (scan.py) + mock data
report/    → audit report generation via the Claude API (with a non-AI fallback)
app/       → Streamlit interface (scan + display + report download)
terraform/ → intentionally vulnerable demo infrastructure, to test the scanner
tests/     → unit tests (AWS checks mocked with moto, end-to-end scan)
```

Flow: `AWS scan (or mock)` → `findings.json` → `Claude API` → `report.md` (+ Streamlit view).

## Implemented controls

| ID | Control | Severity |
|---|---|---|
| S3-01 | S3 bucket without full Block Public Access | HIGH |
| IAM-01 | IAM policy with `Action:*` / `Resource:*` | HIGH |
| SG-01 / SG-02 | Security group open to `0.0.0.0/0` (SSH, RDP, DB, or all ports) | HIGH |
| EBS-01 | Unencrypted EBS volume | MEDIUM |
| CT-01 / CT-02 / CT-03 | CloudTrail missing, not multi-region, or without log file validation | HIGH / MEDIUM / LOW |
| ROOT-01 | MFA disabled on the root account | HIGH |

## Quickstart (demo mode, no AWS account needed)

```bash
pip install -r requirements.txt

# Scan with sample data, no credentials required
python -m scanner.scan --mode mock --output findings.json

# Report (local template if no API key, or written by Claude if ANTHROPIC_API_KEY is set)
python -m report.generate_report --input findings.json --output report.md

# Web interface
streamlit run app/app.py
```

## Using a real AWS account

```bash
cp .env.example .env   # fill in ANTHROPIC_API_KEY, AWS_PROFILE, AWS_REGION

python -m scanner.scan --mode aws --profile default --region eu-west-3 --output findings.json
python -m report.generate_report --input findings.json --output report.md
```

Required read-only IAM permissions: `s3:ListAllMyBuckets`, `s3:GetBucketPublicAccessBlock`, `iam:ListPolicies`, `iam:GetPolicyVersion`, `iam:GetAccountSummary`, `ec2:DescribeSecurityGroups`, `ec2:DescribeVolumes`, `cloudtrail:DescribeTrails`.

## Windows

All commands above work on Windows, with these equivalents:

```powershell
# Virtual environment
python -m venv venv
venv\Scripts\activate

# Copy the example file (CMD)
copy .env.example .env
# PowerShell: cp also works (alias for Copy-Item)
```

Docker requires Docker Desktop; Terraform requires `terraform.exe` on the PATH. Everything else (pip, python, streamlit, pytest, ruff) is identical.

## Testing the scanner against intentionally vulnerable infrastructure

The `terraform/` folder provisions a public S3 bucket, a security group open on port 22, and an unencrypted EBS volume — useful to validate the scanner on a **disposable sandbox** AWS account (never on production).

```bash
cd terraform
terraform init
terraform apply
```

## Docker

```bash
docker build -t cloud-audit-agent .
docker run -p 8501:8501 --env-file .env cloud-audit-agent
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest -v
ruff check .
```

## Tech stack

Python · boto3 · Anthropic API (Claude) · Streamlit · pytest · moto · ruff · Docker · GitHub Actions · Terraform

## Limitations and roadmap

- Coverage is intentionally limited (6 control families) — extensible to other services (RDS, KMS, VPC Flow Logs, etc.)
- No persistence of scans over time (no history/diff between two audits)
- Report generation is Markdown only — PDF export is a possible future addition
- Azure/GCP support not implemented (the checks architecture is designed to be extensible in that direction)

## License

MIT — personal project for demonstration purposes.
