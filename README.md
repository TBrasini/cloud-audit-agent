# Cloud Audit Agent

Scanner de sécurité cloud (AWS) qui détecte des mauvaises configurations à partir de contrôles inspirés du **CIS AWS Foundations Benchmark**, puis génère un **rapport d'audit professionnel** rédigé par l'API Claude (Anthropic). Interface Streamlit incluse pour lancer un scan et consulter le rapport.

## Pourquoi ce projet

Auditeur IT de formation ingénieur, je voulais un projet qui me remette à niveau sur le cloud, le dev et l'IA générative appliquée — tout en restant dans mon domaine d'expertise : l'audit et la conformité. Ce projet reproduit, en miniature, un vrai flux d'audit : collecte des faits techniques → analyse contre un référentiel → rapport structuré avec recommandations priorisées.

## Ce que ça démontre

- **Cloud / AWS** : lecture d'une infrastructure via `boto3` (IAM, S3, EC2, CloudTrail)
- **Sécurité / audit** : contrôles alignés sur un référentiel reconnu (CIS Benchmark), sévérités, recommandations actionnables
- **IA générative appliquée** : intégration de l'API Claude pour transformer des données brutes en rapport rédigé, avec un design robuste (fallback local si pas de clé API)
- **Dev / ingénierie logicielle** : tests unitaires (`pytest` + `moto` pour mocker AWS), lint (`ruff`), CI (`GitHub Actions`), conteneurisation (`Docker`)
- **Infra as Code** : environnement de démo `Terraform` volontairement mal configuré, pour tester le scanner de façon reproductible

## Architecture

```
scanner/   → contrôles de sécurité (checks.py) + orchestrateur (scan.py) + données mock
report/    → génération du rapport d'audit via l'API Claude (avec fallback sans IA)
app/       → interface Streamlit (scan + affichage + téléchargement du rapport)
terraform/ → infra de démo intentionnellement vulnérable, pour tester le scanner
tests/     → tests unitaires (checks AWS mockés avec moto, scan end-to-end)
```

Flux : `scan AWS (ou mock)` → `findings.json` → `Claude API` → `report.md` (+ vue Streamlit).

## Contrôles implémentés

| ID | Contrôle | Sévérité |
|---|---|---|
| S3-01 | Bucket S3 sans Block Public Access complet | HIGH |
| IAM-01 | Politique IAM avec `Action:*` / `Resource:*` | HIGH |
| SG-01 / SG-02 | Security group ouvert à `0.0.0.0/0` (SSH, RDP, DB, ou tous ports) | HIGH |
| EBS-01 | Volume EBS non chiffré | MEDIUM |
| CT-01 / CT-02 / CT-03 | CloudTrail absent, non multi-région, ou sans validation d'intégrité | HIGH / MEDIUM / LOW |
| ROOT-01 | MFA désactivé sur le compte root | HIGH |

## Démarrage rapide (mode démo, sans compte AWS)

```bash
pip install -r requirements.txt

# Scan avec des données d'exemple, aucun credential requis
python -m scanner.scan --mode mock --output findings.json

# Rapport (template local si pas de clé API, ou rédigé par Claude si ANTHROPIC_API_KEY est configurée)
python -m report.generate_report --input findings.json --output report.md

# Interface web
streamlit run app/app.py
```

## Utilisation sur un vrai compte AWS

```bash
cp .env.example .env   # renseigner ANTHROPIC_API_KEY, AWS_PROFILE, AWS_REGION

python -m scanner.scan --mode aws --profile default --region eu-west-3 --output findings.json
python -m report.generate_report --input findings.json --output report.md
```

Permissions IAM en lecture seule nécessaires : `s3:ListAllMyBuckets`, `s3:GetBucketPublicAccessBlock`, `iam:ListPolicies`, `iam:GetPolicyVersion`, `iam:GetAccountSummary`, `ec2:DescribeSecurityGroups`, `ec2:DescribeVolumes`, `cloudtrail:DescribeTrails`.

## Windows

Toutes les commandes ci-dessus fonctionnent sous Windows, avec ces équivalences :

```powershell
# Environnement virtuel
python -m venv venv
venv\Scripts\activate

# Copier le fichier d'exemple (CMD)
copy .env.example .env
# PowerShell : cp fonctionne aussi (alias de Copy-Item)
```

Docker nécessite Docker Desktop ; Terraform nécessite `terraform.exe` dans le PATH. Le reste (pip, python, streamlit, pytest, ruff) est strictement identique.

## Tester le scanner sur une infra volontairement vulnérable

Le dossier `terraform/` provisionne un bucket S3 public, un security group ouvert sur le port 22, et un volume EBS non chiffré — utile pour valider le scanner sur un compte AWS **sandbox jetable** (jamais en production).

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

## Stack technique

Python · boto3 · Anthropic API (Claude) · Streamlit · pytest · moto · ruff · Docker · GitHub Actions · Terraform

## Limites et pistes d'évolution

- Couverture de contrôles volontairement réduite (6 familles) — extensible à d'autres services (RDS, KMS, VPC Flow Logs, etc.)
- Pas de persistance des scans dans le temps (pas d'historique/diff entre deux audits)
- Génération de rapport en Markdown uniquement — export PDF possible en ajout futur
- Support Azure/GCP non implémenté (architecture des checks pensée pour être extensible dans ce sens)

## Licence

MIT — projet personnel à but de démonstration.
