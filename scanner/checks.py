"""
Contrôles de sécurité cloud inspirés du CIS AWS Foundations Benchmark.

Chaque fonction prend un client boto3 et retourne une liste de findings
au format standard :

{
    "check_id": "S3-01",
    "title": "...",
    "severity": "HIGH" | "MEDIUM" | "LOW",
    "resource": "arn ou identifiant",
    "description": "...",
    "recommendation": "...",
}
"""
from __future__ import annotations

from typing import Any


def _finding(check_id, title, severity, resource, description, recommendation):
    return {
        "check_id": check_id,
        "title": title,
        "severity": severity,
        "resource": resource,
        "description": description,
        "recommendation": recommendation,
    }


def check_s3_public_buckets(s3_client) -> list[dict[str, Any]]:
    """CIS 2.1.5 - Buckets S3 accessibles publiquement."""
    findings = []
    try:
        buckets = s3_client.list_buckets().get("Buckets", [])
    except Exception as exc:  # pragma: no cover - accès refusé, pas de credentials, etc.
        return [_finding(
            "S3-ERR", "Impossible de lister les buckets S3", "LOW", "s3",
            f"Erreur API: {exc}", "Vérifier les permissions IAM (s3:ListAllMyBuckets).",
        )]

    for bucket in buckets:
        name = bucket["Name"]
        is_public = False
        try:
            pab = s3_client.get_public_access_block(Bucket=name)
            cfg = pab["PublicAccessBlockConfiguration"]
            if not all(cfg.values()):
                is_public = True
        except s3_client.exceptions.ClientError:
            # Pas de config PublicAccessBlock => potentiellement exposé
            is_public = True
        except Exception:
            continue

        if is_public:
            findings.append(_finding(
                "S3-01", "Bucket S3 potentiellement public", "HIGH", f"s3://{name}",
                "Le blocage d'accès public n'est pas pleinement activé sur ce bucket.",
                "Activer les 4 options de S3 Block Public Access, sauf besoin métier explicite et documenté.",
            ))
    return findings


def check_iam_wildcard_policies(iam_client) -> list[dict[str, Any]]:
    """CIS 1.16 - Politiques IAM avec Action:* et Resource:* (trop permissives)."""
    findings = []
    try:
        paginator = iam_client.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                version = iam_client.get_policy_version(
                    PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
                )
                doc = version["PolicyVersion"]["Document"]
                statements = doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                for stmt in statements:
                    if stmt.get("Effect") != "Allow":
                        continue
                    actions = stmt.get("Action", [])
                    resources = stmt.get("Resource", [])
                    actions = [actions] if isinstance(actions, str) else actions
                    resources = [resources] if isinstance(resources, str) else resources
                    if "*" in actions and "*" in resources:
                        findings.append(_finding(
                            "IAM-01", "Politique IAM trop permissive (Action:* / Resource:*)",
                            "HIGH", policy["Arn"],
                            "Cette politique autorise toutes les actions sur toutes les ressources.",
                            "Appliquer le principe du moindre privilège : restreindre Action et Resource "
                            "aux besoins réels du rôle/utilisateur.",
                        ))
    except Exception as exc:  # pragma: no cover
        return [_finding(
            "IAM-ERR", "Impossible d'analyser les politiques IAM", "LOW", "iam",
            f"Erreur API: {exc}", "Vérifier les permissions IAM (iam:ListPolicies, iam:GetPolicyVersion).",
        )]
    return findings


def check_security_groups_open_ingress(ec2_client) -> list[dict[str, Any]]:
    """CIS 5.2 / 5.3 - Security groups ouverts au monde entier sur des ports sensibles."""
    sensitive_ports = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL"}
    findings = []
    try:
        sgs = ec2_client.describe_security_groups()["SecurityGroups"]
    except Exception as exc:  # pragma: no cover
        return [_finding(
            "SG-ERR", "Impossible de lister les security groups", "LOW", "ec2",
            f"Erreur API: {exc}", "Vérifier les permissions IAM (ec2:DescribeSecurityGroups).",
        )]

    for sg in sgs:
        for perm in sg.get("IpPermissions", []):
            open_to_world = any(
                r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])
            )
            if not open_to_world:
                continue
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            if from_port is None and to_port is None:
                # Tous les ports ouverts
                findings.append(_finding(
                    "SG-02", "Security group ouvert sur tous les ports (0.0.0.0/0)",
                    "HIGH", sg["GroupId"],
                    f"Le groupe {sg.get('GroupName', sg['GroupId'])} autorise tout le trafic entrant depuis Internet.",
                    "Restreindre les règles entrantes aux plages d'IP et ports strictement nécessaires.",
                ))
                continue
            for port, name in sensitive_ports.items():
                if from_port is not None and from_port <= port <= to_port:
                    findings.append(_finding(
                        "SG-01", f"Port {name} ({port}) ouvert au monde entier",
                        "HIGH", sg["GroupId"],
                        f"Le groupe {sg.get('GroupName', sg['GroupId'])} expose le port {port} ({name}) à 0.0.0.0/0.",
                        f"Restreindre l'accès {name} à des IP/CIDR de confiance ou passer par un bastion/VPN.",
                    ))
    return findings


def check_ebs_unencrypted_volumes(ec2_client) -> list[dict[str, Any]]:
    """CIS 2.2.1 - Volumes EBS non chiffrés."""
    findings = []
    try:
        paginator = ec2_client.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page["Volumes"]:
                if not vol.get("Encrypted", False):
                    findings.append(_finding(
                        "EBS-01", "Volume EBS non chiffré", "MEDIUM", vol["VolumeId"],
                        "Ce volume EBS n'est pas chiffré au repos.",
                        "Activer le chiffrement par défaut des volumes EBS au niveau du compte/région, "
                        "et migrer ce volume via un snapshot chiffré.",
                    ))
    except Exception as exc:  # pragma: no cover
        return [_finding(
            "EBS-ERR", "Impossible de lister les volumes EBS", "LOW", "ec2",
            f"Erreur API: {exc}", "Vérifier les permissions IAM (ec2:DescribeVolumes).",
        )]
    return findings


def check_cloudtrail_enabled(cloudtrail_client) -> list[dict[str, Any]]:
    """CIS 3.1 - CloudTrail multi-région actif avec log file validation."""
    findings = []
    try:
        trails = cloudtrail_client.describe_trails().get("trailList", [])
    except Exception as exc:  # pragma: no cover
        return [_finding(
            "CT-ERR", "Impossible de lister les trails CloudTrail", "LOW", "cloudtrail",
            f"Erreur API: {exc}", "Vérifier les permissions IAM (cloudtrail:DescribeTrails).",
        )]

    if not trails:
        findings.append(_finding(
            "CT-01", "Aucun trail CloudTrail configuré", "HIGH", "cloudtrail",
            "Aucun trail n'a été trouvé : les appels API du compte ne sont pas journalisés.",
            "Créer un trail CloudTrail multi-région avec journalisation vers un bucket S3 dédié et protégé.",
        ))
        return findings

    multi_region = any(t.get("IsMultiRegionTrail") for t in trails)
    if not multi_region:
        findings.append(_finding(
            "CT-02", "Aucun trail CloudTrail multi-région", "MEDIUM", "cloudtrail",
            "Les trails existants ne couvrent pas toutes les régions.",
            "Configurer au moins un trail avec IsMultiRegionTrail=true.",
        ))

    for t in trails:
        if not t.get("LogFileValidationEnabled", False):
            findings.append(_finding(
                "CT-03", "Validation d'intégrité des logs désactivée", "LOW", t.get("Name", "trail"),
                "La validation d'intégrité (log file validation) n'est pas activée sur ce trail.",
                "Activer LogFileValidationEnabled pour détecter toute altération des logs.",
            ))
    return findings


def check_root_account_mfa(iam_client) -> list[dict[str, Any]]:
    """CIS 1.5 - MFA activé sur le compte root."""
    try:
        summary = iam_client.get_account_summary()["SummaryMap"]
    except Exception as exc:  # pragma: no cover
        return [_finding(
            "ROOT-ERR", "Impossible de vérifier le MFA du compte root", "LOW", "iam",
            f"Erreur API: {exc}", "Vérifier les permissions IAM (iam:GetAccountSummary).",
        )]

    if summary.get("AccountMFAEnabled", 0) != 1:
        return [_finding(
            "ROOT-01", "MFA non activé sur le compte root", "HIGH", "root-account",
            "Le compte root n'a pas de MFA activé, ce qui en fait une cible critique en cas de compromission.",
            "Activer immédiatement un dispositif MFA matériel ou virtuel sur le compte root.",
        )]
    return []


ALL_CHECKS = [
    ("s3", check_s3_public_buckets),
    ("iam", check_iam_wildcard_policies),
    ("ec2", check_security_groups_open_ingress),
    ("ec2", check_ebs_unencrypted_volumes),
    ("cloudtrail", check_cloudtrail_enabled),
    ("iam", check_root_account_mfa),
]
