"""
Findings d'exemple, utilisés en mode --mode mock.

Objectif : permettre de démontrer tout le pipeline (scan -> rapport -> UI)
sans compte AWS ni credentials, pour un portfolio / une démo CV.
"""

MOCK_FINDINGS = [
    {
        "check_id": "S3-01",
        "title": "Bucket S3 potentiellement public",
        "severity": "HIGH",
        "resource": "s3://demo-company-backups",
        "description": "Le blocage d'accès public n'est pas pleinement activé sur ce bucket.",
        "recommendation": "Activer les 4 options de S3 Block Public Access, sauf besoin métier explicite et documenté.",
    },
    {
        "check_id": "IAM-01",
        "title": "Politique IAM trop permissive (Action:* / Resource:*)",
        "severity": "HIGH",
        "resource": "arn:aws:iam::123456789012:policy/legacy-admin-policy",
        "description": "Cette politique autorise toutes les actions sur toutes les ressources.",
        "recommendation": "Appliquer le principe du moindre privilège : restreindre Action et Resource "
        "aux besoins réels du rôle/utilisateur.",
    },
    {
        "check_id": "SG-01",
        "title": "Port SSH (22) ouvert au monde entier",
        "severity": "HIGH",
        "resource": "sg-0a1b2c3d4e5f6a7b8",
        "description": "Le groupe web-servers-sg expose le port 22 (SSH) à 0.0.0.0/0.",
        "recommendation": "Restreindre l'accès SSH à des IP/CIDR de confiance ou passer par un bastion/VPN.",
    },
    {
        "check_id": "EBS-01",
        "title": "Volume EBS non chiffré",
        "severity": "MEDIUM",
        "resource": "vol-0f1e2d3c4b5a69788",
        "description": "Ce volume EBS n'est pas chiffré au repos.",
        "recommendation": "Activer le chiffrement par défaut des volumes EBS au niveau du compte/région, "
        "et migrer ce volume via un snapshot chiffré.",
    },
    {
        "check_id": "CT-02",
        "title": "Aucun trail CloudTrail multi-région",
        "severity": "MEDIUM",
        "resource": "cloudtrail",
        "description": "Les trails existants ne couvrent pas toutes les régions.",
        "recommendation": "Configurer au moins un trail avec IsMultiRegionTrail=true.",
    },
    {
        "check_id": "ROOT-01",
        "title": "MFA non activé sur le compte root",
        "severity": "HIGH",
        "resource": "root-account",
        "description": "Le compte root n'a pas de MFA activé, ce qui en fait une cible critique en cas de compromission.",
        "recommendation": "Activer immédiatement un dispositif MFA matériel ou virtuel sur le compte root.",
    },
    {
        "check_id": "CT-03",
        "title": "Validation d'intégrité des logs désactivée",
        "severity": "LOW",
        "resource": "trail-main",
        "description": "La validation d'intégrité (log file validation) n'est pas activée sur ce trail.",
        "recommendation": "Activer LogFileValidationEnabled pour détecter toute altération des logs.",
    },
]
