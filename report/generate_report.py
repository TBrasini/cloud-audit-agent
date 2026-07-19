"""
Génération d'un rapport d'audit lisible à partir des findings JSON,
via l'API Claude (Anthropic). Fallback en template simple si aucune
clé API n'est disponible, pour que la démo fonctionne sans compte payant.

Usage:
    python -m report.generate_report --input findings.json --output report.md
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

SYSTEM_PROMPT = """Tu es un auditeur sécurité cloud senior. On te donne une liste de
findings issus d'un scan automatisé (format JSON) d'un compte AWS. Rédige un rapport
d'audit professionnel en français, en Markdown, structuré ainsi :

1. Résumé exécutif (3-5 phrases, ton factuel, orienté risque business)
2. Tableau de synthèse par sévérité
3. Détail des findings, groupés par sévérité (HIGH puis MEDIUM puis LOW), avec pour
   chacun : titre, ressource concernée, description, recommandation concrète
4. Plan de remédiation priorisé (quick wins vs actions structurantes)

Reste concis, professionnel, sans blabla marketing. N'invente aucun finding qui
ne soit pas dans les données fournies."""


def _template_fallback(payload: dict) -> str:
    """Rapport généré sans IA, pour fonctionner sans clé API Anthropic."""
    lines = ["# Rapport d'audit cloud (mode local, sans IA)\n"]
    lines.append(f"Date du scan : {payload['scan_date']}")
    lines.append(f"Mode : {payload['mode']}\n")
    lines.append("## Résumé\n")
    s = payload["summary"]
    lines.append(f"- HIGH : {s.get('HIGH', 0)}")
    lines.append(f"- MEDIUM : {s.get('MEDIUM', 0)}")
    lines.append(f"- LOW : {s.get('LOW', 0)}\n")
    lines.append("## Findings détaillés\n")
    for f in payload["findings"]:
        lines.append(f"### [{f['severity']}] {f['title']} ({f['check_id']})")
        lines.append(f"- **Ressource** : `{f['resource']}`")
        lines.append(f"- **Description** : {f['description']}")
        lines.append(f"- **Recommandation** : {f['recommendation']}\n")
    lines.append("\n> Rapport généré sans clé ANTHROPIC_API_KEY. "
                  "Ajoutez-la dans `.env` pour un rapport rédigé par Claude.")
    return "\n".join(lines)


def generate_report(payload: dict) -> str:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return _template_fallback(payload)

    try:
        import anthropic
    except ImportError:
        return _template_fallback(payload)

    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=4000,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"Voici les findings à analyser :\n\n{json.dumps(payload, ensure_ascii=False, indent=2)}",
        }],
    )
    return message.content[0].text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Génère un rapport d'audit à partir de findings.json")
    parser.add_argument("--input", default="findings.json")
    parser.add_argument("--output", default="report.md")
    args = parser.parse_args(argv)

    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    report_text = generate_report(payload)
    Path(args.output).write_text(report_text, encoding="utf-8")
    print(f"[OK] Rapport écrit dans {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
