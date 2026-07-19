"""
Interface Streamlit du Cloud Audit Agent.

Lancer avec : streamlit run app/app.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

from report.generate_report import generate_report
from scanner.mock_data import MOCK_FINDINGS
from scanner.scan import build_report_payload, run_aws_scan

load_dotenv()

st.set_page_config(page_title="Cloud Audit Agent", page_icon="🛡️", layout="wide")

SEVERITY_COLOR = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}

st.title("🛡️ Cloud Audit Agent")
st.caption("Scanner de sécurité cloud + génération de rapport d'audit assistée par Claude.")

with st.sidebar:
    st.header("Configuration du scan")
    mode = st.radio("Mode", ["mock (démo, sans credentials)", "aws (compte réel)"], index=0)
    is_mock = mode.startswith("mock")

    profile = None
    region = None
    if not is_mock:
        profile = st.text_input("Profil AWS", value="default")
        region = st.text_input("Région AWS", value="eu-west-3")

    run_scan = st.button("Lancer le scan", type="primary", use_container_width=True)

if "payload" not in st.session_state:
    st.session_state.payload = None
if "report" not in st.session_state:
    st.session_state.report = None

if run_scan:
    with st.spinner("Scan en cours..."):
        if is_mock:
            findings = MOCK_FINDINGS
            account_id = "000000000000 (mock)"
        else:
            try:
                findings = run_aws_scan(profile, region)
                account_id = None
            except Exception as exc:
                st.error(f"Erreur lors du scan AWS : {exc}")
                findings = None
        if findings is not None:
            st.session_state.payload = build_report_payload(
                findings, "mock" if is_mock else "aws", account_id
            )
            st.session_state.report = None

payload = st.session_state.payload

if payload:
    s = payload["summary"]
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total findings", payload["total_findings"])
    col2.metric("🔴 HIGH", s.get("HIGH", 0))
    col3.metric("🟠 MEDIUM", s.get("MEDIUM", 0))
    col4.metric("🟡 LOW", s.get("LOW", 0))

    st.subheader("Findings")
    df = pd.DataFrame(payload["findings"])
    if not df.empty:
        df["severity"] = df["severity"].map(lambda s: f"{SEVERITY_COLOR.get(s, '')} {s}")
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.success("Aucun finding détecté.")

    st.divider()
    st.subheader("Rapport d'audit")
    if st.button("Générer le rapport (via Claude)"):
        with st.spinner("Rédaction du rapport..."):
            st.session_state.report = generate_report(payload)

    if st.session_state.report:
        st.markdown(st.session_state.report)
        st.download_button(
            "Télécharger le rapport (.md)",
            data=st.session_state.report,
            file_name="cloud_audit_report.md",
            mime="text/markdown",
        )
        st.download_button(
            "Télécharger les findings bruts (.json)",
            data=json.dumps(payload, indent=2, ensure_ascii=False),
            file_name="findings.json",
            mime="application/json",
        )
else:
    st.info("Configure le mode dans la barre latérale puis clique sur **Lancer le scan**.")
