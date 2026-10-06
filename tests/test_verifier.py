"""Unit tests for SAGA tri-state static verifier logic and candidate classification."""

from pathlib import Path

from saga.parser.ast_parser import parse_ast_routes_from_directory
from saga.parser.correlator import correlate_endpoints
from saga.verifier.models import CandidateVulnerability, VerificationStatus
from saga.verifier.static_verifier import analyze_target_security

TESTBED_DIR = Path(__file__).parent.parent / "testbed"


def test_tristate_verifier_classification():
    """Verify tri-state classification: PROVEN vs UNPROVEN (CANDIDATE_BOLA) vs UNKNOWN."""
    ast_endpoints = parse_ast_routes_from_directory(TESTBED_DIR)
    correlated = correlate_endpoints([], ast_endpoints)

    summary = analyze_target_security(correlated, target_path=str(TESTBED_DIR))

    report_map = {rep.path: rep for rep in summary.reports}

    # 1. Vulnerable BOLA -> UNPROVEN / CANDIDATE_BOLA (Deterministic confidence 0.75)
    bola_report = report_map["/api/v1/documents/{doc_id}"]
    assert bola_report.result == VerificationStatus.UNPROVEN
    assert bola_report.candidate == CandidateVulnerability.BOLA
    assert bola_report.confidence == 0.75
    assert bola_report.authorization_rule == "NONE"

    # 2. Secure Ownership -> PROVEN / CANDIDATE NONE (Deterministic confidence 1.0)
    ownership_report = report_map["/api/v1/secure/documents/{doc_id}"]
    assert ownership_report.result == VerificationStatus.PROVEN
    assert ownership_report.candidate == CandidateVulnerability.NONE
    assert ownership_report.confidence == 1.0
    assert "Document.owner_id == current_user.id" in ownership_report.authorization_rule

    # 3. Secure Tenant -> PROVEN / CANDIDATE NONE (Deterministic confidence 1.0)
    tenant_report = report_map["/api/v1/secure/tenant/documents/{doc_id}"]
    assert tenant_report.result == VerificationStatus.PROVEN
    assert tenant_report.candidate == CandidateVulnerability.NONE
    assert tenant_report.confidence == 1.0
    assert "Document.tenant_id == current_user.tenant_id" in tenant_report.authorization_rule

    # 4. Delegated Policy -> UNKNOWN / CANDIDATE NONE (Deterministic confidence 0.9)
    unknown_report = report_map["/api/v1/secure/unknown/documents/{doc_id}"]
    assert unknown_report.result == VerificationStatus.UNKNOWN
    assert unknown_report.candidate == CandidateVulnerability.NONE
    assert unknown_report.confidence == 0.90
    assert "delegated" in unknown_report.explanation.lower()

