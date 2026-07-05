import sys
from pathlib import Path

# Make the examples/ directory importable.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))

from agentaudit.bundle import export_bundle, verify_bundle  # noqa: E402
from agentaudit.controls import CONTROL_CATALOG, describe, enrich  # noqa: E402


def test_controls_describe_known_and_unknown():
    assert describe("EU-AI-Act-Art14")["framework"] == "EU AI Act"
    assert describe("NOPE") is None


def test_enrich_surfaces_unmapped_controls():
    out = enrich(["EU-AI-Act-Art12", "CUSTOM-1"])
    by_id = {c["id"]: c for c in out}
    assert by_id["EU-AI-Act-Art12"]["framework"] == "EU AI Act"
    assert by_id["CUSTOM-1"]["framework"] == "unmapped"


def test_all_catalog_entries_wellformed():
    for cid, c in CONTROL_CATALOG.items():
        assert c.id == cid and c.framework and c.title


def test_kyc_demo_produces_verifiable_bundle():
    import kyc_demo

    from agentaudit import AuditLog, SigningKey

    log = AuditLog(signing_key=SigningKey.generate())
    approved = kyc_demo.Applicant("Jane Applicant", "1990-05-01", "P1", "London")
    flagged = kyc_demo.Applicant("Ivan Sanctionov", "1980-01-01", "P2", "Nowhere")
    assert kyc_demo.run_kyc(log, approved) == "approve"
    assert kyc_demo.run_kyc(log, flagged) == "route_to_human"

    log.seal()
    bundle = export_bundle(log)
    assert verify_bundle(bundle).ok

    # No raw PII in the log: inputs are redacted to a hash + class.
    for e in bundle["entries"]:
        if e.get("input"):
            assert e["input"].get("redacted") is True
            assert "name" not in e["input"]

    # Bundle self-describes its regulatory coverage.
    frameworks = {c["framework"] for c in bundle["controls"]}
    assert "EU AI Act" in frameworks


def test_kyc_demo_main_exits_zero(tmp_path, capsys):
    import kyc_demo

    rc = kyc_demo.main(["-o", str(tmp_path / "kyc.json")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "DETECTED (FAIL)" in out  # tamper-evidence demonstrated


def test_selective_disclosure_demo_main_exits_zero(capsys):
    import selective_disclosure_demo

    rc = selective_disclosure_demo.main()
    assert rc == 0
    out = capsys.readouterr().out
    assert "raw PII present:       NONE" in out
    assert "forged excerpt caught: True" in out


def test_anchoring_demo_main_exits_zero(capsys):
    import anchoring_demo

    rc = anchoring_demo.main()
    assert rc == 0
    out = capsys.readouterr().out
    assert "witness cosignature valid (pinned key): True" in out
    assert "rejected when pinned to a different key: True" in out


def test_langchain_kyc_demo_main_exits_zero(capsys):
    import pytest

    pytest.importorskip("langchain_core")
    import langchain_kyc_demo

    rc = langchain_kyc_demo.main()
    assert rc == 0
    out = capsys.readouterr().out
    assert "tamper detected  True" in out


def test_production_hardening_demo_main_exits_zero(capsys):
    import production_hardening_demo

    rc = production_hardening_demo.main()
    assert rc == 0
    out = capsys.readouterr().out
    assert "sizes [5, 10]" in out
    assert "every checkpoint signed + anchored: True" in out
