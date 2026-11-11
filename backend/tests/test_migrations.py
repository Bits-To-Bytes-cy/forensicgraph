import importlib


def test_phase1b_migration_preserves_applied_history():
    revision = importlib.import_module("migrations.versions.0003_case_management")

    assert revision.revision == "0003_case_management"
    assert revision.down_revision == "0002_auth_organizations"


def test_phase2_migration_preserves_phase1b():
    revision = importlib.import_module("migrations.versions.0004_evidence_vault")

    assert revision.revision == "0004_evidence_vault"
    assert revision.down_revision == "0003_case_management"
