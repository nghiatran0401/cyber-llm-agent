from src.rag.data_models import MITRETechniqueResponse


def test_mitre_response_schema_fields():
    resp = MITRETechniqueResponse(
        technique_id="T0000",
        technique_name="Dummy",
        tactic="Tactic",
        description="Desc",
        detection="Detection",
        mitigations="Mitigations",
    )
    assert hasattr(resp, "technique_id")
    assert hasattr(resp, "technique_name")
    assert hasattr(resp, "tactic")
    assert hasattr(resp, "description")
    assert hasattr(resp, "detection")
    assert hasattr(resp, "mitigations")

