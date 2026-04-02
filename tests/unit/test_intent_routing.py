"""Unit tests for shared intent routing behavior."""

import hashlib

from semantic_router.encoders import DenseEncoder

from src.agents.shared import intent_routing


def test_get_route_layer_initializes_with_local_auto_sync(monkeypatch):
    monkeypatch.setattr(intent_routing.Settings, "OPENROUTER_API_KEY", "sk-test-stub")
    captured = {}

    class _FakeChoice:
        name = "standard"

    class _FakeRouter:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def __call__(self, _text):
            return _FakeChoice()

    monkeypatch.setattr(intent_routing, "_route_layer", None)
    monkeypatch.setattr(intent_routing, "_encoder", None)
    monkeypatch.setattr(intent_routing, "_routing_unavailable", False)
    monkeypatch.setattr(intent_routing, "OpenAIEncoder", lambda **_kwargs: object())
    monkeypatch.setattr(intent_routing, "SemanticRouter", _FakeRouter)

    layer = intent_routing._get_route_layer()
    assert isinstance(layer, _FakeRouter)
    assert captured["auto_sync"] == "local"


class _DeterministicEncoder(DenseEncoder):
    name: str = "deterministic-test"

    def __call__(self, texts):
        vectors = []
        for text in texts:
            digest = hashlib.sha256(str(text).encode("utf-8")).digest()
            vectors.append([b / 255.0 for b in digest[:8]])
        return vectors


def test_get_route_layer_builds_ready_local_index(monkeypatch):
    monkeypatch.setattr(intent_routing.Settings, "OPENROUTER_API_KEY", "sk-test-stub")
    monkeypatch.setattr(intent_routing, "_route_layer", None)
    monkeypatch.setattr(intent_routing, "_encoder", None)
    monkeypatch.setattr(intent_routing, "_routing_unavailable", False)
    monkeypatch.setattr(intent_routing, "OpenAIEncoder", lambda **_kwargs: _DeterministicEncoder())

    layer = intent_routing._get_route_layer()
    assert layer.index.is_ready()


def test_is_high_risk_intent_uses_semantic_router_index(monkeypatch):
    monkeypatch.setattr(intent_routing.Settings, "OPENROUTER_API_KEY", "sk-test-stub")
    monkeypatch.setattr(intent_routing, "_route_layer", None)
    monkeypatch.setattr(intent_routing, "_encoder", None)
    monkeypatch.setattr(intent_routing, "_routing_unavailable", False)
    monkeypatch.setattr(intent_routing, "OpenAIEncoder", lambda **_kwargs: _DeterministicEncoder())

    assert intent_routing.is_high_risk_intent("there is a ransomware infection on the network")
    assert not intent_routing.is_high_risk_intent("hello agent")
