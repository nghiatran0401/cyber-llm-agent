"""Unit tests for Week 6 state validation helpers."""

import pytest

from src.utils.state_validator import validate_state, REQUIRED_STATE_KEYS


def test_validate_state_accepts_complete_state():
    state = {key: "" for key in REQUIRED_STATE_KEYS}
    assert validate_state(state) is True


def test_validate_state_raises_for_missing_keys():
    state = {"logs": "example"}
    with pytest.raises(ValueError):
        validate_state(state)

