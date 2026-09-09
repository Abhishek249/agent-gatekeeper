"""Validates the actual Rego policy logic (policies/agent_authz.rego)
against a real Rego interpreter (regopy), independent of the OPA HTTP
transport.

This mirrors policies/agent_authz_test.rego case-for-case. Both exist
deliberately: this file runs in any Python environment (no OPA binary
needed, so it's part of the normal pytest run and CI); the .rego file is
the authoritative test to run with the real `opa test` binary. Divergence
between the two would be a signal to look closely at either the policy or
this harness.
"""
from __future__ import annotations

import pytest

from examples.local_opa import LocalRegoEvaluator


@pytest.fixture(scope="module")
def opa() -> LocalRegoEvaluator:
    return LocalRegoEvaluator()


def _input(action_type, scopes, tier="standard", hour_utc=15):
    return {
        "subject": {"id": "a", "client_id": "demo-agent", "scopes": scopes},
        "action": {"type": action_type},
        "resource": {"id": "r", "tier": tier},
        "context": {"hour_utc": hour_utc},
    }


def test_read_is_always_allowed(opa):
    decision = opa.evaluate(_input("read", []))
    assert decision.allow


def test_write_allowed_with_write_scope(opa):
    decision = opa.evaluate(_input("write", ["actions:write"]))
    assert decision.allow


def test_write_denied_without_write_scope(opa):
    decision = opa.evaluate(_input("write", []))
    assert not decision.allow


def test_write_to_critical_denied_without_override(opa):
    decision = opa.evaluate(_input("write", ["actions:write"], tier="critical"))
    assert not decision.allow


def test_write_to_critical_allowed_with_override(opa):
    decision = opa.evaluate(_input("write", ["actions:write", "actions:override"], tier="critical"))
    assert decision.allow


def test_destructive_allowed_in_business_hours(opa):
    decision = opa.evaluate(_input("destructive", ["actions:destructive"], hour_utc=15))
    assert decision.allow


def test_destructive_denied_outside_business_hours(opa):
    decision = opa.evaluate(_input("destructive", ["actions:destructive"], hour_utc=2))
    assert not decision.allow


def test_destructive_denied_without_scope_even_in_hours(opa):
    decision = opa.evaluate(_input("destructive", [], hour_utc=15))
    assert not decision.allow


def test_unknown_action_type_denied_by_default(opa):
    decision = opa.evaluate(_input("bogus", ["actions:write", "actions:destructive"]))
    assert not decision.allow
    assert "default deny" in decision.reason
