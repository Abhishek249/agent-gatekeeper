"""Tests the OPAClient HTTP transport in isolation from policy correctness
(that's tests/test_policy_rego.py's job): does it build the right request,
and does it correctly interpret OPA's response shapes, including the
"no result" case OPA returns for an undefined query?

Uses httpx.MockTransport so this is a real httpx.Client making a real
request/response round trip, just against an in-process handler instead of
a socket - no server process needed, and no risk of silently testing
against the wrong thing.
"""
from __future__ import annotations

import json

import httpx
import pytest

from gatekeeper.policy import OPAClient, PolicyDecision


def _client_with_handler(handler) -> OPAClient:
    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport)
    return OPAClient("http://opa.local:8181", client=http_client)


def test_sends_input_to_the_expected_data_path():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"result": {"allow": True, "reason": "ok"}})

    client = _client_with_handler(handler)
    decision = client.evaluate({"action": {"type": "read"}})

    assert seen["url"] == "http://opa.local:8181/v1/data/agent_authz/decision"
    assert seen["body"] == {"input": {"action": {"type": "read"}}}
    assert decision == PolicyDecision(allow=True, reason="ok", raw_response={
        "result": {"allow": True, "reason": "ok"}
    })


def test_undefined_result_is_treated_as_a_deny():
    def handler(request: httpx.Request) -> httpx.Response:
        # OPA omits "result" entirely when the query path doesn't resolve.
        return httpx.Response(200, json={})

    client = _client_with_handler(handler)
    decision = client.evaluate({"action": {"type": "read"}})

    assert decision.allow is False
    assert "undefined" in decision.reason


def test_missing_reason_defaults_to_empty_string():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"result": {"allow": False}})

    client = _client_with_handler(handler)
    decision = client.evaluate({"action": {"type": "write"}})

    assert decision.allow is False
    assert decision.reason == ""


def test_http_error_status_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal error")

    client = _client_with_handler(handler)
    with pytest.raises(httpx.HTTPStatusError):
        client.evaluate({"action": {"type": "read"}})


def test_custom_policy_path_is_used_in_the_url():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://opa.local:8181/v1/data/other/pkg/decision"
        return httpx.Response(200, json={"result": {"allow": True, "reason": "ok"}})

    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport)
    client = OPAClient(
        "http://opa.local:8181", policy_path="other/pkg/decision", client=http_client
    )
    client.evaluate({"action": {"type": "read"}})
