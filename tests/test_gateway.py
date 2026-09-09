"""End-to-end test of the gateway: authenticate -> authorize -> audit, all
wired together, driven through FastAPI's TestClient (a real ASGI request
path, not calling the route functions directly).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from examples.local_idp import LocalIdentityProvider
from examples.local_opa import LocalRegoEvaluator
from gatekeeper.audit import LakehouseAuditLog
from gatekeeper.auth import KeycloakAuthenticator
from gatekeeper.gateway import create_app


@pytest.fixture
def idp() -> LocalIdentityProvider:
    return LocalIdentityProvider()


@pytest.fixture
def client(idp, tmp_path) -> TestClient:
    authenticator = KeycloakAuthenticator(
        static_jwks=idp.jwks, issuer=idp.issuer, audience=idp.audience
    )
    opa = LocalRegoEvaluator()
    audit_log = LakehouseAuditLog(tmp_path)
    app = create_app(authenticator, opa, audit_log)
    return TestClient(app)


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_missing_authorization_header_is_rejected(client):
    resp = client.post("/v1/actions/check", json={"action_type": "read", "resource_id": "d1"})
    assert resp.status_code == 422


def test_invalid_token_is_401(client):
    resp = client.post(
        "/v1/actions/check",
        json={"action_type": "read", "resource_id": "d1"},
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert resp.status_code == 401


def test_allowed_read_action(client, idp):
    token = idp.issue_token(subject="agent-1", client_id="demo-agent", scopes=[])
    resp = client.post(
        "/v1/actions/check",
        json={"action_type": "read", "resource_id": "d1"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["allow"] is True
    assert body["agent_subject"] == "agent-1"
    assert body["audit_id"]


def test_denied_write_action_without_scope(client, idp):
    token = idp.issue_token(subject="agent-2", client_id="demo-agent", scopes=[])
    resp = client.post(
        "/v1/actions/check",
        json={"action_type": "write", "resource_id": "d2"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["allow"] is False
    assert "actions:write" in body["reason"]


def test_denials_and_recent_endpoints_reflect_checked_actions(client, idp):
    allowed_token = idp.issue_token(subject="agent-allowed", client_id="demo-agent", scopes=["actions:write"])
    denied_token = idp.issue_token(subject="agent-denied", client_id="demo-agent", scopes=[])

    client.post(
        "/v1/actions/check",
        json={"action_type": "write", "resource_id": "d1"},
        headers={"Authorization": f"Bearer {allowed_token}"},
    )
    client.post(
        "/v1/actions/check",
        json={"action_type": "write", "resource_id": "d2"},
        headers={"Authorization": f"Bearer {denied_token}"},
    )

    recent = client.get("/v1/audit/recent").json()
    assert len(recent) == 2

    denials = client.get("/v1/audit/denials").json()
    assert len(denials) == 1
    assert denials[0]["agent_subject"] == "agent-denied"
