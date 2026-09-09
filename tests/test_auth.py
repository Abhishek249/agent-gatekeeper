from __future__ import annotations

import time

import jwt
import pytest

from examples.local_idp import LocalIdentityProvider
from gatekeeper.auth import KeycloakAuthenticator, TokenValidationError


@pytest.fixture
def idp() -> LocalIdentityProvider:
    return LocalIdentityProvider()


@pytest.fixture
def authenticator(idp: LocalIdentityProvider) -> KeycloakAuthenticator:
    return KeycloakAuthenticator(static_jwks=idp.jwks, issuer=idp.issuer, audience=idp.audience)


def test_valid_token_authenticates_and_extracts_scopes(idp, authenticator):
    token = idp.issue_token(
        subject="agent-1", client_id="demo-agent", scopes=["actions:write", "actions:override"]
    )
    identity = authenticator.authenticate(token)

    assert identity.subject == "agent-1"
    assert identity.client_id == "demo-agent"
    assert identity.scopes == ["actions:write", "actions:override"]
    assert identity.has_scope("actions:write")
    assert not identity.has_scope("actions:destructive")


def test_bearer_prefix_is_stripped(idp, authenticator):
    token = idp.issue_token(subject="agent-1", client_id="demo-agent", scopes=[])
    identity = authenticator.authenticate(f"Bearer {token}")
    assert identity.subject == "agent-1"


def test_expired_token_is_rejected(idp, authenticator):
    token = idp.issue_token(subject="agent-1", client_id="demo-agent", scopes=[], expires_in=-10)
    with pytest.raises(TokenValidationError):
        authenticator.authenticate(token)


def test_wrong_audience_is_rejected(idp):
    authenticator = KeycloakAuthenticator(
        static_jwks=idp.jwks, issuer=idp.issuer, audience="a-different-audience"
    )
    token = idp.issue_token(subject="agent-1", client_id="demo-agent", scopes=[])
    with pytest.raises(TokenValidationError):
        authenticator.authenticate(token)


def test_wrong_issuer_is_rejected(idp):
    authenticator = KeycloakAuthenticator(
        static_jwks=idp.jwks, issuer="http://not-the-real-issuer", audience=idp.audience
    )
    token = idp.issue_token(subject="agent-1", client_id="demo-agent", scopes=[])
    with pytest.raises(TokenValidationError):
        authenticator.authenticate(token)


def test_token_signed_by_an_unknown_key_is_rejected(idp, authenticator):
    # A second, unrelated identity provider - simulates a forged token that
    # isn't in this realm's JWKS at all.
    other_idp = LocalIdentityProvider(issuer=idp.issuer, audience=idp.audience)
    forged = other_idp.issue_token(subject="attacker", client_id="demo-agent", scopes=["actions:override"])
    with pytest.raises(TokenValidationError):
        authenticator.authenticate(forged)


def test_tampered_payload_is_rejected(idp, authenticator):
    token = idp.issue_token(subject="agent-1", client_id="demo-agent", scopes=[])
    header, payload, signature = token.split(".")
    # Flip the last character of the payload segment to corrupt it without
    # touching the signature, which should now fail to verify.
    tampered_payload = payload[:-1] + ("A" if payload[-1] != "A" else "B")
    tampered_token = f"{header}.{tampered_payload}.{signature}"
    with pytest.raises(TokenValidationError):
        authenticator.authenticate(tampered_token)


def test_missing_scope_claim_yields_empty_scopes(idp, authenticator):
    token = idp.issue_token(subject="agent-1", client_id="demo-agent", scopes=[])
    identity = authenticator.authenticate(token)
    assert identity.scopes == []
