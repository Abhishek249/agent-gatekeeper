"""Agent identity via real OAuth2/OIDC access tokens (Keycloak-issued).

Design intent: an agent should not be able to talk itself into an identity.
It authenticates the same way any OAuth2 client-credentials service account
would - it holds a client id/secret, exchanges that with Keycloak for a
signed JWT access token, and every downstream call carries that token. This
module only ever *verifies* tokens (signature, issuer, audience, expiry) and
extracts the caller's identity and scopes from them; it never issues tokens
itself, because token issuance is exactly the part you don't want to
reimplement when a standards-compliant identity provider already does it
correctly.

Two ways to get the signing key, both real code paths:
  - jwks_url: fetch Keycloak's JWKS over HTTP (the live, docker-compose path).
  - static_jwks: a JWKS document supplied directly, which is how the test
    suite and the offline demo mode verify real, correctly-signed tokens
    without a Keycloak server running.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import jwt
from jwt import PyJWKClient


class TokenValidationError(Exception):
    """Raised for any token that fails signature, issuer, audience, or expiry checks."""


@dataclass
class AgentIdentity:
    """The authenticated caller, extracted from a verified access token."""

    subject: str
    client_id: str
    scopes: list[str]
    raw_claims: dict[str, Any] = field(default_factory=dict)

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


class KeycloakAuthenticator:
    """Verifies bearer tokens issued by a Keycloak realm.

    In production this points at the realm's JWKS endpoint, e.g.
    ``http://localhost:8080/realms/agents/protocol/openid-connect/certs``,
    which is exactly what docker-compose here exposes. For tests and the
    offline demo, ``static_jwks`` lets the same verification logic run
    against a locally-generated (but still correctly signed) keypair.
    """

    def __init__(
        self,
        *,
        jwks_url: Optional[str] = None,
        static_jwks: Optional[dict[str, Any]] = None,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        algorithms: Optional[list[str]] = None,
        leeway_seconds: int = 10,
    ) -> None:
        if not jwks_url and not static_jwks:
            raise ValueError("one of jwks_url or static_jwks is required")
        self._jwks_url = jwks_url
        self._static_jwks = static_jwks
        self._jwks_client = PyJWKClient(jwks_url) if jwks_url else None
        self._issuer = issuer
        self._audience = audience
        self._algorithms = algorithms or ["RS256"]
        self._leeway_seconds = leeway_seconds

    def _signing_key_for(self, token: str):
        if self._jwks_client is not None:
            return self._jwks_client.get_signing_key_from_jwt(token).key

        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        for jwk in self._static_jwks.get("keys", []):
            if jwk.get("kid") == kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        raise TokenValidationError(f"no signing key found for kid={kid!r}")

    def authenticate(self, bearer_token: str) -> AgentIdentity:
        """Verify a bearer token and return the identity it names.

        Raises TokenValidationError for any failure - bad signature, wrong
        issuer/audience, or an expired token - rather than letting a
        raw PyJWT exception leak past this boundary.
        """
        token = bearer_token[7:] if bearer_token.startswith("Bearer ") else bearer_token

        try:
            key = self._signing_key_for(token)
            claims = jwt.decode(
                token,
                key,
                algorithms=self._algorithms,
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway_seconds,
                options={"verify_aud": self._audience is not None},
            )
        except jwt.PyJWTError as exc:
            raise TokenValidationError(str(exc)) from exc

        # Keycloak issues scopes as a single space-separated "scope" claim,
        # per RFC 8693 / the OAuth2 convention - not a list.
        scope_claim = claims.get("scope", "")
        scopes = scope_claim.split() if scope_claim else []

        subject = claims.get("sub")
        client_id = claims.get("azp") or claims.get("client_id") or subject
        if not subject:
            raise TokenValidationError("token has no 'sub' claim")

        return AgentIdentity(
            subject=subject,
            client_id=client_id,
            scopes=scopes,
            raw_claims=claims,
        )


def is_expired(claims: dict[str, Any]) -> bool:
    """Small standalone helper, mainly useful in tests/diagnostics."""
    exp = claims.get("exp")
    return exp is not None and exp < time.time()
