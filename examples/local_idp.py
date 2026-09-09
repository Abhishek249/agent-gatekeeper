"""A tiny stand-in identity provider, used only when no real Keycloak is
reachable (offline demo mode, and the test suite).

This is not a mock in the sense of faking the verification logic - it
generates a real RSA keypair, builds a real JWKS document from the public
key, and signs a real RS256 JWT with the private key. gatekeeper/auth.py
verifies that token exactly the way it would verify one Keycloak issued,
via the same jwt.decode() call against the same JWKS shape. The only thing
this module stands in for is Keycloak's token *issuance* endpoint - which is
precisely the part real code should never reimplement, so it's confined
here, clearly labeled, and kept out of the gatekeeper package itself.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass
class LocalIdentityProvider:
    issuer: str = "http://local-idp.demo/realms/agents"
    audience: str = "agent-gatekeeper"

    def __post_init__(self) -> None:
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._kid = str(uuid.uuid4())
        public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(
            self._private_key.public_key(), as_dict=True
        )
        public_jwk.update({"kid": self._kid, "use": "sig", "alg": "RS256"})
        self.jwks: dict = {"keys": [public_jwk]}

    def issue_token(
        self,
        *,
        subject: str,
        client_id: str,
        scopes: list[str],
        expires_in: int = 900,
    ) -> str:
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": subject,
            "azp": client_id,
            "iat": now,
            "exp": now + expires_in,
            "scope": " ".join(scopes),
        }
        return jwt.encode(
            claims,
            self._private_key,
            algorithm="RS256",
            headers={"kid": self._kid},
        )
