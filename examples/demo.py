"""End-to-end walkthrough of the gatekeeper: several agent actions, each
checked through real authentication + real policy evaluation, with every
decision landing in the audit lakehouse - then a couple of SQL queries over
that trail.

Runs out of the box with zero infrastructure (`python -m examples.demo`):
auth is verified against a locally-generated but genuinely RSA-signed JWT,
and policy is evaluated by loading the real policies/agent_authz.rego file
into a local Rego interpreter - see local_idp.py and local_opa.py for why
that's a legitimate stand-in rather than a faked result.

If KEYCLOAK_URL and OPA_URL are set (i.e. `docker compose up` is running),
the script also runs one additional round entirely against that real
infrastructure - a genuine OAuth2 client-credentials token from Keycloak,
verified against Keycloak's live JWKS, evaluated by a real OPA server.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import httpx

from gatekeeper import KeycloakAuthenticator, LakehouseAuditLog
from gatekeeper.policy import OPAClient, build_action_input

from .local_idp import LocalIdentityProvider
from .local_opa import LocalRegoEvaluator

AUDIT_ROOT = Path(__file__).resolve().parent.parent / "audit-lake"


def run_offline_demo() -> None:
    print("=" * 78)
    print("OFFLINE MODE (no KEYCLOAK_URL/OPA_URL set): using a local, RSA-signed")
    print("token issuer and a local Rego evaluator over the real policy file.")
    print("=" * 78)

    idp = LocalIdentityProvider()
    authenticator = KeycloakAuthenticator(
        static_jwks=idp.jwks, issuer=idp.issuer, audience=idp.audience
    )
    opa = LocalRegoEvaluator()

    if AUDIT_ROOT.exists():
        shutil.rmtree(AUDIT_ROOT)
    audit_log = LakehouseAuditLog(AUDIT_ROOT)

    scenarios = [
        ("read a standard doc, no scopes needed", [], "read", "doc-1", "standard"),
        ("write with actions:write scope", ["actions:write"], "write", "doc-2", "standard"),
        ("write with no scopes at all", [], "write", "doc-3", "standard"),
        (
            "write to a CRITICAL resource, write scope only (no override)",
            ["actions:write"],
            "write",
            "prod-config",
            "critical",
        ),
        (
            "write to a CRITICAL resource, write + override scopes",
            ["actions:write", "actions:override"],
            "write",
            "prod-config",
            "critical",
        ),
        (
            "destructive action, destructive scope, during business hours",
            ["actions:destructive"],
            "destructive",
            "old-backups",
            "standard",
        ),
        (
            "destructive action, destructive scope, at 2am UTC",
            ["actions:destructive"],
            "destructive",
            "old-backups",
            "standard",
        ),
    ]

    for i, (label, scopes, action_type, resource_id, tier) in enumerate(scenarios):
        token = idp.issue_token(subject=f"agent-{i}", client_id="demo-agent", scopes=scopes)
        identity = authenticator.authenticate(token)

        hour_utc = 2 if "2am" in label else 15
        input_doc = build_action_input(
            identity,
            action_type=action_type,
            resource_id=resource_id,
            resource_tier=tier,
            hour_utc=hour_utc,
        )
        decision = opa.evaluate(input_doc)
        audit_log.record(
            agent_subject=identity.subject,
            client_id=identity.client_id,
            action_type=action_type,
            resource_id=resource_id,
            resource_tier=tier,
            allow=decision.allow,
            reason=decision.reason,
        )

        verdict = "ALLOW" if decision.allow else "DENY "
        print(f"[{verdict}] {label}\n         -> {decision.reason}")

    print("\n--- audit trail (queried back via DuckDB over the Parquet lakehouse) ---")
    for row in audit_log.recent(limit=10):
        print(f"  {row['timestamp']}  {row['agent_subject']:<10} "
              f"{row['action_type']:<11} allow={row['allow']!s:<5} {row['reason']}")

    print("\n--- denials only ---")
    for row in audit_log.recent_denials(limit=10):
        print(f"  {row['agent_subject']:<10} {row['action_type']:<11} {row['reason']}")


def run_live_smoke_test(keycloak_url: str, opa_url: str) -> None:
    print("\n" + "=" * 78)
    print(f"LIVE MODE: fetching a real token from {keycloak_url} and evaluating")
    print(f"against the real OPA server at {opa_url}.")
    print("=" * 78)

    token_resp = httpx.post(
        f"{keycloak_url.rstrip('/')}/realms/agents/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "demo-agent",
            "client_secret": "demo-agent-secret",
            "scope": "actions:override",
        },
        timeout=10.0,
    )
    token_resp.raise_for_status()
    access_token = token_resp.json()["access_token"]

    authenticator = KeycloakAuthenticator(
        jwks_url=f"{keycloak_url.rstrip('/')}/realms/agents/protocol/openid-connect/certs",
        issuer=f"{keycloak_url.rstrip('/')}/realms/agents",
    )
    identity = authenticator.authenticate(access_token)
    print(f"authenticated as: subject={identity.subject} client_id={identity.client_id} "
          f"scopes={identity.scopes}")

    with OPAClient(opa_url) as opa:
        input_doc = build_action_input(
            identity,
            action_type="write",
            resource_id="prod-config",
            resource_tier="critical",
            hour_utc=15,
        )
        decision = opa.evaluate(input_doc)
        verdict = "ALLOW" if decision.allow else "DENY "
        print(f"[{verdict}] write to critical resource -> {decision.reason}")


def main() -> None:
    run_offline_demo()

    keycloak_url = os.environ.get("KEYCLOAK_URL")
    opa_url = os.environ.get("OPA_URL")
    if keycloak_url and opa_url:
        run_live_smoke_test(keycloak_url, opa_url)
    else:
        print("\n(set KEYCLOAK_URL and OPA_URL, after `docker compose up`, to also "
              "run a live smoke test against real Keycloak + OPA)")


if __name__ == "__main__":
    main()
