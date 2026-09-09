# Agent Gatekeeper

A policy checkpoint that autonomous agents call before taking an action -
authenticate who's asking (Keycloak / OIDC), decide whether the action is
allowed (Open Policy Agent / Rego), and record the decision either way to a
partitioned, SQL-queryable audit trail (a lightweight Parquet lakehouse, in
the shape a real Apache Iceberg table would take).

This exists because "let the agent operate safely and responsibly" is a
policy problem, not a prompting problem. Baking a rule like "never touch a
critical resource without approval" into an agent's system prompt or its
own code means every agent has to get it right, and there's nowhere outside
the agent's own behavior to audit whether it did. Moving that decision to a
gate the agent's action has to pass through - and to a policy file a human
can review and version independently of the agent - is what makes "safe"
something you can actually verify instead of something you hope for.

## Why these three standards specifically

- **OIDC / Keycloak** for identity, because an agent's permissions should be
  tied to a real, revocable credential (an OAuth2 client-credentials grant),
  not a string the agent's own code decides to send. `gatekeeper/auth.py`
  never issues a token - it only verifies one, the same way it would verify
  a token from any standards-compliant identity provider.
- **OPA / Rego** for authorization, because "what is this agent allowed to
  do" is exactly the kind of policy-as-code OPA was built for: versioned,
  testable independently of the application, and evaluated the same way
  whether the caller is this project's gateway or a completely different
  service. `policies/agent_authz.rego` is the actual authority; nothing in
  this repo hardcodes an authorization rule in Python.
- **A Parquet lakehouse** (DuckDB-queryable, partitioned by date) for the
  audit trail, because "what did the agents do" needs to be answerable with
  SQL over history, not a log grep. The write path (one immutable file per
  decision batch) and read path (SQL over a partitioned glob) are exactly
  the shape Apache Iceberg expects - swapping in a real Iceberg table later
  is a storage-layer change, not a rethink of the audit model.

## Architecture

```
   agent  --Bearer token-->  gatekeeper/gateway.py  --POST /v1/data/...-->  OPA
                                     |                                  (policies/agent_authz.rego)
                                     |
                              gatekeeper/auth.py
                              (verifies token against
                               Keycloak's JWKS)
                                     |
                                     v
                        gatekeeper/audit.py (every decision,
                        allow or deny, -> Parquet, partitioned
                        by date, queryable via DuckDB)
```

```
agent-gatekeeper/
  policies/
    agent_authz.rego        # the actual authorization policy
    agent_authz_test.rego   # opa test suite (run against real OPA)
  gatekeeper/
    auth.py                 # verifies Keycloak-issued JWTs via JWKS
    policy.py                # OPA REST client + input-shape builder
    audit.py                 # Parquet lakehouse writer/reader (DuckDB)
    gateway.py                # FastAPI app wiring the three together
  examples/
    local_idp.py             # real RSA-signed JWTs, no Keycloak required
    local_opa.py              # real Rego evaluation, no OPA server required
    demo.py                    # runnable end-to-end walkthrough
  tests/                       # 33 tests covering all of the above
  docker-compose.yml           # real Keycloak + real OPA
  keycloak/realm-export.json   # preconfigured realm + demo-agent client
```

## Quickstart (no infrastructure required)

```bash
pip install -r requirements.txt
python -m examples.demo
```

This authenticates a locally-signed (but genuinely RSA-signed and verified)
token, evaluates seven scenarios against the real `policies/agent_authz.rego`
through a local Rego interpreter, and writes every decision to
`audit-lake/`, then queries it back with DuckDB. See `examples/local_idp.py`
and `examples/local_opa.py` for exactly what's being stood in for and why -
neither one fakes a result; they run the real verification/evaluation logic
against locally-generated (rather than Keycloak/OPA-served) inputs.

## Quickstart (real Keycloak + real OPA)

```bash
docker compose up
export KEYCLOAK_URL=http://localhost:8080
export OPA_URL=http://localhost:8181
python -m examples.demo   # now also runs a live round through both services
```

Or run the gateway itself:

```bash
python -c "
import os
from gatekeeper import KeycloakAuthenticator, LakehouseAuditLog
from gatekeeper.policy import OPAClient
from gatekeeper.gateway import create_app
import uvicorn

authenticator = KeycloakAuthenticator(
    jwks_url='http://localhost:8080/realms/agents/protocol/openid-connect/certs',
    issuer='http://localhost:8080/realms/agents',
)
app = create_app(authenticator, OPAClient('http://localhost:8181'), LakehouseAuditLog('audit-lake'))
uvicorn.run(app, host='0.0.0.0', port=8000)
"
```

Then, having fetched a token from Keycloak's token endpoint for the
`demo-agent` client (`client_id=demo-agent`, `client_secret=demo-agent-secret`,
`grant_type=client_credentials`):

```bash
curl -s localhost:8000/v1/actions/check \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"action_type": "write", "resource_id": "prod-config", "resource_tier": "critical"}'
```

## The policy

`policies/agent_authz.rego` is default-deny. On top of that:

- **read** actions are always allowed for any authenticated agent.
- **write** actions require the `actions:write` scope; writing to a
  `critical`-tier resource additionally requires `actions:override`, which
  is an *optional* Keycloak scope on the demo client - not granted unless
  explicitly requested, the realm-level version of least privilege.
- **destructive** actions require `actions:destructive` *and* fall inside a
  business-hours window (13:00-21:00 UTC) - the policy, not the agent,
  decides when it's acceptable to run something destructive unattended.

## Testing

```bash
pytest -v                # 33 tests: auth, policy client, audit, gateway, and
                          # the policy logic itself via a local Rego interpreter
opa test policies/ -v    # the authoritative check, against real OPA
```

The Rego policy is tested twice, deliberately: `tests/test_policy_rego.py`
runs the same nine scenarios as `policies/agent_authz_test.rego` through
`regopy` (a Rego interpreter with no external binary dependency), so the
policy logic is verified in any Python environment and in CI without
needing OPA installed; `opa test` against the real engine is the
authoritative version to run before trusting a policy change.

## What's deliberately out of scope

There's no multi-agent coordination, no real LLM calls, and the lakehouse
here is Parquet + DuckDB rather than a full Iceberg catalog with snapshot
isolation and time travel - that tradeoff, and how to close it, is called
out specifically in `gatekeeper/audit.py`. The point of this project is the
checkpoint pattern - authenticate, authorize against a real policy engine,
audit unconditionally - not a production-scale data platform.

## License

MIT - see [LICENSE](LICENSE).
