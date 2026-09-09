"""The gatekeeper HTTP gateway: authenticate, authorize, audit - in that order.

This is the single checkpoint every agent action is meant to pass through.
It deliberately does not try to be a general-purpose API gateway; it does
exactly three things, in a fixed order, and refuses to skip any of them:

  1. authenticate the caller's bearer token against Keycloak (or a static
     JWKS in tests) - who is asking?
  2. ask OPA, driven by policies/agent_authz.rego, whether the action is
     allowed - is this specific action, for this caller, right now, OK?
  3. record the decision - allowed or denied - to the audit lakehouse,
     unconditionally. A denied action is exactly as important to have on
     record as an allowed one.

A denial is not an HTTP error: the caller (an agent, or the service acting
on its behalf) gets a normal 200 with `{"allow": false, "reason": "..."}` so
it can react to being denied. A 401 means the caller couldn't even be
identified; that's the only case treated as a hard error at this layer.
"""
from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from .audit import LakehouseAuditLog
from .auth import KeycloakAuthenticator, TokenValidationError
from .policy import OPAClient, build_action_input


class ActionRequest(BaseModel):
    action_type: str  # "read" | "write" | "destructive"
    resource_id: str
    resource_tier: str = "standard"
    hour_utc: Optional[int] = None


class ActionResponse(BaseModel):
    allow: bool
    reason: str
    agent_subject: str
    audit_id: str


def create_app(
    authenticator: KeycloakAuthenticator,
    opa_client: OPAClient,
    audit_log: LakehouseAuditLog,
) -> FastAPI:
    app = FastAPI(title="Agent Gatekeeper", version="0.1.0")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/actions/check", response_model=ActionResponse)
    def check_action(
        request: ActionRequest,
        authorization: str = Header(..., description="Bearer <access token>"),
    ) -> ActionResponse:
        try:
            identity = authenticator.authenticate(authorization)
        except TokenValidationError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

        input_doc = build_action_input(
            identity,
            action_type=request.action_type,
            resource_id=request.resource_id,
            resource_tier=request.resource_tier,
            hour_utc=request.hour_utc,
        )
        decision = opa_client.evaluate(input_doc)

        entry = audit_log.record(
            agent_subject=identity.subject,
            client_id=identity.client_id,
            action_type=request.action_type,
            resource_id=request.resource_id,
            resource_tier=request.resource_tier,
            allow=decision.allow,
            reason=decision.reason,
        )

        return ActionResponse(
            allow=decision.allow,
            reason=decision.reason,
            agent_subject=identity.subject,
            audit_id=entry.audit_id,
        )

    @app.get("/v1/audit/recent")
    def recent(limit: int = 20) -> list[dict]:
        return audit_log.recent(limit)

    @app.get("/v1/audit/denials")
    def denials(limit: int = 20) -> list[dict]:
        return audit_log.recent_denials(limit)

    return app
