"""Thin client for OPA's Data REST API.

Design intent: authorization logic lives in policies/agent_authz.rego as
versioned, independently-testable policy-as-code - not scattered across
if/else branches in application code. This module's only job is to shape a
request the way OPA expects (``POST /v1/data/<path>`` with ``{"input": ...}``)
and turn its response into a typed PolicyDecision. It deliberately has no
opinion about *what* the policy decides - swapping the Rego file changes
agent behavior without touching this client or the gateway that calls it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from .auth import AgentIdentity


@dataclass
class PolicyDecision:
    allow: bool
    reason: str
    raw_response: dict[str, Any] = field(default_factory=dict)


class OPAClient:
    """Evaluates action requests against a running OPA server."""

    def __init__(
        self,
        base_url: str,
        *,
        policy_path: str = "agent_authz/decision",
        timeout: float = 5.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._endpoint = f"{base_url.rstrip('/')}/v1/data/{policy_path.strip('/')}"
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None

    def evaluate(self, input_doc: dict[str, Any]) -> PolicyDecision:
        response = self._client.post(self._endpoint, json={"input": input_doc})
        response.raise_for_status()
        body = response.json()

        # OPA omits "result" entirely when the queried path is undefined for
        # this input (e.g. the policy package/rule name is wrong) - treat
        # that as a deny rather than letting a KeyError leak out, since a
        # gate that fails open on a misconfigured policy path is worse than
        # one that fails closed.
        result = body.get("result")
        if result is None:
            return PolicyDecision(
                allow=False,
                reason="policy evaluation returned no result (undefined query)",
                raw_response=body,
            )

        return PolicyDecision(
            allow=bool(result.get("allow", False)),
            reason=str(result.get("reason", "")),
            raw_response=body,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "OPAClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def build_action_input(
    identity: AgentIdentity,
    *,
    action_type: str,
    resource_id: str,
    resource_tier: str = "standard",
    hour_utc: Optional[int] = None,
) -> dict[str, Any]:
    """Build the input document shape that policies/agent_authz.rego expects.

    Centralizing this in one place means the gateway, the demo script, and
    the tests can't quietly drift into three different input shapes.
    """
    import datetime

    if hour_utc is None:
        hour_utc = datetime.datetime.now(datetime.timezone.utc).hour

    return {
        "subject": {
            "id": identity.subject,
            "client_id": identity.client_id,
            "scopes": identity.scopes,
        },
        "action": {"type": action_type},
        "resource": {"id": resource_id, "tier": resource_tier},
        "context": {"hour_utc": hour_utc},
    }
