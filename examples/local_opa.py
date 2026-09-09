"""A local Rego evaluator with the same interface as gatekeeper.policy.OPAClient.

Used only when no real OPA server is reachable. It loads the exact same
policies/agent_authz.rego file the docker-compose OPA container serves and
evaluates it in-process via regopy (a Rego interpreter), rather than faking
decisions - "python -m examples.demo" with no infrastructure running still
exercises the real policy logic, just through a different transport than
the HTTP path gateway.py uses in production.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import regopy

from gatekeeper.policy import PolicyDecision

DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "policies" / "agent_authz.rego"


class LocalRegoEvaluator:
    def __init__(self, policy_file: Path = DEFAULT_POLICY_PATH) -> None:
        self._policy_source = policy_file.read_text()

    def evaluate(self, input_doc: dict[str, Any]) -> PolicyDecision:
        # A fresh interpreter per call keeps this stateless and avoids a
        # (regopy-specific) query-caching quirk across repeated queries with
        # different inputs on the same interpreter instance.
        interp = regopy.Interpreter()
        interp.add_module("agent_authz", self._policy_source)
        interp.set_input(input_doc)
        output = interp.query("data.agent_authz")
        body = json.loads(str(output))
        result = body["expressions"][0]["decision"]
        return PolicyDecision(
            allow=bool(result.get("allow", False)),
            reason=str(result.get("reason", "")),
            raw_response=body,
        )

    def close(self) -> None:
        pass
