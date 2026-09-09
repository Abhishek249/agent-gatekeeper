# Standard `opa test` suite for the policy. Run with:
#   opa test policies/ -v
#
# This is the authoritative test of the policy logic against the real OPA
# engine. tests/test_policy_rego.py in the Python test suite covers the same
# cases through a local Rego interpreter (regopy) so the policy is verified
# even in environments without the OPA binary installed - see that file for
# why both exist.
package agent_authz_test

import data.agent_authz.decision
import rego.v1

test_read_is_always_allowed if {
	decision.allow with input as {"action": {"type": "read"}, "subject": {"scopes": []}, "resource": {"tier": "standard"}, "context": {"hour_utc": 3}}
}

test_write_allowed_with_write_scope if {
	decision.allow with input as {"action": {"type": "write"}, "subject": {"scopes": ["actions:write"]}, "resource": {"tier": "standard"}, "context": {"hour_utc": 3}}
}

test_write_denied_without_write_scope if {
	not decision.allow with input as {"action": {"type": "write"}, "subject": {"scopes": []}, "resource": {"tier": "standard"}, "context": {"hour_utc": 3}}
}

test_write_to_critical_denied_without_override if {
	not decision.allow with input as {"action": {"type": "write"}, "subject": {"scopes": ["actions:write"]}, "resource": {"tier": "critical"}, "context": {"hour_utc": 3}}
}

test_write_to_critical_allowed_with_override if {
	decision.allow with input as {"action": {"type": "write"}, "subject": {"scopes": ["actions:write", "actions:override"]}, "resource": {"tier": "critical"}, "context": {"hour_utc": 3}}
}

test_destructive_allowed_in_business_hours if {
	decision.allow with input as {"action": {"type": "destructive"}, "subject": {"scopes": ["actions:destructive"]}, "resource": {"tier": "standard"}, "context": {"hour_utc": 15}}
}

test_destructive_denied_outside_business_hours if {
	not decision.allow with input as {"action": {"type": "destructive"}, "subject": {"scopes": ["actions:destructive"]}, "resource": {"tier": "standard"}, "context": {"hour_utc": 2}}
}

test_destructive_denied_without_scope_even_in_hours if {
	not decision.allow with input as {"action": {"type": "destructive"}, "subject": {"scopes": []}, "resource": {"tier": "standard"}, "context": {"hour_utc": 15}}
}

test_unknown_action_type_denied_by_default if {
	not decision.allow with input as {"action": {"type": "bogus"}, "subject": {"scopes": ["actions:write", "actions:destructive"]}, "resource": {"tier": "standard"}, "context": {"hour_utc": 15}}
}
