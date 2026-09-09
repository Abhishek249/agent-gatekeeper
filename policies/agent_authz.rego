# Policy-as-code for the Agent Gatekeeper.
#
# Every action an agent wants to take is described as a small JSON document
# (see gatekeeper/policy.py for the exact shape) and evaluated against this
# policy. The design deliberately mirrors a real authorization model rather
# than a toy example:
#
#   - default deny: an action is blocked unless a rule explicitly allows it.
#   - scope-based access: the caller's OAuth2 scopes (issued by Keycloak)
#     gate which action types it may perform, the same way a real service
#     account's token scopes would.
#   - resource-tier sensitivity: writes to "critical" resources need an
#     additional override scope on top of the base write scope.
#   - time-boxing: destructive actions are further restricted to a
#     business-hours window, so an agent can't run a destructive action
#     at 3am with no human around to notice.
#
# The if/else-if chain (rather than several independent `decision` rules)
# is intentional: Rego treats a complete rule like `decision` as an error if
# two rule bodies produce different values for the same input, so an
# else-chain is the idiomatic way to guarantee at most one branch fires.
package agent_authz

import rego.v1

default decision := {
	"allow": false,
	"reason": "no matching rule: default deny",
}

decision := result if {
	input.action.type == "read"
	result := {
		"allow": true,
		"reason": "read-only action permitted for any authenticated agent",
	}
} else := result if {
	input.action.type == "write"
	input.resource.tier == "critical"
	"actions:write" in input.subject.scopes
	"actions:override" in input.subject.scopes
	result := {
		"allow": true,
		"reason": "write to critical resource permitted: override scope present",
	}
} else := result if {
	input.action.type == "write"
	input.resource.tier == "critical"
	result := {
		"allow": false,
		"reason": "write to critical resource blocked: actions:override scope required",
	}
} else := result if {
	input.action.type == "write"
	"actions:write" in input.subject.scopes
	result := {
		"allow": true,
		"reason": "write action permitted: actions:write scope present",
	}
} else := result if {
	input.action.type == "write"
	result := {
		"allow": false,
		"reason": "write action blocked: actions:write scope missing",
	}
} else := result if {
	input.action.type == "destructive"
	"actions:destructive" in input.subject.scopes
	within_business_hours
	result := {
		"allow": true,
		"reason": "destructive action permitted: actions:destructive scope present and within business hours",
	}
} else := result if {
	input.action.type == "destructive"
	"actions:destructive" in input.subject.scopes
	not within_business_hours
	result := {
		"allow": false,
		"reason": "destructive action blocked: outside business hours (13:00-21:00 UTC)",
	}
} else := result if {
	input.action.type == "destructive"
	result := {
		"allow": false,
		"reason": "destructive action blocked: actions:destructive scope missing",
	}
}

# Business hours window is intentionally simple (UTC hour range) - the point
# being demonstrated is that the *policy*, not the agent's own code, decides
# when a destructive action is allowed to run, and that decision is
# versioned and auditable independently of the agent.
within_business_hours if {
	input.context.hour_utc >= 13
	input.context.hour_utc < 21
}
