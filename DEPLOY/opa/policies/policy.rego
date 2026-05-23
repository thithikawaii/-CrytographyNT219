package policy

import rego.v1

default allow := false

allow if {
    input.token_user_id == input.requested_user_id
}

result := {
    "allow": true,
    "reason": "Allowed"
} if allow

result := {
    "allow": false,
    "reason": "User ID mismatch"
} if not allow