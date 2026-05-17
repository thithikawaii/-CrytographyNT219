package authz

default allow = false

has_ids {
  input.user_id != null
  input.owner_id != null
}

allow {
  has_ids
  input.user_id == input.owner_id
}

reason = msg {
  has_ids
  allow
  msg := sprintf("Allow: User %v owns resource of User %v", [input.user_id, input.owner_id])
}

reason = msg {
  has_ids
  not allow
  msg := sprintf("Deny: User %v attempted to access resource of User %v (BOLA Attack Blocked)", [input.user_id, input.owner_id])
}

reason = msg {
  not has_ids
  msg := "Deny: Missing user_id or owner_id"
}

decision = {"allow": allow, "reason": reason}
