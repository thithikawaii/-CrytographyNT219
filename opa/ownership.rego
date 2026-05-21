package authz

default allow = false

# 1. Kiểm tra xem có đủ data đầu vào không
has_ids {
  input.user_id != null
  input.owner_id != null
}

# 2. Định nghĩa quyền Admin
is_admin {
  input.role == "admin"
}

# 3. Rule Cho Phép (Allow)
allow {
  is_admin
}

allow {
  has_ids
  input.user_id == input.owner_id
}

# 4. CHỐT CHẶN REASON BẰNG MỆNH ĐỀ "ELSE" (Tránh bẫy Multiple Assignments)
reason = msg {
  is_admin
  msg := sprintf("Allow: Admin ID %v accessed resource of User ID %v", [input.user_id, input.owner_id])
} else = msg {
  has_ids
  input.user_id == input.owner_id
  msg := sprintf("Allow: User ID %v owns resource of User ID %v", [input.user_id, input.owner_id])
} else = msg {
  has_ids
  input.user_id != input.owner_id
  not is_admin
  msg := sprintf("Deny: User ID %v attempted to access resource of User ID %v (BOLA Attack Blocked)", [input.user_id, input.owner_id])
} else = msg {
  not has_ids
  msg := "Deny: Missing user_id or owner_id"
}

# 5. Đóng gói kết quả trả về cho Backend
decision = {"allow": allow, "reason": reason}