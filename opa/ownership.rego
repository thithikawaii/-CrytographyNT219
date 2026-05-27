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

# 3. Kiểm tra Method hợp lệ (Tiêu chí E-Z1: Chặn hành động không khai báo)
# Giả sử API lấy thông tin PII chỉ cho phép method GET
is_allowed_method {
    input.method == "GET"
}

# 4. Rule Cho Phép (Allow) - Bắt buộc phải đúng Method
allow {
    is_allowed_method
    is_admin
}

allow {
    is_allowed_method
    has_ids
    input.user_id == input.owner_id
}

# 5. CHỐT CHẶN REASON BẰNG MỆNH ĐỀ "ELSE" (Tránh bẫy Multiple Assignments)
reason = msg {
    not is_allowed_method
    msg := sprintf("Deny: HTTP Method '%v' is not allowed for this endpoint (E-Z1 Policy)", [input.method])
} else = msg {
    is_allowed_method
    is_admin
    msg := sprintf("Allow: Admin ID %v accessed resource of User ID %v", [input.user_id, input.owner_id])
} else = msg {
    is_allowed_method
    has_ids
    input.user_id == input.owner_id
    msg := sprintf("Allow: User ID %v owns resource of User ID %v", [input.user_id, input.owner_id])
} else = msg {
    is_allowed_method
    has_ids
    input.user_id != input.owner_id
    not is_admin
    msg := sprintf("Deny: User ID %v attempted to access resource of User ID %v (BOLA Attack Blocked)", [input.user_id, input.owner_id])
} else = msg {
    msg := "Deny: Missing user_id or owner_id in the request payload"
}

# 6. Đóng gói kết quả trả về cho Backend (Backend sẽ ghi log JSON phần này)
decision = {"allow": allow, "reason": reason}