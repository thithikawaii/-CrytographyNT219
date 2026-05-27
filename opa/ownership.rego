package authz

default allow = false

# 1. Kiểm tra đủ data đầu vào
has_ids {
    input.user_id != null
    input.owner_id != null
}

# 2. Định nghĩa quyền Admin
is_admin {
    input.role == "admin"
}

# 3. NHẬN DIỆN API VÀ METHOD (Fix conflict chặn nhầm POST)
is_pii_endpoint {
    startswith(input.path, "/api/v1/users/")
    endswith(input.path, "/pii")
}

is_allowed_method {
    input.method == "GET"
}

# Các API Public không cần check BOLA (cho qua)
is_public_api {
    input.path == "/users"
    input.method == "POST"
}
is_public_api {
    input.path == "/login"
}
is_public_api {
    input.path == "/enable-2fa"
}
is_public_api {
    input.path == "/verify-2fa"
}

# 4. RULE CHO PHÉP (ALLOW)
allow {
    is_public_api
}

allow {
    is_pii_endpoint
    is_allowed_method
    is_admin
}

allow {
    is_pii_endpoint
    is_allowed_method
    has_ids
    input.user_id == input.owner_id
}

# 5. XUẤT LÝ DO (REASON) - Xử lý E-X2 và E-Z1
reason = msg {
    is_public_api
    msg := "Allow: Public API endpoint accessed"
} else = msg {
    is_pii_endpoint
    not is_allowed_method
    msg := sprintf("Deny: HTTP Method '%v' is not allowed for PII endpoint (E-Z1 Policy)", [input.method])
} else = msg {
    is_pii_endpoint
    is_allowed_method
    is_admin
    msg := sprintf("Allow: Admin ID %v accessed resource of User ID %v", [input.user_id, input.owner_id])
} else = msg {
    is_pii_endpoint
    is_allowed_method
    has_ids
    input.user_id == input.owner_id
    msg := sprintf("Allow: User ID %v owns resource of User ID %v", [input.user_id, input.owner_id])
} else = msg {
    is_pii_endpoint
    is_allowed_method
    has_ids
    input.user_id != input.owner_id
    not is_admin
    msg := sprintf("Deny: User ID %v attempted to access resource of User ID %v (BOLA Attack Blocked)", [input.user_id, input.owner_id])
} else = msg {
    is_pii_endpoint
    msg := "Deny: Missing user_id or owner_id in the request payload"
} else = msg {
    # CÚ CHỐT CHẶN CUỐI CÙNG (CATCH-ALL) - ĐÃ GỘP Ý CỦA QUYÊN VÀ IN RA ĐƯỜNG DẪN BỊ CHẶN
    msg := sprintf("Deny: Endpoint is not defined, not public, or access denied by default (Zero-Trust Policy blocked: %v %v)", [input.method, input.path])
}

# 6. Đóng gói kết quả trả về cho Backend (Backend sẽ nhận được cục JSON sạch sẽ này)
decision = {"allow": allow, "reason": reason}