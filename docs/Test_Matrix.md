# Ma Trận Kiểm Thử Lỗ Hổng BOLA và Zero-Trust (AuthZ Test Matrix)

| Case | Kẻ tấn công (Role / ID) | Nạn nhân (Owner ID) | Method / API Endpoint | Hành động | Kết quả mong đợi | OPA Reason (Minh chứng E-X2 & E-Z1) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1 (Hợp lệ)** | User / ID: 10 | ID: 10 | `GET /api/v1/users/10/pii` | Xem data của chính mình | **200 OK** | `Allow: User ID 10 owns resource of User ID 10` |
| **2 (BOLA)** | User / ID: 10 | ID: 11 | `GET /api/v1/users/11/pii` | Sửa URL đổi ID để xem lén data người khác | **403 Forbidden** | `Deny: User ID 10 attempted to access resource of User ID 11 (BOLA Attack Blocked)` |
| **3 (Admin)** | Admin / ID: 99 | ID: 10 | `GET /api/v1/users/10/pii` | Admin kiểm tra data khách hàng | **200 OK** | `Allow: Admin ID 99 accessed resource of User ID 10` |
| **4 (Thiếu Data)** | User / ID: null | ID: 10 | `GET /api/v1/users/10/pii` | Gửi request lỗi cấu trúc, thiếu ID | **403 Forbidden** | `Deny: Missing user_id or owner_id in the request payload` |
| **5 (Zero-Trust E-Z1)**| User / ID: 10 | ID: 10 | `DELETE /api/v1/users/10/pii` | Cố tình gửi request xóa dữ liệu (Hành động không khai báo) | **403 Forbidden** | `Deny: HTTP Method 'DELETE' is not allowed for this endpoint (E-Z1 Policy)` |
| **6 (Zero-Trust E-Z1)**| Admin / ID: 99 | ID: 10 | `PUT /api/v1/users/10/pii` | Cố tình dùng quyền Admin để update data trái phép | **403 Forbidden** | `Deny: HTTP Method 'PUT' is not allowed for this endpoint (E-Z1 Policy)` |