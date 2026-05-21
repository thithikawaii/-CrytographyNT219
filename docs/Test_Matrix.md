# Ma Trận Kiểm Thử Lỗ Hổng BOLA (AuthZ Test Matrix)

| Case | Kẻ tấn công (Role / ID) | Nạn nhân (Owner ID) | API Endpoint | Hành động | Kết quả mong đợi | OPA Reason (E-X2) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1 (Hợp lệ)** | User / ID: 10 | ID: 10 | `GET /api/v1/users/10/pii` | Xem data của chính mình | **200 OK** | `Allow: User ID 10 owns resource...` |
| **2 (BOLA)** | User / ID: 10 | ID: 11 | `GET /api/v1/users/11/pii` | Sửa URL đổi ID để xem lén | **403 Forbidden** | `Deny: User ID 10 attempted... (BOLA Attack Blocked)` |
| **3 (Admin)** | Admin / ID: 99 | ID: 10 | `GET /api/v1/users/10/pii` | Kiểm tra data khách hàng | **200 OK** | `Allow: Admin ID 99 accessed...` |
| **4 (Thiếu)** | User / ID: null | ID: 10 | `GET /api/v1/users/10/pii` | Gửi request lỗi cấu trúc | **403 Forbidden** | `Deny: Missing user_id...` |