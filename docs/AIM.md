# PHÂN TÍCH TÀI SẢN VÀ RỦI RO (ASSET-CENTRIC CONTEXT)

## 1. Danh mục tài sản (Assets)
Dựa theo mô hình Asset-Centric, hệ thống của chúng tôi tập trung bảo vệ các tài sản sau:
- **A1. Dữ liệu (Data):** Thông tin định danh cá nhân (PII) của khách hàng bao gồm `cccd`, `phone_number`. Dữ liệu này cần được bảo vệ ở trạng thái tĩnh (at-rest) tại Database và trạng thái truyền tải (in-transit) qua mạng.
- **A2. Bí mật & Khóa (Secrets & Keys):** Master Key (KEK) lưu trữ tại Mock KMS (biến môi trường Node 2), DEK được mã hóa và lưu trữ tại Database Node 3. Khóa này chỉ có thể giải mã thông qua KEK tại Backend.
- **A3. Danh tính (Identities):** Người dùng hệ thống (Admin, User) và các dịch vụ nội bộ.
- **A4. Trạng thái & Chính sách (State & Policies):** JWT Session được quản lý qua Redis Blacklist và luật phân quyền RBAC kết hợp Ownership.
- **A5. Hạ tầng tin cậy (Trust Infrastructure):** Nginx đóng vai trò API Gateway quản lý chứng chỉ TLS 1.3 tự ký.

## 2. Ngữ cảnh và Ràng buộc (Context & Constraints)
- **Kiến trúc triển khai:** Hệ thống áp dụng kịch bản D2 (OpenStack VM - Zero-Trust tối giản) triển khai phân tán trên 3 máy ảo Ubuntu. Node 1 (Gateway) tiếp xúc bên ngoài; Node 2 (Backend) và Node 3 (DB) hoàn toàn cô lập.

## 3. Phân tích rủi ro & Mục tiêu bảo vệ định lượng (SMART Goals)
- **Rủi ro 1 - Lộ dữ liệu tĩnh & truyền tải:** Kẻ tấn công dump database hoặc đánh chặn MITM. 
  - *Giải pháp:* Bảo vệ kênh truyền bằng TLS 1.3 và mã hóa dữ liệu at-rest bằng AES-GCM-256.
  - *Mục tiêu (E-Crypto):* **0 byte** plaintext rò rỉ khi dump trực tiếp DB.
- **Rủi ro 2 - Tampering (Chỉnh sửa dữ liệu trái phép):** Kẻ tấn công thay đổi nội dung bản mã.
  - *Giải pháp:* Sử dụng tính năng xác thực (Auth Tag) của thuật toán AES-GCM.
  - *Mục tiêu (E-Crypto):* Lỗi AEAD error = **100%**.
- **Rủi ro 3 - BOLA (Broken Object Level Authorization):** Truy cập chéo hồ sơ.
  - *Giải pháp:* Áp dụng RBAC và Ownership Check (So sánh User ID trong Token và Owner ID của tài nguyên).
  - *Mục tiêu (E-AuthZ):* Policy pass-rate = **100%** (Chặn đứng hoàn toàn truy cập chéo).
- **Rủi ro 4 - Lộ khóa Master (KEK):** 
  - *Giải pháp:* Áp dụng mã hóa phong bì (Envelope Encryption). Khi có sự cố, chỉ cần xoay vòng khóa KEK để mã hóa lại các khóa DEK.
  - *Mục tiêu (E-X1):* Kịch bản xoay vòng khóa mô phỏng hoàn tất **≤ 10 phút**.

## 4. Các khẳng định bảo mật (Invariants)
- **I1:** Không rò rỉ plaintext PII trên kênh bảo vệ TLS 1.3 và Database.
- **I2:** Mọi hành vi can thiệp ciphertext tại DB sẽ bị từ chối giải mã (AEAD Error).
- **I4:** JWT Token bị vô hiệu hóa tức thời khi đăng xuất nhờ Redis Blacklist.
- **I5:** Quyết định AuthZ từ chối BOLA được thực thi bằng RBAC + Ownership Check.
- **I6:** Có quy trình (Runbook) rõ ràng cho việc xoay vòng khóa KEK khi xảy ra sự cố.