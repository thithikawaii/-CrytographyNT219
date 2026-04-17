# PHÂN TÍCH TÀI SẢN VÀ RỦI RO (ASSET-CENTRIC CONTEXT)

## 1. Danh mục tài sản (Assets)
Dựa theo mô hình Asset-Centric và Checklist V2, hệ thống tập trung bảo vệ các lớp tài sản cốt lõi sau:

*   **A1. Dữ liệu (Data):** Thông tin định danh cá nhân (PII) của khách hàng (ví dụ: Căn cước công dân, Số điện thoại). 
    *   *Trạng thái vòng đời:* Bảo vệ khép kín ở 3 trạng thái gồm *in-transit* (khi truyền tải qua mạng), *in-process* (khi xử lý trên RAM Node 2), và *at-rest* (khi lưu trữ tĩnh tại Database Node 3).
*   **A2. Bí mật & Khóa (Secrets & Keys):** 
    *   Master Key (KEK) quản lý tại biến môi trường (Backend).
    *   Data Encryption Keys (DEK) được mã hóa phong bì (Envelope Encryption) và lưu tại Database.
    *   Thông tin xác thực Database (DB Credentials).
*   **A3. Danh tính (Identities):** 
    *   *Người dùng (Users):* Định danh thông qua JWT (chứa `user_id`, `role`).
    *   *Dịch vụ nội bộ (Microservices):* Định danh thông qua địa chỉ IP Tailscale và DB Credentials.
*   **A4. Trạng thái & Chính sách (State & Policies):** 
    *   Phiên đăng nhập (JWT Session) được kiểm soát và thu hồi bởi cụm Redis Blacklist.
    *   Chính sách kiểm soát truy cập (RBAC + Ownership Check).
*   **A5. Hạ tầng tin cậy (Trust Infrastructure):** API Gateway (Nginx) quản lý chứng chỉ TLS 1.3 và Hạ tầng mạng riêng ảo (Tailscale/WireGuard).

---

## 2. Ngữ cảnh và Ràng buộc (Context & Constraints)

*   **Đặc thù nghiệp vụ:** Là dịch vụ API cho doanh nghiệp nhỏ (SME - Topic 10). Hệ thống ưu tiên tối ưu chi phí vận hành (không dùng HSM đắt tiền), dễ bảo trì, tự động hóa bảo mật và tinh gọn.
*   **Kiến trúc triển khai:** Áp dụng **Kịch bản D2 (Zero-Trust Tối giản)** phân tán trên 3 Nodes độc lập: Node 1 (Gateway), Node 2 (Backend), Node 3 (Database).
*   **Trust Boundaries (Ranh giới tin cậy):**
    *   *Internet → Node 1 (Gateway):* Ranh giới Public. Được bảo vệ nghiêm ngặt bởi giao thức TLS 1.3.
    *   *Node 1 → Node 2 → Node 3:* Ranh giới Private. Chạy ngầm trong mạng Tailscale (mã hóa WireGuard end-to-end). HTTP nội bộ giữa Node 1 và Node 2 được chấp nhận để tối ưu hiệu năng nhờ đã có lớp mạng Tailscale bảo vệ.
*   **Bảo vệ Database:** Node 3 (DB) được cưỡng chế tường lửa UFW và `MySQL GRANT`, chỉ chấp nhận duy nhất kết nối định danh từ IP Tailscale của Node 2.

---

## 3. Phân tích rủi ro & Ngưỡng cam kết bảo vệ (SMART Goals)

*   **R1a. Lộ dữ liệu tĩnh (Data leakage at-rest):**
    *   *Bề mặt tấn công:* Kẻ tấn công nội bộ hoặc hacker xâm nhập được Node 3 và dump Database.
    *   *Giải pháp:* Mã hóa tại chỗ (Envelope Encryption) bằng thuật toán AES-GCM-256.
    *   *Mục tiêu (E-C1):* Rò rỉ **0 byte** plaintext PII khi dump trực tiếp Database.

*   **R1b. Lộ dữ liệu đường truyền (Data leakage in-transit):**
    *   *Bề mặt tấn công:* Attacker trên Internet thực hiện Man-In-The-Middle (MITM) nghe lén gói tin.
    *   *Giải pháp:* Cưỡng chế HTTPS, cấu hình chứng chỉ SAN chuẩn, giao thức TLS 1.3.
    *   *Mục tiêu (I1):* Rò rỉ **0 byte** plaintext trên kênh truyền mạng.

*   **R2. Can thiệp dữ liệu trái phép (Tampering):**
    *   *Bề mặt tấn công:* Kẻ tấn công lén sửa đổi, giả mạo ciphertext trong Database nhằm phá hoại logic hệ thống.
    *   *Giải pháp:* Sử dụng tính năng xác thực tính toàn vẹn bằng MAC (Auth Tag) của thuật toán AES-GCM.
    *   *Mục tiêu (E-C3):* Tỷ lệ phát hiện và đánh chặn = **100%** (Hệ thống từ chối giải mã và văng lỗi `AEAD MAC check failed`).

*   **R3. Chiếm đoạt phiên & Tấn công xác thực (AuthN Risk):**
    *   *Bề mặt tấn công:* Đánh cắp JWT và tái sử dụng (Replay attack) token của người dùng đã đăng xuất.
    *   *Giải pháp:* Sử dụng JWT có thời hạn (TTL) ngắn kết hợp Redis Blacklist để thu hồi trạng thái (Stateful).
    *   *Mục tiêu (E-AuthN):* Lockout latency **≤ 1s** (Token bị vô hiệu hóa gần như ngay lập tức sau lệnh `/logout`).

*   **R4. Lỗ hổng BOLA (Broken Object Level Authorization):**
    *   *Bề mặt tấn công:* User hợp lệ cố tình đổi tham số ID trên URL để xem trái phép hồ sơ của người khác.
    *   *Giải pháp:* Thực thi chính sách RBAC kết hợp Ownership Check tại lớp Backend; ghi log cấu trúc cho mọi request.
    *   *Mục tiêu (E-AuthZ):* Pass-rate chặn BOLA = **100%**. Explainability (Khả năng tái dựng lý do từ log) = **100%**.

*   **R5. Lộ khóa Master (KEK Compromise):**
    *   *Bề mặt tấn công:* Hacker trích xuất được file `.env` chứa khóa KEK tại Node 2.
    *   *Giải pháp:* Xây dựng kịch bản xoay vòng khóa (Key Rotation) để mã hóa lại toàn bộ DEK hiện có mà không làm gián đoạn dữ liệu PII.
    *   *Mục tiêu (E-X1):* Thời gian hoàn tất rotate **≤ 10 phút**; Tác động rủi ro (Blast-radius) **≤ 24h**.

---

## 4. Các khẳng định bảo mật (Invariants)
Hệ thống cam kết duy trì và sẽ thực hiện kiểm chứng các tính chất bất biến (Invariants) sau trong giai đoạn Evaluation (Đánh giá Cuối kỳ):

*   **I1 - Không rò rỉ plaintext:** Không có bất kỳ plaintext PII nào bị lộ trên kênh bảo vệ TLS 1.3 và khi lưu trữ tại Database. *(Kiểm chứng bằng Wireshark và DBeaver - E-C1).*
*   **I2 - Tampering bị từ chối:** Mọi hành vi can thiệp ciphertext tại DB đều bị thuật toán từ chối giải mã và sinh log hệ thống. *(Kiểm chứng bằng kịch bản sửa 1 ký tự Base64 trên DB - E-C3).*
*   **I3 - Tính khả dụng & Toàn vẹn (Data Authentication):** Dữ liệu hợp lệ lấy lên từ DB giữ nguyên trạng thái gốc, không bị biến đổi sai lệch. *(Kiểm chứng bằng Closed-loop test POST ↔ GET).*
*   **I4 - AuthN chống Replay:** JWT đã bị Logout sẽ bị cụm Redis Blacklist từ chối ngay lập tức. *(Kiểm chứng bằng Automation Test gọi lại API bằng token đã thu hồi).*
*   **I5 - AuthZ giải thích được (Explainability):** Quyết định ủy quyền (đánh chặn BOLA) được thi hành triệt để và giải thích được rõ ràng qua Log. *(Trích xuất Structured Log từ Backend).*
*   **I6 - Vận hành khóa quan sát được:** Xoay vòng KEK diễn ra nhanh chóng, có kịch bản rõ ràng, giới hạn được blast-radius. *(Chạy Script `rotate_key.py` tính thời gian Benchmark - E-X1).*