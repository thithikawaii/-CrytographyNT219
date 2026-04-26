# RUNBOOK: Kịch bản Triển khai D1 - Nhóm 10

## 1. Deployment ID & Name
**D1: Dockerized - Cloud-Native Architecture** (Kiến trúc API-Gateway + IdP + PDP dựa trên Docker).

## 2. Mục đích & khác biệt so với kiến trúc tổng
- **Mục đích:** Khởi chạy mô hình bảo mật API cho doanh nghiệp nhỏ (SME) hoàn toàn bằng các container độc lập. Triển khai đầy đủ 3 lớp bảo mật: mTLS ở lớp mạng, mTLS-bound JWT kết hợp OPA ABAC ở tầng ứng dụng, và Envelope Encryption (AES-GCM) ở tầng lưu trữ.
- **Sự khác biệt:** So với kịch bản D2 (Máy ảo phân tán dùng Tailscale VPN), D1 gom cụm toàn bộ các thành phần vào một máy chủ duy nhất nhưng thiết lập sự cô lập thông qua Docker Network.

## 3. Thành phần (BOM)
- **API Gateway:** Nginx 
- **Backend / IdP:** FastAPI (Python 3.10)
- **Policy Decision Point (PDP):** OPA (Open Policy Agent)
- **Cơ sở dữ liệu (Két sắt):** MySQL 8.0
- **Quản lý phiên (Session/Blacklist):** Redis (alpine)
- **Thư viện Crypto lõi:** `cryptography`, `PyJWT`, `pyotp`

## 4. Trust boundaries & Network
- **Public Zone (Untrusted):** Môi trường Internet bên ngoài, chỉ có thể kết nối vào hệ thống qua Port 443 (HTTPS) của Nginx.
- **Private Zone (Trusted - Docker Network `internal_net`):** Mạng nội bộ nơi FastAPI, OPA, Redis và MySQL giao tiếp với nhau. Các cổng 8000, 8181, 6379, 3306 tuyệt đối không được Expose ra ngoài Host (chỉ bind vào `127.0.0.1` hoặc ẩn hoàn toàn trong mạng ảo Docker với cờ `internal: true`).

## 5. Cấu trúc thư mục triển khai

```text
DEPLOY/
├── api_gateway
│   ├── default_no_rate.conf
│   └── default_with_rate.conf
├── database
│   └── schema.sql
├── docker-compose.yml
├── nginx
│   └── certs
│       ├── ca.crt
│       ├── ca.key
│       ├── client.crt
│       ├── client.csr
│       ├── client.key
│       ├── client.p12
│       ├── extfile.cnf
│       ├── server.crt
│       ├── server.csr
│       └── server.key
└── nginx.conf
```
## 6. Các bước cài đặt (Từ máy sạch)
**Bước 1:** Chuẩn bị môi trường (Ubuntu 22.04 LTS)
- sudo apt update && sudo apt install docker.io docker-compose -y
- sudo usermod -aG docker $USER
- newgrp docker

**Bước 2:** Khởi tạo khóa và Chứng chỉ mTLS (Local CA) Tạo thư mục certs và sử dụng OpenSSL để sinh bộ khóa nội bộ (Thực thi trên máy Host node1):
mkdir -p nginx/certs && cd nginx/certs

# 1. Tạo Root CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=Nhóm 10 Root CA"

# 2. Tạo chứng chỉ cho API Gateway (Nginx Server)
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256

# 3. Tạo chứng chỉ Client cho Postman/Data User
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=DataUser_01"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256

# 4. Đóng gói thành file .p12 để Client dễ cài đặt vào trình duyệt/Postman
openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.crt
Bước 3: Khởi chạy hạ tầng Zero-Trust (Docker Compose) Đảm bảo đã cấu hình đủ biến môi trường trong file .env (chứa DB_PASS, REDIS_PASSWORD), sau đó khởi chạy:
# Dọn dẹp môi trường cũ (nếu có) để tránh tràn ổ cứng
docker system prune -af --volumes

# Build và chạy ngầm các container
docker-compose up -d --build

--------------------------------------------------------------------------------
## 7. Bootstrap Secrets/Keys & Rotation
Symmetric Keys (AES-GCM 256-bit): Khóa Data Encryption Key (DEK) được dùng để mã hóa PII dưới Database. Khóa này tạm thời được cấu hình qua biến môi trường của FastAPI container. (Trong Giai đoạn 2 của đồ án (Tuần 5-6), KEK sẽ được quản lý và xoay vòng tự động bằng HashiCorp Vault ≤ 10 phút/lần).
Asymmetric Keys (mTLS): Root CA và Server Certificate được sinh thủ công bằng OpenSSL và mount trực tiếp vào thư mục /etc/nginx/certs của container Nginx dưới quyền Read-Only (:ro).
Database/Cache Passwords: Được nhúng động vào Container thông qua file .env (bỏ qua Git bằng .gitignore để tránh lộ lọt).

## 8. Health Checks & Observability (Metrics/Logs)
Để kiểm tra trạng thái và truy vết lỗi trong quá trình vận hành, sử dụng các lệnh giám sát sau:
Kiểm tra trạng thái các Nodes: docker ps -a (Đảm bảo 4 container đều ở trạng thái Up).
Giám sát Log chặn mTLS của API Gateway: docker logs gateway_nginx (Phát hiện các IP cố tình truy cập không có Client Certificate).
Giám sát Log App (FastAPI) & OPA: docker logs backend (Kiểm tra log của Python và truy vết mã băm x5t#S256 hoặc lý do OPA deny request để đáp ứng tiêu chí Explainability).
Kiểm tra dung lượng ổ đĩa (Ngăn MySQL Crash): df -h | grep /var/lib/mysql

--------------------------------------------------------------------------------
## 9. Troubleshooting (Lỗi dự kiến & Cách xử lý)
Lỗi 1: Port 443 already in use khi chạy Docker Compose
Nguyên nhân: Dịch vụ Nginx native của Ubuntu Host đang chạy ngầm và chiếm cổng 443 của Docker.
Xử lý: Chạy lần lượt các lệnh:
Lỗi 2: Nginx báo HTTP 400 / 431 Request Header Or Cookie Too Large
Nguyên nhân: Chứng chỉ Client ($ssl_client_escaped_cert) được Nginx đẩy xuống Backend qua Header có kích thước quá lớn, vượt bộ đệm mặc định.
Xử lý: Đã cấu hình thêm large_client_header_buffers 4 32k; trong nginx.conf và set cờ --limit-max-field-size 16384 cho dịch vụ Uvicorn.
Lỗi 3: Redis báo NOAUTH Authentication required hoặc WRONGPASS
Nguyên nhân: Container Backend hoặc quản trị viên gọi vào Redis nhưng cung cấp sai mật khẩu so với cờ --requirepass lúc start.
Xử lý: Kiểm tra lại file .env, đảm bảo biến ${REDIS_PASSWORD} khớp với mật khẩu đang gọi. Có thể soi cấu hình gốc bằng lệnh:
Lỗi 4: Máy ảo đầy 100% Disk do Fuzzing/Test
Nguyên nhân: Sinh quá nhiều image rác và container cache trong lúc build code.
Xử lý: Chạy lệnh sau để dọn rác và thu hồi dung lượng: