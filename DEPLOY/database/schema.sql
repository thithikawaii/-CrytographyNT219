CREATE DATABASE IF NOT EXISTS company_db;
USE company_db;

-- Bảng Users: Lưu trữ thông tin định danh và PII đã mã hóa
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    
    -- Dùng TEXT vì bản mã sau khi Base64 sẽ dài hơn bản rõ ban đầu
    pii_cccd_encrypted TEXT NOT NULL,
    pii_phone_encrypted TEXT NOT NULL,
    
    -- Secret cho MFA (Tuần 2), mặc định NULL cho đến khi User kích hoạt
    totp_secret_encrypted TEXT DEFAULT NULL,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin; 
-- Dùng COLLATE utf8mb4_bin để so khớp chính xác từng bit của bản mã

-- Bảng Keys: Lưu trữ khóa phiên (DEK) theo mô hình Envelope Encryption
CREATE TABLE IF NOT EXISTS keys_storage (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    
    encrypted_dek TEXT NOT NULL, -- DEK đã bọc bởi KEK
    key_version INT DEFAULT 1,   -- Version để phục vụ xoay khóa (Tuần 4)
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT uq_user_id UNIQUE (user_id),
    CONSTRAINT fk_user_keys 
        FOREIGN KEY (user_id) 
        REFERENCES users(id) 
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;