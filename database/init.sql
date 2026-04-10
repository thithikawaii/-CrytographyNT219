CREATE DATABASE IF NOT EXISTS mmh_project;
USE mmh_project;

-- 1. Bảng lưu PII (Tài sản A1)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    pii_cccd TEXT NOT NULL,
    pii_phone TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- 2. Bảng lưu Khóa DEK đã được mã hóa bằng KEK (Tài sản A2)
CREATE TABLE IF NOT EXISTS keys_storage (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,          -- Liên kết 1-1 với ID của users
    encrypted_dek TEXT NOT NULL,
    key_version INT DEFAULT 1,            -- Phục vụ cho Tuần 4: Đếm số lần xoay khóa
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- 3. Phân quyền Zero-Trust cho Backend (Node 2)
CREATE USER IF NOT EXISTS 'backend_user'@'100.74.182.127' IDENTIFIED BY 'MatMaHoc2026@';
GRANT SELECT, INSERT, UPDATE ON mmh_project.* TO 'backend_user'@'100.74.182.127';
FLUSH PRIVILEGES;