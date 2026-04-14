import os
import base64
from dotenv import load_dotenv

load_dotenv()

def get_master_kek() -> bytes:
    """
    Hàm Wrapper lấy Khóa Master (KEK).
    Giai đoạn Tuần 1-3: Đọc từ file .env
    Giai đoạn Tuần 4: Sẽ xóa code đọc .env và thay bằng code gọi API Vault.
    """
    master_kek_str = os.getenv("MASTER_KEK")
    if not master_kek_str:
        raise ValueError("[CRITICAL] Không tìm thấy MASTER_KEK trong môi trường! Hệ thống dừng hoạt động.")

    try:
        master_kek = base64.b64decode(master_kek_str)
    except Exception:
        raise ValueError("[CRITICAL] MASTER_KEK không đúng định dạng Base64!")

    if len(master_kek) != 32:
        raise ValueError(f"[CRITICAL] MASTER_KEK phải dài đúng 32 bytes cho AES-256! HIện là {len(master_kek)} bytes.")

    return master_kek

def get_db_credentials() -> dict:
    """
    Hàm Wrapper lấy thông tin kết nối Cơ sở dữ liệu.
    Giai đoạn Tuần 1-3: Đọc từ file .env
    Giai đoạn Tuần 4: Sẽ thay thế bằng Dynamic Secrets của Vault.
    """
    db_config = {
        "host": os.getenv("DB_HOST"),
        "user": os.getenv("DB_USER"),
        "password": os.getenv("DB_PASS"),
        "name": os.getenv("DB_NAME")
    }

    missing_keys =[k for k, v in db_config.items() if not v]
    if missing_keys:
        raise ValueError(f"[CRITICAL] Thiếu cấu hình Database: {missing_keys}. Hệ thống dừng hoạt động.")

    return db_config
    