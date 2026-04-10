import os
import base64
from dotenv import load_dotenv
from Crypto.Cipher import AES

load_dotenv()
MASTER_KEK_STR = os.getenv("MASTER_KEK")
if not MASTER_KEK_STR or len(MASTER_KEK_STR) != 32:
    raise ValueError("MASTER_KEK phải dài đúng 32 bytes trong file .env!")

MASTER_KEK = MASTER_KEK_STR.encode('utf-8')

def generate_dek() -> bytes:
    """Sinh ngẫu nhiên khóa DEK 32 bytes"""
    return os.urandom(32)

def encrypt_aes_gcm(data_bytes: bytes, key: bytes) -> str:
    """Hàm lõi: Đóng gói Nonce (12B) + Ciphertext + Tag (16B) -> Base64"""
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)

    packet = nonce + ciphertext + tag
    return base64.b64encode(packet).decode('utf-8')

def decrypt_aes_gcm(b64_string: str, key: bytes) -> bytes:
    """Hàm lõi: Giải mac và kiểm tra tính toàn vẹn (E-C3)"""
    raw_data = base64.b64decode(b64_string)

    nonce = raw_data[:12]
    tag = raw_data[-16:]
    ciphertext = raw_data[12:-16]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def encrypt_dek_with_kek(dek_bytes: bytes) -> str:
    return encrypt_aes_gcm(dek_bytes, MASTER_KEK)

def decrypt_dek_with_kek(encrypted_dek_b64: str) -> bytes:
    return decrypt_aes_gcm(encrypted_dek_b64, MASTER_KEK)

def encrypt_pii(plaintext_str: str, dek_bytes: bytes) -> str:
    return encrypt_aes_gcm(plaintext_str.encode('utf-8'), dek_bytes)

def decrypt_pii(encrypt_pii_b64: str, dek_bytes: bytes) -> str:
    return decrypt_aes_gcm(encrypt_pii_b64, dek_bytes).decode('utf-8')
