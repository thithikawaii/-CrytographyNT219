import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_dek() -> bytes:
    """Sinh ngẫu nhiên khóa DEK 256-bit (32 bytes) an toàn"""
    return AESGCM.generate_key(bit_length=256)

def wrap_dek(kek: bytes, dek: bytes) -> bytes:
    """Bọc DEK bằng KEK sử dụng thuật toán AES-GCM (AEAD)"""
    aesgcm = AESGCM(kek)
    nonce = os.urandom(12)
    
    encrypted_dek = aesgcm.encrypt(nonce, dek, None)
    return nonce + encrypted_dek

def unwrap_dek(kek: bytes, wrapped_dek: bytes) -> bytes:
    """Mở bọc DEK bằng KEK sử dụng thuật toán AES-GCM (AEAD)"""
    aesgcm = AESGCM(kek)
    
    nonce = wrapped_dek[:12]
    encrypted_dek = wrapped_dek[12:]
    
    return aesgcm.decrypt(nonce, encrypted_dek, None)