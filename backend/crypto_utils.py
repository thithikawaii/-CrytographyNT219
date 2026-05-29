import os
import base64
import hashlib
import urllib.parse
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def compute_cc_thumbprint_from_nginx(cert_string: str) -> str:
    """Băm chứng chỉ X.509 sang Base64url SHA-256 (Chuẩn RFC 8705)."""
    if not cert_string:
        return ""
    decode_cert_pem = urllib.parse.unquote(cert_string)
    cert_obj = x509.load_pem_x509_certificate(decode_cert_pem.encode('utf-8'))
    der_cert = cert_obj.public_bytes(serialization.Encoding.DER)
    cert_hash = hashlib.sha256(der_cert).digest()
    return base64.urlsafe_b64encode(cert_hash).decode('utf-8').rstrip('=')


def encrypt_pii(plaintext_str: str, dek_bytes: bytes) -> str:
    aesgcm = AESGCM(dek_bytes)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext_str.encode('utf-8'), None)
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_pii(encrypt_pii_b64: str, dek_bytes: bytes) -> str:
    aesgcm = AESGCM(dek_bytes)
    encrypted_data = base64.b64decode(encrypt_pii_b64)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')


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