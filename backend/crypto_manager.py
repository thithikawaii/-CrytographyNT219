from cryptography.fernet import Fernet
import base64
import os

def generate_dek():
    return Fernet.generate_key()

def wrap_dek(kek, dek):
    f = Fernet(base64.urlsafe_b64encode(kek.encode().ljust(32)[:32]))
    return f.encrypt(dek)

def unwrap_dek(kek, encrypted_dek):
    f = Fernet(base64.urlsafe_b64encode(kek.encode().ljust(32)[:32]))
    return f.decrypt(encrypted_dek)