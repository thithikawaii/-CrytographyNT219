from vault_client import get_master_kek
from crypto_manager import generate_dek, wrap_dek, unwrap_dek

kek = get_master_kek()
print(f"KEK lấy từ Vault: {kek}")

dek = generate_dek()
print(f"DEK mới tạo: {dek}")

wrapped_dek = wrap_dek(kek, dek)
print(f"DEK sau khi bọc: {wrapped_dek}")

original_dek = unwrap_dek(kek, wrapped_dek)
print(f"DEK sau khi mở bọc: {original_dek}")