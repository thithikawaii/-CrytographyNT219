from vault_client import get_master_kek
from crypto_manager import generate_dek, wrap_dek, unwrap_dek 

kek = get_master_kek()
print("KEK lấy từ Vault: [THÀNH CÔNG - ĐÃ GIẤU KÍN ĐỂ BẢO MẬT]")

dek = generate_dek()
print(f"DEK mới tạo (HEX): {dek.hex()[:10]}... [ĐÃ CẮT BỚT]")

wrapped_dek = wrap_dek(kek, dek)
print(f"DEK sau khi bọc: {wrapped_dek.hex()[:10]}...")

original_dek = unwrap_dek(kek, wrapped_dek)
if dek == original_dek:
    print("Giải mã DEK khớp 100%! Envelope Encryption hoàn hảo.")