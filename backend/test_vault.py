from vault_client import get_master_kek

try:
    kek = get_master_kek()
    if kek:
        print("Vault kết nối thành công! Khóa KEK đã được truy xuất (Không in ra để bảo mật).")
except Exception as e:
    print(f"Lỗi kết nối Vault: {e}")