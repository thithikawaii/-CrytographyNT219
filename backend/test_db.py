import mysql.connector
from crypto_utils import generate_dek, encrypt_pii, encrypt_dek_with_kek

print("=== BẮT ĐẦU TEST KẾT NỐI DATABASE ===")

try: 
    db = mysql.connector.connect(
        host="100.78.117.121",
        user="backend_user",
        password="MatMaHoc2026@",
        database="mmh_project"
    )
    cursor = db.cursor()
    print("Bước 1: Kết nối Database của Quyên thành công!")

    username = "dong_nguyen_cute"
    cccd_plain = "079099123456"
    phone_plain = "0901234567"

    print("Bước 2: Đang mã hóa dữ liệu theo chuẩn...")
    dek = generate_dek()

    enc_cccd = encrypt_pii(cccd_plain, dek)
    enc_phone = encrypt_pii(phone_plain, dek)
    enc_dek = encrypt_dek_with_kek(dek)

    sql_user = "INSERT INTO users (username, pii_cccd, pii_phone) VALUES (%s, %s, %s)"
    cursor.execute(sql_user, (username, enc_cccd, enc_phone))

    new_user_id = cursor.lastrowid
    print(f"Bước 3: Đã tạo User thành công với ID: {new_user_id}")

    sql_key = "INSERT INTO keys_storage (user_id, encrypted_dek) VALUES (%s, %s)"
    cursor.execute(sql_key, (new_user_id, enc_dek))
    print(f"Bước 4: Đã cất khóa DEK an toàn cho User Ì: {new_user_id}")

    db.commit()
    print("HOÀN TẤT: Dự liệu đã nằm gọn trong Database của Quyên!")

except mysql.connector.Error as err:
    print(f"Lỗi Database: {err}")
finally:
    if 'db' in locals() and db.is_connected():
            cursor.close()
            db.close()
            print("Đã đóng kết nối Database.")
