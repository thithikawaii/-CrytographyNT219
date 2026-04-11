import os
import mysql.connector
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

from crypto_utils import generate_dek, encrypt_pii, encrypt_dek_with_kek, decrypt_pii, decrypt_dek_with_kek

load_dotenv()
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_NAME = os.getenv("DB_NAME")

app = FastAPI()

class UserCreate(BaseModel):
    username: str 
    cccd: str 
    phone: str

def get_db_connection():
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME
    )

@app.post("/users")
def create_user(user: UserCreate):
    db = get_db_connection()
    cursor = db.cursor()
    try:
        dek = generate_dek()
        enc_cccd = encrypt_pii(user.cccd, dek)
        enc_phone = encrypt_pii(user.phone, dek)
        enc_dek = encrypt_dek_with_kek(dek)

        sql_user = "INSERT INTO users (username, pii_cccd, pii_phone) VALUES (%s, %s, %s)"
        cursor.execute(sql_user, (user.username, enc_cccd, enc_phone))

        new_user_id = cursor.lastrowid

        sql_key = "INSERT INTO keys_storage (user_id, encrypted_dek) VALUES (%s, %s)"
        cursor.execute(sql_key, (new_user_id, enc_dek))

        db.commit()
        return {"message": "Tạo user thành công", "user_id": new_user_id}

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        db.close()

@app.get("/users/{user_id}")
def get_user(user_id: int):
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()

        cursor.execute("SELECT * FROM keys_storage WHERE user_id = %s", (user_id,))
        key_data = cursor.fetchone()

        if not user_data or not key_data:
            raise HTTPException(status_code=404, detail="Not found")

        dek_bytes = decrypt_dek_with_kek(key_data['encrypted_dek'])

        plain_cccd = decrypt_pii(user_data['pii_cccd'], dek_bytes)
        plain_phone = decrypt_pii(user_data['pii_phone'], dek_bytes)

        return {
            "id": user_data['id'],
            "username": user_data['username'],
            "cccd": plain_cccd,
            "phone": plain_phone
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi: {str(e)}")
    finally:
        cursor.close()
        db.close()
