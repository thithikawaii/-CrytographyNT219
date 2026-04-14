import os
import logging
import mysql.connector
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from crypto_utils import generate_dek, encrypt_pii, encrypt_dek_with_kek, decrypt_pii, decrypt_dek_with_kek

from config import get_master_kek, get_db_credentials

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

class UserCreate(BaseModel):
    username: str 
    cccd: str 
    phone: str

def get_db_connection():
    db_info = get_db_credentials()
    return mysql.connector.connect(
        host=db_info['host'],
        user=db_info['user'],
        password=db_info['password'],
        database=db_info['name']
    )

@app.post("/users")
def create_user(user: UserCreate):
    db = None
    cursor = None
    try:
        db = get_db_connection()
        cursor = db.cursor()
        
        kek_key = get_master_kek()
        
        dek = generate_dek()
        enc_cccd = encrypt_pii(user.cccd, dek)
        enc_phone = encrypt_pii(user.phone, dek)
        enc_dek = encrypt_dek_with_kek(dek, kek_key) 

        del kek_key

        sql_user = "INSERT INTO users (username, pii_cccd, pii_phone) VALUES (%s, %s, %s)"
        cursor.execute(sql_user, (user.username, enc_cccd, enc_phone))
        new_user_id = cursor.lastrowid

        sql_key = "INSERT INTO keys_storage (user_id, encrypted_dek) VALUES (%s, %s)"
        cursor.execute(sql_key, (new_user_id, enc_dek))

        db.commit()
        return {"message": "Tạo user thành công", "user_id": new_user_id}

    except Exception as e:
        if db:
            db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()

@app.get("/api/v1/users/{user_id}/pii") 
def get_user(user_id: int):
    db = None
    cursor = None
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        cursor.execute("SELECT * FROM keys_storage WHERE user_id = %s", (user_id,))
        key_data = cursor.fetchone()

        if not user_data or not key_data:
            raise HTTPException(status_code=404, detail="Not found")

        kek_key = get_master_kek()
        dek_bytes = decrypt_dek_with_kek(key_data['encrypted_dek'], kek_key)
        
        del kek_key

        plain_cccd = decrypt_pii(user_data['pii_cccd'], dek_bytes)
        plain_phone = decrypt_pii(user_data['pii_phone'], dek_bytes)

        del dek_bytes

        return {
            "id": user_data['id'],
            "username": user_data['username'],
            "cccd": plain_cccd,
            "phone": plain_phone
        }

    except ValueError as ve:
        if "MAC check failed" in str(ve):
            logger.critical("[CRITICAL] MAC check failed - Dữ liệu bị can thiệp!")
            raise HTTPException(status_code=500, detail="System Integrity Failure")
        raise HTTPException(status_code=500, detail="Lỗi dữ liệu hệ thống")
    except Exception as e:
        raise HTTPException(status_code=500, detail="System Integrity Failure") 
    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()
            