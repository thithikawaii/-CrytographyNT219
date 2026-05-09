import os
import logging
import redis
import mysql.connector
import pyotp
import jwt
import datetime
import qrcode
import base64
from io import BytesIO
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from config import get_master_kek, get_db_credentials
from crypto_utils import generate_dek, encrypt_pii, encrypt_dek_with_kek, decrypt_pii, decrypt_dek_with_kek

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI()

class CreateUserRequest(BaseModel):
    username: str
    cccd: str
    phone: str

class Enable2FARequest(BaseModel):
    user_id: int

class Verify2FARequest(BaseModel):
    user_id: int
    otp: str

def get_db_connection():
    db_config = get_db_credentials()
    return mysql.connector.connect(
        host=db_config['host'],
        user=db_config['user'],
        password=db_config['password'],
        database=db_config['name']
    )


@app.post("/users")
def create_user(request: CreateUserRequest):
    db = None
    cursor = None
    try:
        db = get_db_connection()
        cursor = db.cursor()
        
        kek_key = get_master_kek()
        dek = generate_dek()
        enc_cccd = encrypt_pii(request.cccd, dek)
        enc_phone = encrypt_pii(request.phone, dek)
        enc_dek = encrypt_dek_with_kek(dek, kek_key) 
        del kek_key

        sql_user = "INSERT INTO users (username, pii_cccd_encrypted, pii_phone_encrypted) VALUES (%s, %s, %s)"
        cursor.execute(sql_user, (request.username, enc_cccd, enc_phone))
        new_user_id = cursor.lastrowid

        sql_key = "INSERT INTO keys_storage (user_id, encrypted_dek) VALUES (%s, %s)"
        cursor.execute(sql_key, (new_user_id, enc_dek))

        db.commit()
        return {"message": "Tạo user thành công", "user_id": new_user_id}
    except Exception as e:
        if db: db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if cursor: cursor.close()
        if db and db.is_connected(): db.close()


@app.post("/login")
def test_infrastructure_connection():
    connection_status = {"mysql": "pending", "redis": "pending"}

    try:
        conn = mysql.connector.connect(
            host='mysql_db',
            port=3306,
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASS'),
            database=os.getenv('DB_NAME')
        )
        conn.close()
        connection_status["mysql"] = "SUCCESS"
        logger.info("Database connection established successfully.")
    except Exception as e:
        logger.error("CRITICAL: Failed to connect to MySQL Database.")
        raise HTTPException(status_code=500, detail="DB Connection Failed")

    try:
        r = redis.Redis(
            host='redis_blacklist',
            port=6379,
            password=os.getenv('REDIS_PASSWORD'),
            decode_responses=True
        )
        r.ping()
        connection_status["redis"] = "SUCCESS"
        logger.info("Redis connection established successfully.")
    except Exception as e:
        logger.error("CRITICAL: Failed to connect to Redis Cache.")
        raise HTTPException(status_code=500, detail="Redis Connection Failed")

    return {"message": "Nghiệm thu ngày 1 thành công!", "status": connection_status}

@app.post("/enable-2fa")
def enable_2fa(request: Enable2FARequest):
    db = None
    cursor = None
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE id = %s", (request.user_id,))
        user_data = cursor.fetchone()
        cursor.execute("SELECT * FROM keys_storage WHERE user_id = %s", (request.user_id,))
        key_data = cursor.fetchone()

        if not user_data or not key_data:
            raise HTTPException(status_code=404, detail="User not found")

        raw_totp_secret = pyotp.random_base32()
        
        kek_key = get_master_kek()
        dek_bytes = decrypt_dek_with_kek(key_data['encrypted_dek'], kek_key)
        del kek_key

        enc_totp_secret = encrypt_pii(raw_totp_secret, dek_bytes)
        del dek_bytes

        cursor.execute("UPDATE users SET totp_secret_encrypted = %s WHERE id = %s", (enc_totp_secret, request.user_id))
        db.commit()

        provisioning_uri = pyotp.totp.TOTP(raw_totp_secret).provisioning_uri(
            name=user_data['username'],
            issuer_name="UIT_Security_NT219"
        )

        qr = qrcode.make(provisioning_uri)
        buf = BytesIO()
        qr.save(buf, format="PNG")
        qr_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

        return {
            "message": "MFA Setup Initialized",
            "uri": provisioning_uri,
            "qr_code_base64": f"data:image/png;base64,{qr_base64}"
        }
    except Exception as e:
        if db: db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if cursor: cursor.close()
        if db: db.close()

@app.post("/verify-2fa")
def verify_2fa(request: Verify2FARequest):
    db = None
    cursor = None
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE id = %s", (request.user_id,))
        user_data = cursor.fetchone()
        cursor.execute("SELECT * FROM keys_storage WHERE user_id = %s", (request.user_id,))
        key_data = cursor.fetchone()

        if not user_data or not user_data.get('totp_secret_encrypted') or not key_data:
            raise HTTPException(status_code=400, detail="MFA chưa bật hoặc không tìm thấy khóa!")

        kek_key = get_master_kek()
        dek_bytes = decrypt_dek_with_kek(key_data['encrypted_dek'], kek_key)
        del kek_key  

        raw_totp_secret = decrypt_pii(user_data['totp_secret_encrypted'], dek_bytes)
        del dek_bytes  

        totp = pyotp.totp.TOTP(raw_totp_secret)
        is_valid = totp.verify(request.otp)

        if is_valid:
            return {"message": "Verify Success! Login hoàn tất.", "status": "SUCCESS"}
        else:
            logger.info(f"SERVER_NOW: {totp.now()} | CLIENT_SEND: {request.otp}")
            raise HTTPException(status_code=401, detail="Mã OTP sai hoặc hết hạn!")
            
    except ValueError as ve:
        if "MAC check failed" in str(ve):
            logger.critical("[CRITICAL] MAC check failed - Dữ liệu bị can thiệp!")
            raise HTTPException(status_code=500, detail="System Integrity Failure")
        raise HTTPException(status_code=500, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if cursor: cursor.close()
        if db: db.close()

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
            raise HTTPException(status_code=404, detail="User not found")

        kek_key = get_master_kek()
        dek_bytes = decrypt_dek_with_kek(key_data['encrypted_dek'], kek_key)
        del kek_key

        plain_cccd = decrypt_pii(user_data['pii_cccd_encrypted'], dek_bytes)
        plain_phone = decrypt_pii(user_data['pii_phone_encrypted'], dek_bytes)
        del dek_bytes
        
        return {
            "id": user_data['id'],
            "username": user_data['username'],
            "cccd": plain_cccd,
            "phone": plain_phone
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="System Integrity Failure")
    finally:
        if cursor: cursor.close()
        if db: db.close()