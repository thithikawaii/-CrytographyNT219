import os
import logging
import redis
import mysql.connector
import pyotp
import jwt
import datetime
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from config import get_master_kek, get_db_credentials
from crypto_utils import encrypt_pii, decrypt_pii

class Enable2FARequest(BaseModel):
    user_id: int

class Verify2FARequest(BaseModel):
    user_id: int
    otp: str

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI()


def get_db_connection(): # Sử dụng hàm này để tạo kết nối đến MySQL, đảm bảo rằng thông tin kết nối được lấy từ config.py
    db_config = get_db_credentials()
    return mysql.connector.connect(
        host=db_config['host'],
        user=db_config['user'],
        password=db_config['password'],
        database=db_config['name']
    )

class CreateUserRequest(BaseModel):
    username: str
    cccd: str
    phone: str

@app.post("/users")
def create_user(request: CreateUserRequest):
    return {"message": "User created", "user": request.dict()}

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

        uri = pyotp.totp.TOTP(raw_totp_secret).provisioning_uri(
            name=user_data['username'],
            issuer_name="UIT_Security_NT219"
        )

        return {"message": "MFA Setup Initialized", "uri": uri}
        
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

        if not user_data or not user_data.get('totp_secret_encrypted'):
            raise HTTPException(status_code=400, detail="MFA chưa bật!")

        kek_key = get_master_kek()
        dek_bytes = decrypt_dek_with_kek(key_data['encrypted_dek'], kek_key)
        del kek_key

        raw_totp_secret = decrypt_pii(user_data['totp_secret_encrypted'], dek_bytes)
        del dek_bytes

        totp = pyotp.totp.TOTP(raw_totp_secret)
        if totp.verify(request.otp):
            return {"message": "Verify Success! Login hoàn tất.", "status": "SUCCESS"}
        else:
            raise HTTPException(status_code=401, detail="Mã OTP sai hoặc hết hạn!")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if cursor: cursor.close()
        if db: db.close()