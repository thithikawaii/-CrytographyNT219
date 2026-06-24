import os
import logging
import mysql.connector
import pyotp
import jwt
import datetime
import qrcode
import base64
import uuid 
from io import BytesIO
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from vault_client import get_master_kek
from config import get_db_credentials
from crypto_utils import (
    compute_cc_thumbprint_from_nginx, 
    generate_dek, wrap_dek, unwrap_dek,
    encrypt_pii, decrypt_pii
)

SECRET_KEY = os.getenv('JWT_SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("CRITICAL: Không tìm thấy JWT_SECRET_KEY trong môi trường!")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Identity Provider (Layer 2)")

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

def create_access_token(user_id: str, client_cert: str, role: str = "user"):
    thumbprint = compute_cc_thumbprint_from_nginx(client_cert)
    expire_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    jti = str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "exp": expire_time,
        "jti": jti,
        "role": role,
        "cnf": {
            "x5t#S256": thumbprint
        }
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

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
        enc_dek = wrap_dek(kek_key, dek) 
        del kek_key
        del dek 

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

@app.post("/api/v1/enable-2fa") 
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
        dek_bytes = unwrap_dek(kek_key, key_data['encrypted_dek'])
        del kek_key

        enc_totp_secret = encrypt_pii(raw_totp_secret, dek_bytes)
        del dek_bytes

        cursor.execute("UPDATE users SET totp_secret_encrypted = %s WHERE id = %s", (enc_totp_secret, request.user_id))
        db.commit()

        provisioning_uri = pyotp.totp.TOTP(raw_totp_secret).provisioning_uri(
            name=user_data['username'],
            issuer_name="CrytographyNT219_IdP"
        )

        qr = qrcode.make(provisioning_uri)
        buf = BytesIO()
        qr.save(buf, format="PNG")
        qr_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

        return {
            "message": "MFA Setup Initialized",
            "qr_code_base64": f"data:image/png;base64,{qr_base64}"
        }
    except Exception as e:
        if db: db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if cursor: cursor.close()
        if db: db.close()

@app.post("/api/v1/verify-2fa")
def verify_2fa(req_body: Verify2FARequest, request: Request):
    db = None
    cursor = None
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE id = %s", (req_body.user_id,))
        user_data = cursor.fetchone()
        cursor.execute("SELECT * FROM keys_storage WHERE user_id = %s", (req_body.user_id,))
        key_data = cursor.fetchone()

        if not user_data or not user_data.get('totp_secret_encrypted') or not key_data:
            raise HTTPException(status_code=400, detail="MFA chưa bật hoặc không tìm thấy khóa!")

        kek_key = get_master_kek()
        dek_bytes = unwrap_dek(kek_key, key_data['encrypted_dek'])
        del kek_key

        raw_totp_secret = decrypt_pii(user_data['totp_secret_encrypted'], dek_bytes)
        del dek_bytes  

        totp = pyotp.totp.TOTP(raw_totp_secret)
        is_valid = totp.verify(req_body.otp)

        if is_valid:
            client_cert = request.headers.get("X-SSL-Client-Cert", "")
            access_token = create_access_token(str(req_body.user_id), client_cert, user_data.get("role", "user"))

            return {
                "message": "Xác thực thành công", 
                "access_token": access_token
            }
        else:
            raise HTTPException(status_code=401, detail="Mã OTP sai hoặc hết hạn!")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if cursor: cursor.close()
        if db: db.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
