import os
import logging
import redis
import mysql.connector
import pyotp
import jwt
import datetime
import qrcode
import base64
import uuid 
import requests
import urllib.parse
import hashlib
from io import BytesIO
from fastapi import FastAPI, HTTPException, Request, Header, Depends
from pydantic import BaseModel
from config import get_master_kek, get_db_credentials
from crypto_utils import generate_dek, encrypt_pii, encrypt_dek_with_kek, decrypt_pii, decrypt_dek_with_kek
from crypto_utils import get_x5t_s256
from cryptography import x509
from cryptography.hazmat.primitives import serialization

SECRET_KEY = os.getenv('JWT_SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("CRITICAL: Không tìm thấy JWT_SECRET_KEY trong môi trường!")

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
        dek_bytes = decrypt_dek_with_kek(key_data['encrypted_dek'], kek_key)
        del kek_key  

        raw_totp_secret = decrypt_pii(user_data['totp_secret_encrypted'], dek_bytes)
        del dek_bytes  

        totp = pyotp.totp.TOTP(raw_totp_secret)
        is_valid = totp.verify(req_body.otp)

        if is_valid:
            client_cert = request.headers.get("X-SSL-Client-Cert", "")

            access_token = create_access_token(str(req_body.user_id), client_cert)

            return {
                "message": "Verify Success! Login hoàn tất.", 
                "status": "SUCCESS",
                "access_token": access_token
            }
        else:
            logger.info(f"SERVER_NOW: {totp.now()} | CLIENT_SEND: {req_body.otp}")
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

async def verify_token_binding(
        authorization: str = Header(None),
        x_client_cert: str = Header(None, alias="X-SSL-Client-Cert")
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Thiếu hoặc sai định dạng Token")
    if not x_client_cert:
        raise HTTPException(status_code=403, detail="Yêu cầu phải có Client Certificate (mTLS)")
    
    try:
        token = authorization.split(" ")[1]

        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

        jti = payload.get("jti")
        if not jti:
            raise HTTPException(status_code=401, detail="Token không hợp lệ (Thiếu JTI)")
        
        try: 
            r = redis.Redis(
                host='redis_blacklist',
                port=6379,
                password=os.getenv('REDIS_PASSWORD'),
                decode_responses=True
            )
            if r.get(jti):
                raise HTTPException(status_code=401, detail="Token đã bị thu hồi (Blacklisted)!")
        except redis.RedisError as re:
            logger.error(f"Redis Connection Error: {re}")
            raise HTTPException(status_code=500, detail="Lỗi kết nối máy chủ xác thực Redis") 

        token_cnf = payload.get("cnf", {}).get("x5t#S256")
        if not token_cnf:
            raise HTTPException(status_code=403, detail="Token không hỗ trợ Proof-of-Possession")
        
        current_cert_thumbprint = get_x5t_s256(x_client_cert)

        if token_cnf != current_cert_thumbprint:
            raise HTTPException(
                status_code=403,
                detail="PoP Mismatch! Token không thuộc về chứng chỉ này."
            )
        
        return payload
    
    except HTTPException:
        raise
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token đã hết hạn!")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Chữ ký Token không hợp lệ!")
    except Exception as e:
        logger.error(f"Middleware Exception: {str(e)}")
        raise HTTPException(status_code=403, detail="Truy cập bị từ chối do lỗi xác thực hệ thống!")

@app.get("/api/v1/users/{user_id}/pii")
def get_user(user_id: int, token_payload: dict = Depends(verify_token_binding)):
    token_user_id = token_payload.get("sub")

    opa_url = "http://opa:8181/v1/data/authz/allow" 
    input_data = {
        "input": {
            "token_user_id": str(token_user_id),
            "requested_user_id": str(user_id),
            "method": "GET"
        }
    }

    try:
        resp = requests.post(opa_url, json=input_data, timeout=2)
        resp.raise_for_status()

        opa_payload = resp.json()
        opa_result = opa_payload.get("result", opa_payload)

        allow = False
        reason = "access denied by policy"
        if isinstance(opa_result, bool):
            allow = opa_result
        elif isinstance(opa_result, dict):
            allow = bool(opa_result.get("allow"))
            reason = opa_result.get("reason", reason)
        else:
            logger.error("OPA returned unsupported payload: %s", opa_result)
            raise HTTPException(status_code=403, detail="Authorization check failed")

        if not allow:
            logger.warning("OPA deny for token_user_id=%s requested_user_id=%s reason=%s", token_user_id, user_id, reason)
            raise HTTPException(status_code=403, detail=reason)
    except requests.RequestException as re:
        logger.error("OPA connection error: %s", re)
        raise HTTPException(status_code=403, detail="Authorization service unavailable")
    except ValueError as ve:
        logger.error("OPA JSON parse error: %s", ve)
        raise HTTPException(status_code=403, detail="Authorization check failed")

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
    except HTTPException:
        raise

    except ValueError as ve:
        if "MAC check failed" in str(ve):
            logger.critical(f"[CRITICAL] MAC check failed - Dữ liệu PII của User {user_id} đã bị can thiệp trái phép!")
            raise HTTPException(status_code=500, detail="System Integrity Failure")
        
        logger.error(f"[ERROR] ValueError tại get_user: {str(ve)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
        
    except Exception as e:
        logger.error(f"[ERROR] Lỗi hệ thống tại get_user: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
        
    finally:
        if cursor: cursor.close()
        if db: db.close()

def create_access_token(user_id: str, client_cert: str):
    thumbprint = get_x5t_s256(client_cert)

    expire_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

    jti = str(uuid.uuid4())

    payload = {
        "sub": user_id,
        "exp": expire_time,
        "jti": jti,
        "cnf": {
            "x5t#S256": thumbprint
        }
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def compute_cc_thumbprint_from_nginx(cert_string: str) -> str:
    decode_cert_pem = urllib.parse.unquote(cert_string)
    cert_obj = x509.load_pem_x509_certificate(decode_cert_pem.encode('utf-8'))
    der_cert = cert_obj.public_bytes(serialization.Encoding.DER)
    cert_hash = hashlib.sha256(der_cert).digest()

    thumbprint = base64.urlsafe_b64encode(cert_hash).decode('utf-8').rstrip('=')
    return thumbprint

@app.get("/api/v1/test-cert")
async def test_receive_cert(request: Request):
    client_cert_header = request.headers.get("X-SSL-Client-Cert")

    if not client_cert_header:
        return {"status": "Thất bại", "message": "Nginx không gửi chứng chỉ qua Header!"}

    thumbprint = compute_cc_thumbprint_from_nginx(client_cert_header)
    
    print("========== BÁO CÁO NGÀY 1 ==========")
    print(f"Mã băm chứng chỉ (Thumbprint): {thumbprint}")
    print("====================================")

    del client_cert_header, thumbprint

    return {"status": "Thành công", "message": "Đã nhận, băm chứng chỉ và xóa dấu vết trong RAM!"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)