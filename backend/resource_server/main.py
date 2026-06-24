import os
import logging
import mysql.connector
import jwt
import requests
from fastapi import FastAPI, HTTPException, Request, Header, Depends
from vault_client import get_master_kek
from config import get_db_credentials
from crypto_utils import (
    compute_cc_thumbprint_from_nginx, 
    unwrap_dek,
    decrypt_pii
)
from redis_blacklist import is_token_blacklisted, blacklist_token

SECRET_KEY = os.getenv('JWT_SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("CRITICAL: Không tìm thấy JWT_SECRET_KEY trong môi trường!")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Resource Server (Layer 3)")

def get_db_connection():
    db_config = get_db_credentials()
    return mysql.connector.connect(
        host=db_config['host'],
        user=db_config['user'],
        password=db_config['password'],
        database=db_config['name']
    )

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
        # Resource Server chỉ giải mã (verify), không cần quyền ký mới
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

        jti = payload.get("jti")
        if not jti or is_token_blacklisted(jti):
            raise HTTPException(status_code=401, detail="Token không hợp lệ hoặc đã bị thu hồi!")

        token_cnf = payload.get("cnf", {}).get("x5t#S256")
        if not token_cnf:
            raise HTTPException(status_code=403, detail="Token không hỗ trợ Proof-of-Possession")
        
        current_cert_thumbprint = compute_cc_thumbprint_from_nginx(x_client_cert)

        if token_cnf != current_cert_thumbprint:
            raise HTTPException(
                status_code=403,
                detail="PoP Mismatch! Token không thuộc về chứng chỉ này."
            )
        return payload
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token đã hết hạn!")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Chữ ký Token không hợp lệ!")
    except Exception as e:
        logger.error(f"Middleware Exception: {str(e)}")
        raise HTTPException(status_code=403, detail="Truy cập bị từ chối!")

@app.get("/api/v1/users/{user_id}/pii")
def get_user_pii(user_id: int, token_payload: dict = Depends(verify_token_binding)):
    token_user_id = token_payload.get("sub")

    # 1. Gọi OPA để kiểm tra BOLA (ABAC Ownership Check)
    opa_url = "http://opa:8181/v1/data/authz/decision" 
    input_data = {
        "input": {
            "user_id": str(token_user_id),
            "owner_id": str(user_id),
            "method": "GET",
            "path": f"/api/v1/users/{user_id}/pii",
            "role": token_payload.get("role", "user")
        }
    }

    try:
        resp = requests.post(opa_url, json=input_data, timeout=1.0)
        opa_result = resp.json().get("result", {})
        
        allow = opa_result.get("allow", False)
        reason = opa_result.get("reason", "Denied by Policy")

        if not allow:
            logger.warning(f"OPA Deny: {reason}")
            raise HTTPException(status_code=403, detail=reason)
            
    except Exception as e:
        logger.error(f"OPA Error: {str(e)}")
        raise HTTPException(status_code=403, detail="Authorization service unavailable")

    # 2. Truy xuất và giải mã dữ liệu
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
        dek_bytes = unwrap_dek(kek_key, key_data['encrypted_dek'])
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
    finally:
        if cursor: cursor.close()
        if db: db.close()

@app.post("/api/v1/logout")
async def logout(token_payload: dict = Depends(verify_token_binding)):
    jti = token_payload.get("jti")
    exp = token_payload.get("exp")
    blacklist_token(jti, exp)
    return {"message": "Đăng xuất thành công, token đã bị thu hồi!"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
