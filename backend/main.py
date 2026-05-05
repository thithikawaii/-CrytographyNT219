import os
import logging
import redis
import mysql.connector
from fastapi import FastAPI, HTTPException

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI()

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
