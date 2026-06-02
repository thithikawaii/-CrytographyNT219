import redis
import os
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "redis_blacklist"),
    port=6379,
    password=os.getenv("REDIS_PASSWORD"),
    decode_responses=True
)

def blacklist_token(jti: str, exp_timestamp: int):
    now = datetime.now(timezone.utc).timestamp()
    ttl = int(exp_timestamp - now)

    if ttl <= 0:
        return

    key = f"blacklist:{jti}"

    try:
        redis_client.setex(key, ttl, "revoked")
        logger.info("Token %s đã bị vô hiệu hóa trong %s giây.", jti, ttl)
    except Exception as e:
        logger.error("Redis error khi blacklist token: %s", str(e))


def is_token_blacklisted(jti: str) -> bool:
    key = f"blacklist:{jti}"

    try:
        return redis_client.exists(key) == 1
    except Exception as e:
        logger.error("Redis error khi check blacklist: %s", str(e))
        return False