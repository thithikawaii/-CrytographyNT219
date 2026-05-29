import hvac
import os
import base64

def get_master_kek() -> bytes:
    vault_token = os.getenv('VAULT_TOKEN')
    if not vault_token:
        raise ValueError("[CRITICAL] Không tìm thấy VAULT_TOKEN trong môi trường!")
    
    client = hvac.Client(url='http://vault:8200', token=vault_token)
    read_response = client.secrets.kv.v2.read_secret_version(path='master-key')
    kek_base64 = read_response['data']['data']['kek']

    if "VAULT_TOKEN" in os.environ:
        del os.environ["VAULT_TOKEN"]

    return base64.b64decode(kek_base64)