import hvac
import os
import base64

def get_master_kek() -> bytes:
    client = hvac.Client(url='http://vault:8200', token=os.getenv('VAULT_TOKEN'))
    read_response = client.secrets.kv.v2.read_secret_version(path='master-key')
    kek_base64 = read_response['data']['data']['kek']
    
    return base64.b64decode(kek_base64)