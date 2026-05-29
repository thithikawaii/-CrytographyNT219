import hvac
import os

def get_master_kek():
    client = hvac.Client(url='http://vault:8200', token=os.getenv('VAULT_TOKEN'))

    read_response = client.secrets.kv.v2.read_secret_version(path='master-key')
    kek = read_response['data']['data']['kek']

    return kek