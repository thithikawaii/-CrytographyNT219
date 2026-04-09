from fastapi import FastAPI
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

@app.get("/")
def home():
    kek = os.getenv("MASTER_KEK")
    return {
        "status": "Online",
        "author": "Dong Nguyen",
        "message": "Da ket noi thanh cong va san sang code AES-GCM!",
        "key_status": "Da nhan KEK" if kek else "Chua thay KEK"
    }
