from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json
from glycon.config import CONFIG

class SecureComms:
    @staticmethod
    def encrypt(data):
        cipher = AES.new(CONFIG.aes_key, AES.MODE_CBC, CONFIG.aes_iv)
        padded_data = pad(json.dumps(data).encode(), AES.block_size)
        ct_bytes = cipher.encrypt(padded_data)
        return base64.b64encode(ct_bytes)

    @staticmethod
    def decrypt(enc_data):
        cipher = AES.new(CONFIG.aes_key, AES.MODE_CBC, CONFIG.aes_iv)
        ct = base64.b64decode(enc_data)
        pt = cipher.decrypt(ct)
        return json.loads(unpad(pt, AES.block_size))