# data.py (refactored to use simulated ABE with RSA + AES)

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import json
import os

BLOCK_SIZE = 16
KEY_DIR = "keys"
RECORD_FILE = "records.txt"
AUTHORIZED_ROLES = ["Doctor", "Admin"]

os.makedirs(KEY_DIR, exist_ok=True)

def pad(data):
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + chr(pad_len) * pad_len

def unpad(data):
    return data[:-ord(data[-1])]

def encrypt_data(data, username):
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Random import get_random_bytes
    import datetime
    import base64
    import os, json

    aes_key = get_random_bytes(16)
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    encrypted_data = cipher.encrypt(pad(data).encode())

    encrypted_keys = {}
    for role in AUTHORIZED_ROLES:
        pub_path = os.path.join(KEY_DIR, f"{role}_public.pem")
        if os.path.exists(pub_path):
            with open(pub_path, "rb") as f:
                pub_key = RSA.import_key(f.read())
                rsa_cipher = PKCS1_OAEP.new(pub_key)
                encrypted_key = rsa_cipher.encrypt(aes_key)
                encrypted_keys[role] = base64.b64encode(encrypted_key).decode()

    record = {
        "user": username,
        "timestamp": str(datetime.datetime.now()),
        "iv": base64.b64encode(iv).decode(),
        "data": base64.b64encode(encrypted_data).decode(),
        "keys": encrypted_keys
    }

    with open(RECORD_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")

    return True, "Record encrypted and saved."


def decrypt_data(role):
    priv_path = os.path.join(KEY_DIR, f"{role}_private.pem")
    if not os.path.exists(priv_path):
        return False, "Private key not found for this role."

    with open(priv_path, "rb") as f:
        priv_key = RSA.import_key(f.read())

    try:
        with open(RECORD_FILE, "r") as f:
            records = [json.loads(line.strip()) for line in f if line.strip()]
    except:
        return False, "No records found."

    results = []
    for record in records:
        encrypted_key_b64 = record["keys"].get(role)
        if not encrypted_key_b64:
            results.append((record["user"], False, "Not authorized to decrypt this record."))
            continue

        try:
            encrypted_key = base64.b64decode(encrypted_key_b64)
            rsa_cipher = PKCS1_OAEP.new(priv_key)
            aes_key = rsa_cipher.decrypt(encrypted_key)

            iv = base64.b64decode(record["iv"])
            encrypted_data = base64.b64decode(record["data"])
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted_data).decode())

            results.append((record["user"], record.get("timestamp", "N/A"), True, decrypted))
        except Exception as e:
            results.append((record["user"], False, f"Decryption error: {str(e)}"))

    return True, results

