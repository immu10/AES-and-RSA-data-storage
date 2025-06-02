# data.py (refactored to use simulated ABE with RSA + AES)

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import json
import datetime
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

from time import perf_counter  # for eval

from time import perf_counter  # for eval

def encrypt_data(data, username, debug=False):  # for eval
    start_total = perf_counter()  # for eval

    aes_key = get_random_bytes(16)
    iv = get_random_bytes(16)

    # AES encryption
    start_aes_enc = perf_counter()  # for eval
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data).encode())
    aes_enc_time = perf_counter() - start_aes_enc  # for eval

    encrypted_keys = {}
    rsa_enc_times = []  # for eval
    for role in AUTHORIZED_ROLES:
        pub_path = os.path.join(KEY_DIR, f"{role}_public.pem")
        if os.path.exists(pub_path):
            with open(pub_path, "rb") as f:
                pub_key = RSA.import_key(f.read())
                rsa_cipher = PKCS1_OAEP.new(pub_key)
                start_rsa = perf_counter()  # for eval
                encrypted_key = rsa_cipher.encrypt(aes_key)
                rsa_enc_times.append(perf_counter() - start_rsa)  # for eval
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

    total_time = perf_counter() - start_total  # for eval
    data_size_mb = len(data.encode()) / (1024 * 1024)  # for eval
    aes_throughput = data_size_mb / aes_enc_time if aes_enc_time else 0  # for eval

    if debug:  # for eval
        print(f"\n🔐 ENCRYPTION BENCHMARK")  
        print(f"AES Encrypt Time       : {aes_enc_time:.4f} sec")  
        print(f"AES Encrypt Throughput : {aes_throughput:.2f} MB/s")  
        print(f"RSA Encrypt Times (per key): {[f'{t:.4f}' for t in rsa_enc_times]}")  
        print(f"Total Time             : {total_time:.4f} sec")  

    return True, "Record encrypted and saved."

def decrypt_data(role, debug=False):  # for eval
    from time import perf_counter  # for eval

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
            start_total = perf_counter()  # for eval

            encrypted_key = base64.b64decode(encrypted_key_b64)
            start_rsa_dec = perf_counter()  # for eval
            rsa_cipher = PKCS1_OAEP.new(priv_key)
            aes_key = rsa_cipher.decrypt(encrypted_key)
            rsa_dec_time = perf_counter() - start_rsa_dec  # for eval

            iv = base64.b64decode(record["iv"])
            encrypted_data = base64.b64decode(record["data"])

            start_aes_dec = perf_counter()  # for eval
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted_data).decode())
            aes_dec_time = perf_counter() - start_aes_dec  # for eval

            total_time = perf_counter() - start_total  # for eval
            data_size_mb = len(encrypted_data) / (1024 * 1024)  # for eval
            aes_throughput = data_size_mb / aes_dec_time if aes_dec_time else 0  # for eval

            if debug:  # for eval
                print(f"\n🔓 DECRYPTION BENCHMARK for {record['user']}")  # for eval
                print(f"RSA Decrypt Time       : {rsa_dec_time:.4f} sec")  # for eval
                print(f"AES Decrypt Time       : {aes_dec_time:.4f} sec")  # for eval
                print(f"AES Decrypt Throughput : {aes_throughput:.2f} MB/s")  # for eval
                print(f"Total Time             : {total_time:.4f} sec")  # for eval

            results.append((record["user"], record.get("timestamp", "N/A"), True, decrypted))
        except Exception as e:
            results.append((record["user"], False, f"Decryption error: {str(e)}"))

    return True, results
