# login.py

import json
import bcrypt

DATA_FILE = "logins.txt"

def load_users():
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def verify_login(username, password):
    users = load_users()
    if username not in users:
        return False
    stored_hash = users[username]["password"].encode()
    return bcrypt.checkpw(password.encode(), stored_hash)

def get_user_attributes(username):
    users = load_users()
    return users.get(username, {}).get("attributes", [])

def can_user_write(username):
    users = load_users()
    return users.get(username, {}).get("can_write", False)