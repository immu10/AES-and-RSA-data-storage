# create_user.py

import json
import bcrypt
import os

DATA_FILE = "patient_data.txt"

def load_users():
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(DATA_FILE, "w") as f:
        json.dump(users, f, indent=2)

def create_user(username, password, role, can_write=False):
    users = load_users()
    if username in users:
        return "exists"

    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    attributes = [role]
    if role == "Doctor":
        attributes.append("Cardiology")

    users[username] = {
        "password": hashed_pw,
        "attributes": attributes,
        "can_write": can_write
    }
    save_users(users)
    return "success"
