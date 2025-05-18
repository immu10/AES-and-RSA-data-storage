from Crypto.PublicKey import RSA
import os

KEY_DIR = "keys"
os.makedirs(KEY_DIR, exist_ok=True)

def generate_role_keys(role):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(f"{KEY_DIR}/{role}_private.pem", "wb") as f:
        f.write(private_key)

    with open(f"{KEY_DIR}/{role}_public.pem", "wb") as f:
        f.write(public_key)

    print(f"RSA keypair generated for role: {role}")

# Example:
generate_role_keys("Doctor")
generate_role_keys("Admin")
