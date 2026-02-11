import requests
import base64
from cryptography.hazmat.primitives import serialization
from crypto_utils import (
    generate_rsa_keys,
    save_private_key,
    save_public_key,
    encrypt_message,
    decrypt_message,
    encrypt_session_key,
    decrypt_session_key
)

SERVER = "http://127.0.0.1:5000"

username = input("Enter your username: ")

# Generate keys
private_key, public_key = generate_rsa_keys()

save_private_key(private_key, f"keys/{username}_private.pem")
save_public_key(public_key, f"keys/{username}_public.pem")

with open(f"keys/{username}_public.pem", "r") as f:
    public_key_str = f.read()

# Register user
requests.post(
    f"{SERVER}/register",
    json={"username": username, "public_key": public_key_str}
)

print("Registered successfully.")

while True:
    print("\n1. Send Message")
    print("2. Receive Messages")
    print("3. Exit")

    choice = input("Select: ")

    if choice == "1":
        receiver = input("Enter receiver username: ")
        message = input("Enter message: ").encode()

        res = requests.get(f"{SERVER}/get_key/{receiver}")
        if res.status_code != 200:
            print("Receiver not found.")
            continue

        receiver_key_str = res.json()["public_key"]
        receiver_public_key = serialization.load_pem_public_key(
            receiver_key_str.encode()
        )

        aes_key, nonce, ciphertext = encrypt_message(message)
        encrypted_session_key = encrypt_session_key(aes_key, receiver_public_key)

        payload = {
            "sender": username,
            "receiver": receiver,
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "encrypted_session_key": base64.b64encode(encrypted_session_key).decode()
        }

        requests.post(f"{SERVER}/send", json=payload)
        print("Encrypted message sent.")

    elif choice == "2":
        res = requests.get(f"{SERVER}/receive/{username}")
        messages = res.json().get("messages", [])

        for msg in messages:
            encrypted_session_key = base64.b64decode(msg["encrypted_session_key"])
            nonce = base64.b64decode(msg["nonce"])
            ciphertext = base64.b64decode(msg["ciphertext"])

            aes_key = decrypt_session_key(encrypted_session_key, private_key)
            decrypted = decrypt_message(aes_key, nonce, ciphertext)

            print(f"\nFrom {msg['sender']}: {decrypted.decode()}")

        if not messages:
            print("No new messages.")

    elif choice == "3":
        break
