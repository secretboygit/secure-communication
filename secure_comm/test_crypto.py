from crypto_utils import generate_rsa_keys, save_private_key, save_public_key

private_key, public_key = generate_rsa_keys()

save_private_key(private_key, "keys/private.pem")
save_public_key(public_key, "keys/public.pem")

print("RSA 4096-bit Keys Generated Successfully.")

from crypto_utils import encrypt_message, decrypt_message

message = b"Secure Defence Message"

aes_key, nonce, ciphertext = encrypt_message(message)
decrypted = decrypt_message(aes_key, nonce, ciphertext)

print("Original:", message)
print("Decrypted:", decrypted)

from cryptography.hazmat.primitives import serialization
from crypto_utils import encrypt_session_key, decrypt_session_key

# Load keys
with open("keys/private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

with open("keys/public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(
        f.read()
    )

# Encrypt AES key with RSA
encrypted_session_key = encrypt_session_key(aes_key, public_key)

# Decrypt AES key
decrypted_session_key = decrypt_session_key(encrypted_session_key, private_key)

print("Session Key Match:", aes_key == decrypted_session_key)
