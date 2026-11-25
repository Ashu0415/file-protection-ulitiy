import os
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a cryptographic key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def calculate_sha256(file_path: str) -> str:
    """Calculate the SHA-256 hash of a file for integrity verification."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def encrypt_file(file_path: str, password: str) -> None:
    """Encrypt a file and save it with a .enc extension."""
    if not os.path.exists(file_path):
        print(f"Error: '{file_path}' not found.")
        return

    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    original_hash = calculate_sha256(file_path)

    with open(file_path, "rb") as f:
        data = f.read()

    encrypted_data = fernet.encrypt(data)
    encrypted_path = f"{file_path}.enc"

    with open(encrypted_path, "wb") as f:
        f.write(salt + encrypted_data)

    print(f"Encrypted successfully -> {encrypted_path}")
    print(f"Original SHA-256: {original_hash}")


def decrypt_file(encrypted_path: str, password: str) -> None:
    """Decrypt a .enc file back to its original form."""
    if not os.path.exists(encrypted_path):
        print(f"Error: '{encrypted_path}' not found.")
        return

    with open(encrypted_path, "rb") as f:
        raw_data = f.read()

    salt = raw_data[:16]
    encrypted_data = raw_data[16:]
    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception:
        print("Decryption failed: Invalid password or corrupted file.")
        return

    output_path = (
        encrypted_path[:-4]
        if encrypted_path.endswith(".enc")
        else f"{encrypted_path}.dec"
    )

    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    restored_hash = calculate_sha256(output_path)
    print(f"Decrypted successfully -> {output_path}")
    print(f"Restored SHA-256: {restored_hash}")


def main() -> None:
    print("=== File Protection Utility ===")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    print("3. Check file SHA-256 hash")

    choice = input("Choose an option (1/2/3): ").strip()

    if choice == "1":
        path = input("Enter file path to encrypt: ").strip()
        pwd = input("Enter password: ").strip()
        encrypt_file(path, pwd)
    elif choice == "2":
        path = input("Enter .enc file path to decrypt: ").strip()
        pwd = input("Enter password: ").strip()
        decrypt_file(path, pwd)
    elif choice == "3":
        path = input("Enter file path: ").strip()
        if os.path.exists(path):
            print(f"SHA-256: {calculate_sha256(path)}")
        else:
            print(f"Error: '{path}' not found.")
    else:
        print("Invalid option.")


if __name__ == "__main__":
    main()
