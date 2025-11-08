import os
import json
from Crypto.Hash import SHA1
from Crypto.Cipher import AES

# ==============================
# CONSTANTS & SETTINGS
# ==============================
SALT = "jjo+Ffqil5bdpo5VG82kLj8Ng1sK7L/rCqFTa39Zkom2/baqf5j9HMmsuCr0ipjYsPrsaNIOESWy7bDDGYWx1eA=="
BLOCK_SIZE = 16
CRC32_SIZE = 4


# ==============================
# CRC32 IMPLEMENTATION
# ==============================
class CRC32:
    def __init__(self):
        self.__table = self.__make_table()

    def compute(self, data):
        num = 0xD6EAF23C
        for idx in range(len(data)):
            num = num >> 8 ^ self.__table[data[idx] ^ num & 0xFF]
        return num

    @staticmethod
    def __make_table():
        table = []
        for idx1 in range(256):
            num = idx1
            for idx2 in range(8):
                num = num >> 1 if (num & 1) != 1 else num ^ 0x58E6D9AF
            table.append(num)
        return table


# ==============================
# HELPER FUNCTIONS
# ==============================
def password_derive_bytes(pstring, salt, iterations, keylen):
    lasthash = pstring + salt
    for i in range(iterations - 1):
        lasthash = SHA1.new(lasthash).digest()
    bytes_ = SHA1.new(lasthash).digest()
    ctrl = 1
    while len(bytes_) < keylen:
        bytes_ += SHA1.new(str(ctrl).encode() + lasthash).digest()
        ctrl += 1
    return bytes_[:keylen]


def pkcs5_unpad(data):
    return data[0:-data[-1]]


def pkcs5_pad(data):
    length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([length] * length)


def verify_crc32(data):
    data_crc32 = CRC32().compute(data[0:len(data) - CRC32_SIZE])
    real_crc32 = int.from_bytes(data[len(data) - CRC32_SIZE:], byteorder='little')
    return data_crc32 == real_crc32


# ==============================
# ENCRYPT / DECRYPT CORE
# ==============================
def decrypt_oc2(save_file_path, dest_file_path, steam_id):
    with open(save_file_path, 'rb') as file_d:
        data = file_d.read()

    if len(data) <= BLOCK_SIZE + CRC32_SIZE:
        raise RuntimeError("Cannot decrypt save because source save is too small")

    if not verify_crc32(data):
        print(f" WARNING: CRC32 mismatch for {save_file_path}")

    aes_iv = data[:BLOCK_SIZE]
    data = data[BLOCK_SIZE:len(data) - CRC32_SIZE]

    key = password_derive_bytes(steam_id.encode(), SALT.encode(), 2, 32)
    cipher = AES.new(key, AES.MODE_CBC, iv=aes_iv)
    decrypted_file = pkcs5_unpad(cipher.decrypt(data))

    try:
        json.loads(decrypted_file)
    except json.JSONDecodeError:
        raise RuntimeError(f"Decryption failed for {save_file_path} (wrong Steam ID or corrupted file)")

    with open(dest_file_path, "wb+") as file_d:
        file_d.write(decrypted_file)


def encrypt_oc2(save_file_path, dest_file_path, steam_id):
    with open(save_file_path, 'rb') as file_d:
        data = file_d.read()

    try:
        json.loads(data)
    except json.JSONDecodeError:
        raise RuntimeError(f"Cannot encrypt {save_file_path} (invalid JSON format)")

    key = password_derive_bytes(steam_id.encode(), SALT.encode(), 2, 32)
    cipher = AES.new(key, AES.MODE_CBC)
    aes_iv = cipher.iv

    crypted_data_with_iv = aes_iv + cipher.encrypt(pkcs5_pad(data))
    data_crc32 = CRC32().compute(crypted_data_with_iv)

    with open(dest_file_path, "wb+") as file_d:
        file_d.write(crypted_data_with_iv)
        file_d.write(data_crc32.to_bytes(4, byteorder='little'))


# ==============================
# BATCH PROCESSING LOGIC
# ==============================
def main():
    decrypt_id = input("Enter Steam ID for DECRYPT: ").strip()
    encrypt_id = input("Enter Steam ID for ENCRYPT: ").strip()

    save_files = [f for f in os.listdir('.') if f.endswith('.save')]
    if not save_files:
        print("No .save files found in current directory.")
        return

    for save_file in save_files:
        base_name = os.path.splitext(save_file)[0]
        json_file = f"{base_name}.json"

        print(f"\n=== Processing {save_file} ===")

        # Step 1: Decrypt
        print(f"Decrypting {save_file} -> {json_file} ...")
        decrypt_oc2(save_file, json_file, decrypt_id)

        # Step 2: Encrypt
        print(f"Encrypting {json_file} -> {save_file} ...")
        encrypt_oc2(json_file, save_file, encrypt_id)

        # Step 3: Remove JSON
        if os.path.exists(json_file):
            os.remove(json_file)
            print(f"Removed {json_file}")

    print("\n All files processed successfully!")


if __name__ == "__main__":
    main()
