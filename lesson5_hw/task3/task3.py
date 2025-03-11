import json
import os
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

"""

Алгоритм: PBKDF2 + HMAC-SHA256
- алгоритм заточен на генерацию ключей из паролей с низкой энтропией
- использует соль и гибкую настройку количества итераций для генерации ключа

"""



def derive_key(username, password):
    if not os.path.exists("lesson5_hw\\task3\\user_metadata.json"):
        with open("lesson5_hw\\task3\\user_metadata.json", "w") as file:
            json.dump([], file)

    with open("lesson5_hw\\task3\\user_metadata.json", "r") as file:
        users = json.load(file)

    user = next((u for u in users if u["username"] == username), None)

    if user is None:
        salt = os.urandom(16)
        user = {
            "username": username,
            "salt": salt.hex()
        }
        users.append(user)
        with open("lesson5_hw\\task3\\user_metadata.json", "w") as file:
            json.dump(users, file)
    else:
        salt = bytes.fromhex(user["salt"])

    key = PBKDF2(password, salt, dkLen=16, count=600000, hmac_hash_module=SHA256)
    return key.hex()



username = "Alice Cooper"
password = "Cooper12345"
key = derive_key(username, password)
print(f"{username}'s key - {key}")
