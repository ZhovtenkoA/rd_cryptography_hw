import requests


# 1. Получаем шифротекст cookie
response = requests.get("https://aes.cryptohack.org/flipping_cookie/get_cookie/")
if response.status_code != 200:
    print(f"Failed to get cookie. Status code: {response.status_code}")
    exit()
cookie = response.json()['cookie']
print(f"Original cookie: {cookie}")

# 2. Делим шифротекст на IV и ciphertext
iv = cookie[:32]  # Первые 16 байт — это IV
ciphertext = cookie[32:]  # Остаток — ciphertext
print(f"IV: {iv}")
print(f"Ciphertext: {ciphertext}")

# 3. Ксорим старое и новое значение (admin=False и admin=True)
old_value = b"admin=False;"
new_value = b"admin=True;"
xor_diff = bytes([a ^ b for a, b in zip(old_value, new_value)])

# 4. Модифицируем IV
iv_bytes = bytearray.fromhex(iv)
for i in range(len(xor_diff)):
    iv_bytes[i] ^= xor_diff[i]
modified_iv = iv_bytes.hex()
print(f"Modified IV: {modified_iv}")

# 5. Отправляем модифицированный IV и ciphertext в /check_admin
response = requests.get(f"https://aes.cryptohack.org/flipping_cookie/check_admin/{ciphertext}/{modified_iv}/")
if response.status_code != 200:
    print(f"Failed to check admin. Status code: {response.status_code}")
    print("Raw response:", response.text)
    exit()

try:
    server_response = response.json()
    print("Server response:", server_response)
except requests.exceptions.JSONDecodeError:
    print("Failed to decode JSON. Raw response:", response.text)