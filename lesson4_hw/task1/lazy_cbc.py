import requests

# 1. Шифруем три блока нулей
plaintext = "00" * 48  
response = requests.get(f"https://aes.cryptohack.org/lazy_cbc/encrypt/{plaintext}/")
ciphertext = response.json()['ciphertext']
print(f"Ciphertext: {ciphertext}")

# 2. Разбиваем шифротекст на три блока по 16 байт и меняем средний блок на нули
ciphertext_blocks = [ciphertext[i:i+32] for i in range(0, len(ciphertext), 32)]  
modified_ciphertext = ciphertext_blocks[0] + "0" * 32 + ciphertext_blocks[0]  
print(f"Modified ciphertext: {modified_ciphertext}")

# 3. Отправляем наш модифицированный шифротекст в /receive
response = requests.get(f"https://aes.cryptohack.org/lazy_cbc/receive/{modified_ciphertext}/")
decrypted_data = response.json()['error'].split(": ")[1]
print(f"Decrypted data: {decrypted_data}")

# 4. Ксорим первый и третий блок расшифрованных данных что бы получить ключ (P_1 XOR P_3)
decrypted_blocks = [decrypted_data[i:i+32] for i in range(0, len(decrypted_data), 32)]
p1 = bytes.fromhex(decrypted_blocks[0]) 
p3 = bytes.fromhex(decrypted_blocks[2]) 
key = bytes([p1[i] ^ p3[i] for i in range(16)]).hex()  
print(f"Key: {key}")

# 5. Получаем флаг
response = requests.get(f"https://aes.cryptohack.org/lazy_cbc/get_flag/{key}/")
if 'plaintext' in response.json():
    flag = response.json()['plaintext']
    flag = bytes.fromhex(flag).decode()
    print(f"Flag: {flag}")
else:
    print("Failed to get the flag. Response:", response.json())