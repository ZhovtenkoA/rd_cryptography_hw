from Crypto.Hash import HMAC, SHA256

"""

Алгоритм: HMAC-SHA256
- обеспечивает аутентификацию и целосность данных
- использует SHA-256. SHA-256 на текущий момент криптографически стойкая хэш-функция

Для генерации имитовставки ключом был выбран главный ключ (для согласования между шифрованием и аутентификацией)
Так же для генерации имитовствки был использован:
 - IV (что бы MAC зависел от уникального значения, которое используется при шифровании и что бы МАС нельзя было переиспользовать)
 - шифротекст (для обеспечения целосности данных, уверенности что данные не были изменены)


"""



# Ключ, шифротекст и IV
key = bytes.fromhex("63e353ae93ecbfe00271de53b6f02a46")
ciphertext = bytes.fromhex("76c3ada7f1f7563ff30d7290e58fb4476eb12997d02a6488201c075da52ff3890260e2c89f631e7f919af96e4e47980a")
iv = bytes.fromhex("75b777fc8f70045c6006b39da1b3d622")

# Данные для генерации MAC
data = iv + ciphertext

# Генерация HMAC-SHA256
hmac = HMAC.new(key, digestmod=SHA256)
hmac.update(data)
mac = hmac.hexdigest()

# Сохранение MAC в файл
with open("mac.txt", "w") as file:
    file.write(mac)