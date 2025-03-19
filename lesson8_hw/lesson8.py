from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import hashes
import binascii


"""
Исходные данные Алисы
"""

# Открытый ключ Alice для подписи в PEM формате
alice_pub_sign_key_raw = b"""
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAES/35y89DRx2XEh6pJvCckadQ9Awuys84
HORPVVaDksVxWfSkngYrz/c+HwVS9tV5ivnVwCHxyJ8gTQob/0LDDg==
-----END PUBLIC KEY-----
"""

# Открытый ключ Alice для согласование ключа
alice_x_pub_key = b'92ce3bc6d941238da92639c72a7d3bb483d3c18fdca9f42164459a3751638433'

# Подпись открытого ключа Alice для согласования ключа
signature = b'3045022034b7944bf92bfaa2791b5fe929d915add4ee59dbd9e776c1520568fbf2503048022100f09c9113f38fadb33b05332eab9a4982f7dda35fb1f503bb46da806c8e8dbaa2'


# Загрузка открытого ключа Alice для подписи
alice_pub_sign_key = serialization.load_pem_public_key(alice_pub_sign_key_raw)

# Функция проверки поодписи Alice
def verify_signature(public_key, signature, data):
    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        print(f"Ошибка проверки подписи: {e}")
        return False

# Проверяем подпись Alice
alice_x_pub_key_bytes = binascii.unhexlify(alice_x_pub_key)
signature_bytes = binascii.unhexlify(signature)

if verify_signature(alice_pub_sign_key, signature_bytes, alice_x_pub_key_bytes):
    print("Подпись Alice валидна")
else:
    print("Подпись Alice не валидна")




"""
Согласование ключа со стороны Боба
"""


# Генерация долгострочной ключевой пары для подписи Боба
bob_private_sign_key = ec.generate_private_key(ec.SECP256K1())
bob_public_sign_key = bob_private_sign_key.public_key()

# Сериализация открытого ключа Боба для подписи в PEM формате
bob_pub_sign_key_pem = bob_public_sign_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Генерация private_key Боба для согласования ключа
bob_private_key = X25519PrivateKey.generate()
bob_public_key = bob_private_key.public_key()

# Сериализация открытого ключа Боба для согласования ключа в hex формате
bob_public_key_bytes = bob_public_key.public_bytes(
    encoding=serialization.Encoding.Raw, 
    format=serialization.PublicFormat.Raw 
)
bob_public_key_hex = binascii.hexlify(bob_public_key_bytes)

# Подпись открытого ключа Боба для согласования ключа
signature_bob = bob_private_sign_key.sign(
    bob_public_key_bytes,
    ec.ECDSA(hashes.SHA256())
)

# Сериализация подписи Боба в hex формате
signature_bob_hex = binascii.hexlify(signature_bob)

# Сохранение результатов
with open("bob_output.txt", "w") as f:
    f.write("Открытый ключ подписи Bob (PEM):\n")
    f.write(bob_pub_sign_key_pem.decode() + "\n\n")
    f.write("Открытый ключ ECDH Bob (hex):\n")
    f.write(bob_public_key_hex.decode() + "\n\n")
    f.write("Подпись открытого ключа ECDH Bob (hex):\n")
    f.write(signature_bob_hex.decode() + "\n")

print("Результаты сохранены в bob_output.txt")