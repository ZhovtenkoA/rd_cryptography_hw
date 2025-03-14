from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Считываем открытый ключ
with open("lesson6_hw\\task_pub.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Считываем сообщение
with open("lesson6_hw\\task_message.txt", "r") as msg_file:
    message = bytes.fromhex(msg_file.read())

# Считываем подпись
with open("lesson6_hw\\task_signature.txt", "r") as sig_file:
    signature = bytes.fromhex(sig_file.read())

# Верификация подписи
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Подпись верифицировано успешно")
except Exception as e:
    print(f"Подпись не верифицировано: {e}")