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

# Вводим сообщение в консоль
message = input("Введите Ваше сообщение: ")

message_bytes = message.encode("utf-8")

# Шифруем сообщение
encrypted_message = public_key.encrypt(
    message_bytes,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Сохраняем сообщение в hex формате
with open("task-2-message.txt", "w") as msg_file:
    msg_file.write(encrypted_message.hex())

print("Сообщение зашифровано и сохранено в task-2-message.txt.")