from binascii import hexlify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# Загальні параметри DH спільні для всіх учасників і узгоджуються на рівні протоколу.
print("Generating parameters...")
parameters = dh.generate_parameters(generator=2, key_size=2048)
print("Module:\n", parameters.parameter_numbers().p)
print("Gen:", parameters.parameter_numbers().g)

# Алиса: Генерация ключей RSA
alice_private_rsa = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
alice_public_rsa = alice_private_rsa.public_key()

# Боб: Генерация ключей RSA
bob_private_rsa = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
bob_public_rsa = bob_private_rsa.public_key()




# Алиса: Генерация ключей Диффи-Хелмана
alice_private_dh = parameters.generate_private_key()
alice_public_dh = alice_private_dh.public_key()

# Боб: Генерация ключей Диффи-Хелмана
bob_private_dh = parameters.generate_private_key()
bob_public_dh = bob_private_dh.public_key()

# Алиса: Подпись публичного ключа Диффи-Хелмана
alice_signature = alice_private_rsa.sign(
    alice_public_dh.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    ),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Боб: Подпись публичного ключа Диффи-Хелмана
bob_signature = bob_private_rsa.sign(
    bob_public_dh.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    ),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)




# Алиса: Проверка подписи Боба
try:
    bob_public_rsa.verify(
        bob_signature,
        bob_public_dh.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        ),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Алиса: Подпись Боба валидна.")
except Exception as e:
    print(f"Алиса: Подпись Боба не валидна -  {e}")

# Боб: Проверка подписи Алисы 
try:
    alice_public_rsa.verify(
        alice_signature,
        alice_public_dh.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        ),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Боб: Подпись Алисы валидна")
except Exception as e:
    print(f"Боб: Подпись Алисы не валидна - {e}")

# Алиса: Просчет общего секрета
alice_shared_value = alice_private_dh.exchange(bob_public_dh)
alice_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"handshake data",
).derive(alice_shared_value)
print("Алиса: Общий секретный ключ:\n", hexlify(alice_derived_key))

# Боб: Просчет общего секрета
bob_shared_value = bob_private_dh.exchange(alice_public_dh)
bob_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"handshake data",
).derive(bob_shared_value)
print("Боб: Общий секретны ключ:\n", hexlify(bob_derived_key))

# Проверка одинаковости ключа
if alice_derived_key == bob_derived_key:
    print("Ключи одинаковые")
else:
    print("Ключи разные")