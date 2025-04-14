import asyncio
from utils import THEIR_PROMPT, bob_client, decrypt_message, derive_session_key, derive_shared_secret, deserialize_dh_public_key, encrypt_message, generate_diffie_hellman_key, generate_key_pair_ecds, serialize_dh_public_key, show, prompt, read_message_from_stdin, generate_key_pair, serialize_public_key, deserialize_public_key, sign_data, verify_signature
from cryptography.exceptions import InvalidTag
async def receive(reader, session_key, sender_public_key):
    """Receive data, verify signature, and decrypt"""
    while True:
        try:
            # Отримуємо довжину підпису
            signature_len_bytes = await reader.read(4)
            if not signature_len_bytes:
                break
            signature_len = int.from_bytes(signature_len_bytes, 'big')

            # Отримуємо підпис
            signature = await reader.read(signature_len)
            if not signature:
                break

            # Отримуємо зашифроване повідомлення (включаючи nonce та тег)
            ciphertext_with_tag = await reader.read(1024 + 12 + 16)  # Max message + nonce + tag
            if not ciphertext_with_tag:
                break

            # Перевіряємо підпис зашифрованого повідомлення
            if verify_signature(sender_public_key, signature, ciphertext_with_tag):
                try:
                    plaintext = decrypt_message(session_key, ciphertext_with_tag)
                    message = plaintext.decode()
                    show(message)
                    prompt()
                except InvalidTag:
                    print(f"{THEIR_PROMPT}Помилка: Недійсний тег автентифікації! Можливо, повідомлення було підроблено.")
                    prompt()
                except Exception as e:
                    print(f"{THEIR_PROMPT}Помилка при дешифруванні: {e}")
                    prompt()
            else:
                print(f"{THEIR_PROMPT}Помилка: Недійсний підпис від відправника!")
                prompt()
        except Exception as e:
            print(f"{THEIR_PROMPT}Помилка при отриманні: {e}")
            break

async def send(writer, session_key, my_private_key):
    """Send data, encrypt, and sign"""
    while True:
        message = await read_message_from_stdin()
        plaintext = message.strip().encode()

        # Шифруємо повідомлення
        ciphertext_with_tag = encrypt_message(session_key, plaintext)

        # Підписуємо зашифроване повідомлення
        signature = sign_data(my_private_key, ciphertext_with_tag)

        # Відправляємо довжину підпису, сам підпис та зашифроване повідомлення
        signature_len_bytes = len(signature).to_bytes(4, 'big')
        writer.write(signature_len_bytes)
        writer.write(signature)
        writer.write(ciphertext_with_tag)

        prompt()
        await writer.drain()


async def init_connection():
    reader, writer = await bob_client()
    print("Starting secure key exchange with Alice...")
    prompt()

    # 1. Генеруємо довгострокову пару ключів Bob
    bob_ecdsa_private, bob_ecdsa_public = generate_key_pair_ecds()
    print("Bob generated his ECDSA keys.")

    # 2. Генеруємо одноразову пару ключів DH Bob
    bob_dh_private, bob_dh_public = generate_diffie_hellman_key()
    bob_dh_public_bytes = serialize_dh_public_key(bob_dh_public)
    print("Bob generated his DH key.")
    print("Bob's DH public key (bytes):", bob_dh_public_bytes.hex()) # ДОДАНИЙ РЯДОК

    # 3. Отримуємо довгостроковий публічний ключ Alice
    alice_ecdsa_public_bytes = await reader.read(2048)
    if not alice_ecdsa_public_bytes:
        print("Error: Alice disconnected before sending her ECDSA public key.")
        return
    print("Перші 50 байтів отриманого ECDSA ключа Alice:", alice_ecdsa_public_bytes[:50]) # Залишаємо для налагодження
    alice_ecdsa_public = deserialize_public_key(alice_ecdsa_public_bytes)
    print("Bob received Alice's ECDSA public key.")

    # 4. Отримуємо публічний ключ DH Alice та її підпис
    alice_dh_public_bytes = await reader.read(32)
    if not alice_dh_public_bytes:
        print("Error: Alice disconnected before sending her DH public key.")
        return
    signature_alice_dh_len_bytes = await reader.read(4)
    if not signature_alice_dh_len_bytes:
        print("Error: Alice disconnected before sending her DH signature length.")
        return
    signature_alice_dh_len = int.from_bytes(signature_alice_dh_len_bytes, 'big')
    signature_alice_dh = await reader.read(signature_alice_dh_len)
    if not signature_alice_dh:
        print("Error: Alice disconnected before sending her DH signature.")
        return
    alice_dh_public = deserialize_dh_public_key(alice_dh_public_bytes)
    print("Bob received Alice's DH public key and signature.")

    # 5. Перевіряємо підпис публічного ключа DH Alice довгостроковим публічним ключем Alice
    if not verify_signature(alice_ecdsa_public, signature_alice_dh, alice_dh_public_bytes):
        print("Error: Invalid signature on Alice's DH public key!")
        return
    print("Signature on Alice's DH public key is valid.")

    # 6. Серіалізуємо та відправляємо публічний ключ DH Bob'а, підписаний довгостроковим ключем
    signature_bob_dh = sign_data(bob_ecdsa_private, bob_dh_public_bytes)
    writer.write(bob_dh_public_bytes)
    writer.write(len(signature_bob_dh).to_bytes(4, 'big'))
    writer.write(signature_bob_dh)
    await writer.drain()
    print("Bob sent his DH public key and signature to Alice.")

    # 7. Серіалізуємо та відправляємо довгостроковий публічний ключ Bob'а
    bob_ecdsa_public_bytes = serialize_public_key(bob_ecdsa_public)
    writer.write(bob_ecdsa_public_bytes)
    await writer.drain()
    print("Bob sent his ECDSA public key to Alice.")

    # 8. Обчислюємо спільний секрет
    shared_secret_bob = derive_shared_secret(bob_dh_private, alice_dh_public)
    print("Bob's shared secret (bytes):", shared_secret_bob.hex()) # ДОДАНИЙ РЯДОК
    session_key_bob = derive_session_key(shared_secret_bob)
    print("Bob's session key:", session_key_bob.hex())

    print("Secure key exchange complete!")
    prompt()

    await asyncio.gather(receive(reader, session_key_bob, alice_ecdsa_public), send(writer, session_key_bob, bob_ecdsa_private))


if __name__ == "__main__":
    print("Starting Bob's chat...")
    asyncio.run(init_connection())
