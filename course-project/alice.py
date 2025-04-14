import asyncio
from utils import THEIR_PROMPT, alice_server, decrypt_message, encrypt_message, prompt, show, read_message_from_stdin, generate_key_pair_ecds, serialize_public_key, deserialize_public_key, sign_data, verify_signature, generate_diffie_hellman_key, serialize_dh_public_key, deserialize_dh_public_key, derive_shared_secret, derive_session_key
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



async def init_connection(reader, writer):
    print("Starting secure key exchange with Bob...")
    prompt()

    # 1. Генеруємо довгострокову пару ключів Alice
    alice_ecdsa_private, alice_ecdsa_public = generate_key_pair_ecds()
    print("Alice generated her ECDSA keys.")

    # 2. Серіалізуємо та відправляємо довгостроковий публічний ключ Alice
    alice_ecdsa_public_bytes = serialize_public_key(alice_ecdsa_public)
    writer.write(alice_ecdsa_public_bytes)
    await writer.drain()
    print("Alice sent her ECDSA public key to Bob.")

    # 3. Генеруємо одноразову пару ключів DH Alice
    alice_dh_private, alice_dh_public = generate_diffie_hellman_key()
    alice_dh_public_bytes = serialize_dh_public_key(alice_dh_public)
    print("Alice generated her DH key.")
    print("Alice's DH public key (bytes):", alice_dh_public_bytes.hex()) # ДОДАНИЙ РЯДОК

    # 4. Серіалізуємо та відправляємо публічний ключ DH Alice, підписаний довгостроковим ключем
    signature_alice_dh = sign_data(alice_ecdsa_private, alice_dh_public_bytes)
    writer.write(alice_dh_public_bytes)
    writer.write(len(signature_alice_dh).to_bytes(4, 'big'))
    writer.write(signature_alice_dh)
    await writer.drain()
    print("Alice sent her DH public key and signature to Bob.")

    # 5. Отримуємо публічний ключ DH Bob'а та його підпис
    bob_dh_public_bytes = await reader.read(32)
    if not bob_dh_public_bytes:
        print("Error: Bob disconnected before sending his DH public key.")
        return
    signature_bob_dh_len_bytes = await reader.read(4)
    if not signature_bob_dh_len_bytes:
        print("Error: Bob disconnected before sending his DH signature length.")
        return
    signature_bob_dh_len = int.from_bytes(signature_bob_dh_len_bytes, 'big')
    signature_bob_dh = await reader.read(signature_bob_dh_len)
    if not signature_bob_dh:
        print("Error: Bob disconnected before sending his DH signature.")
        return
    bob_dh_public = deserialize_dh_public_key(bob_dh_public_bytes)
    print("Alice received Bob's DH public key and signature.")

    # 6. Отримуємо довгостроковий публічний ключ Bob'а
    bob_ecdsa_public_bytes = await reader.read(2048)
    if not bob_ecdsa_public_bytes:
        print("Error: Bob disconnected before sending his ECDSA public key.")
        return
    bob_ecdsa_public = deserialize_public_key(bob_ecdsa_public_bytes)
    print("Alice received Bob's ECDSA public key.")

    # 7. Перевіряємо підпис публічного ключа DH Bob'а довгостроковим публічним ключем Bob'а
    if not verify_signature(bob_ecdsa_public, signature_bob_dh, bob_dh_public_bytes):
        print("Error: Invalid signature on Bob's DH public key!")
        return
    print("Signature on Bob's DH public key is valid.")

    shared_secret_alice = derive_shared_secret(alice_dh_private, bob_dh_public)
    print("Alice's shared secret (bytes):", shared_secret_alice.hex()) # ДОДАНИЙ РЯДОК
    session_key_alice = derive_session_key(shared_secret_alice)
    print("Alice's session key:", session_key_alice.hex())

    print("Secure key exchange complete!")
    prompt()

    await asyncio.gather(receive(reader, session_key_alice, bob_ecdsa_public), send(writer, session_key_alice, alice_ecdsa_private))


if __name__ == "__main__":
    print("Starting Alice's chat... Waiting for Bob...")
    asyncio.run(alice_server(init_connection))
