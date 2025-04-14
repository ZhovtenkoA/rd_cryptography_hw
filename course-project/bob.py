import asyncio
from utils import (
    THEIR_PROMPT,
    bob_client,
    decrypt_message,
    derive_session_key,
    derive_shared_secret,
    deserialize_dh_public_key,
    encrypt_message,
    generate_diffie_hellman_key,
    generate_key_pair_ecds,
    serialize_dh_public_key,
    show,
    prompt,
    read_message_from_stdin,
    generate_key_pair,
    serialize_public_key,
    deserialize_public_key,
    sign_data,
    verify_signature,
)
from cryptography.exceptions import InvalidTag

received_sequence_numbers = set()


async def receive(reader, session_key, sender_public_key):
    global received_sequence_numbers
    while True:
        try:
            signature_len_bytes = await reader.read(4)
            if not signature_len_bytes:
                break
            signature_len = int.from_bytes(signature_len_bytes, "big")
            signature = await reader.read(signature_len)
            if not signature:
                break
            ciphertext_with_tag = await reader.read(1024 + 12 + 16)
            if not ciphertext_with_tag:
                break

            if verify_signature(sender_public_key, signature, ciphertext_with_tag):
                try:
                    plaintext_with_sequence = decrypt_message(
                        session_key, ciphertext_with_tag
                    )
                    parts = plaintext_with_sequence.decode().split(":", 1)
                    if len(parts) == 2:
                        sequence_number_str, actual_plaintext = parts
                        try:
                            sequence_number = int(sequence_number_str)
                            if sequence_number in received_sequence_numbers:
                                prompt()
                                continue
                            received_sequence_numbers.add(sequence_number)
                            message = actual_plaintext
                            show(message)
                            prompt()
                        except ValueError:
                            prompt()
                    else:
                        print(f"{THEIR_PROMPT}Ошибка: Неправильный формат сообщения!")
                        prompt()
                except InvalidTag:
                    print(f"{THEIR_PROMPT}Ошибка тэга аутентификации")
                    prompt()
                except Exception as e:
                    print(f"{THEIR_PROMPT}Ошибка при дешифровании: {e}")
                    prompt()
            else:
                print(f"{THEIR_PROMPT}Ошибка: Недействительная подпись!")
                prompt()
        except Exception as e:
            print(f"{THEIR_PROMPT}Ошибка при получении: {e}")
            break


message_counter = 0


async def send(writer, session_key, my_private_key):
    global message_counter
    while True:
        message = await read_message_from_stdin()
        plaintext = message.strip().encode()

        message_counter += 1
        data_to_sign = str(message_counter).encode() + b":" + plaintext
        ciphertext_with_tag = encrypt_message(session_key, data_to_sign)
        signature = sign_data(my_private_key, ciphertext_with_tag)

        signature_len_bytes = len(signature).to_bytes(4, "big")
        writer.write(signature_len_bytes)
        writer.write(signature)
        writer.write(ciphertext_with_tag)

        prompt()
        await writer.drain()


async def init_connection():
    reader, writer = await bob_client()
    print("Starting secure key exchange with Alice...")
    prompt()

    bob_ecdsa_private, bob_ecdsa_public = generate_key_pair_ecds()
    print("Bob generated his ECDSA keys.")

    bob_dh_private, bob_dh_public = generate_diffie_hellman_key()
    bob_dh_public_bytes = serialize_dh_public_key(bob_dh_public)
    print("Bob generated his DH key.")

    alice_ecdsa_public_bytes = await reader.read(2048)
    if not alice_ecdsa_public_bytes:
        print("Error: Alice disconnected before sending her ECDSA public key.")
        return
    alice_ecdsa_public = deserialize_public_key(alice_ecdsa_public_bytes)
    print("Bob received Alice's ECDSA public key.")

    alice_dh_public_bytes = await reader.read(32)
    if not alice_dh_public_bytes:
        print("Error: Alice disconnected before sending her DH public key.")
        return
    signature_alice_dh_len_bytes = await reader.read(4)
    if not signature_alice_dh_len_bytes:
        print("Error: Alice disconnected before sending her DH signature length.")
        return
    signature_alice_dh_len = int.from_bytes(signature_alice_dh_len_bytes, "big")
    signature_alice_dh = await reader.read(signature_alice_dh_len)
    if not signature_alice_dh:
        print("Error: Alice disconnected before sending her DH signature.")
        return
    alice_dh_public = deserialize_dh_public_key(alice_dh_public_bytes)
    print("Bob received Alice's DH public key and signature.")

    if not verify_signature(
        alice_ecdsa_public, signature_alice_dh, alice_dh_public_bytes
    ):
        print("Error: Invalid signature on Alice's DH public key!")
        return
    print("Signature on Alice's DH public key is valid.")

    signature_bob_dh = sign_data(bob_ecdsa_private, bob_dh_public_bytes)
    writer.write(bob_dh_public_bytes)
    writer.write(len(signature_bob_dh).to_bytes(4, "big"))
    writer.write(signature_bob_dh)
    await writer.drain()
    print("Bob sent his DH public key and signature to Alice.")

    bob_ecdsa_public_bytes = serialize_public_key(bob_ecdsa_public)
    writer.write(bob_ecdsa_public_bytes)
    await writer.drain()
    print("Bob sent his ECDSA public key to Alice.")

    # 8. Обчислюємо спільний секрет
    shared_secret_bob = derive_shared_secret(bob_dh_private, alice_dh_public)

    session_key_bob = derive_session_key(shared_secret_bob)

    print("Secure key exchange complete!")
    prompt()

    await asyncio.gather(
        receive(reader, session_key_bob, alice_ecdsa_public),
        send(writer, session_key_bob, bob_ecdsa_private),
    )


if __name__ == "__main__":
    print("Starting Bob's chat...")
    asyncio.run(init_connection())
