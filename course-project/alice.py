import asyncio
from utils import (
    THEIR_PROMPT,
    alice_server,
    decrypt_message,
    encrypt_message,
    prompt,
    show,
    read_message_from_stdin,
    generate_key_pair_ecds,
    serialize_public_key,
    deserialize_public_key,
    sign_data,
    verify_signature,
    generate_diffie_hellman_key,
    serialize_dh_public_key,
    deserialize_dh_public_key,
    derive_shared_secret,
    derive_session_key,
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


async def init_connection(reader, writer):
    print("Starting secure key exchange with Bob...")
    prompt()

    alice_ecdsa_private, alice_ecdsa_public = generate_key_pair_ecds()
    print("Alice generated her ECDSA keys.")

    alice_ecdsa_public_bytes = serialize_public_key(alice_ecdsa_public)
    writer.write(alice_ecdsa_public_bytes)
    await writer.drain()
    print("Alice sent her ECDSA public key to Bob.")

    alice_dh_private, alice_dh_public = generate_diffie_hellman_key()
    alice_dh_public_bytes = serialize_dh_public_key(alice_dh_public)
    print("Alice generated her DH key.")

    signature_alice_dh = sign_data(alice_ecdsa_private, alice_dh_public_bytes)
    writer.write(alice_dh_public_bytes)
    writer.write(len(signature_alice_dh).to_bytes(4, "big"))
    writer.write(signature_alice_dh)
    await writer.drain()
    print("Alice sent her DH public key and signature to Bob.")

    bob_dh_public_bytes = await reader.read(32)
    if not bob_dh_public_bytes:
        print("Error: Bob disconnected before sending his DH public key.")
        return
    signature_bob_dh_len_bytes = await reader.read(4)
    if not signature_bob_dh_len_bytes:
        print("Error: Bob disconnected before sending his DH signature length.")
        return
    signature_bob_dh_len = int.from_bytes(signature_bob_dh_len_bytes, "big")
    signature_bob_dh = await reader.read(signature_bob_dh_len)
    if not signature_bob_dh:
        print("Error: Bob disconnected before sending his DH signature.")
        return
    bob_dh_public = deserialize_dh_public_key(bob_dh_public_bytes)
    print("Alice received Bob's DH public key and signature.")

    bob_ecdsa_public_bytes = await reader.read(2048)
    if not bob_ecdsa_public_bytes:
        print("Error: Bob disconnected before sending his ECDSA public key.")
        return
    bob_ecdsa_public = deserialize_public_key(bob_ecdsa_public_bytes)
    print("Alice received Bob's ECDSA public key.")

    if not verify_signature(bob_ecdsa_public, signature_bob_dh, bob_dh_public_bytes):
        print("Error: Invalid signature on Bob's DH public key!")
        return
    print("Signature on Bob's DH public key is valid.")

    shared_secret_alice = derive_shared_secret(alice_dh_private, bob_dh_public)

    session_key_alice = derive_session_key(shared_secret_alice)

    print("Secure key exchange complete!")
    prompt()

    await asyncio.gather(
        receive(reader, session_key_alice, bob_ecdsa_public),
        send(writer, session_key_alice, alice_ecdsa_private),
    )


if __name__ == "__main__":
    print("Starting Alice's chat... Waiting for Bob...")
    asyncio.run(alice_server(init_connection))
