import requests
import json

from binascii import hexlify


def encrypt(pt):
    """Obtain ciphertext (encryption) for plaintext"""
    hex = hexlify(pt.encode()).decode()
    url = "http://aes.cryptohack.org/ecb_oracle/encrypt/" + hex
    r = requests.get(url)
    ct = (json.loads(r.text))["ciphertext"]
    return ct


def print_ciphertext(ct):
    """Print ciphertext by block"""
    parts = [ct[i : i + 32] for i in range(0, len(ct), 32)]
    for p in parts:
        print(p)

#             0123456789abcdef
# ct = encrypt("p3n6u1n5_h473_3c"
# )
# print_ciphertext(ct)



# def find_flag():

#     known_flag = "crypto"
#     charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}"

#     for _ in range(10):  # остаток символов
#         prefix = "-" * (16 - len(known_flag) - 1)
#         for char in charset:
#             pt = prefix + known_flag + char + prefix
#             ct = encrypt(pt)
#             if ct[:32] == ct[32:64]:
#                 known_flag += char
#                 print(f"Найден символ: {char}, текущий флаг: {known_flag}")
#                 break
#     return known_flag


# if __name__ == "__main__":
#     flag = find_flag()
#     print(f"Флаг: {flag}")