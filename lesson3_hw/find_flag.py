import requests
import json
import string



# Размер блока в HEX (16 байт = 32 символа)
BLOCK_SIZE_HEX = 16 * 2
# Чарсет для подбора флага
CHARSET = string.ascii_letters + string.digits + string.punctuation


def encrypt(plaintext: str) -> str:
    """
    Шифрует открытый текст с помощью ECB Oracle.
    Возвращает шифротекст в виде HEX-строки.
    """
    url = f"https://aes.cryptohack.org/ecb_oracle/encrypt/{plaintext.encode().hex()}"
    response = requests.get(url)
    return json.loads(response.text)["ciphertext"]


def split_into_blocks(ciphertext: str, block_size: int) -> list[str]:
    """
    Разбивает шифротекст на блоки заданного размера
    """
    return [ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)]


def find_flag() -> str:
    """
    Находит флаг, используя уязвимость ECB Oracle)
    """
    flag = ""
    
    try:
        # Подбор символов флага
        for i in range(BLOCK_SIZE_HEX - 1, 0, -1):
            # Формируем сообщения для подбора
            padding = "A" * i  
            # Получаем "эталонный" блок шифротекста 
            target_block = split_into_blocks(encrypt(padding), BLOCK_SIZE_HEX)[1]
            # Подбираем символ флага
            found_char = False
            for char in CHARSET:
                # Формируем сообщение для побора
                plaintext = padding + flag + char
                # Получаем шифротекст
                ciphertext = encrypt(plaintext)
                # Разбиваем шифротекст на блоки
                blocks = split_into_blocks(ciphertext, BLOCK_SIZE_HEX)
                # Сравниваем второй блок с "эталонным"
                if blocks[1] == target_block:
                    flag += char
                    print(f"Найден символ: {char}, текущий флаг: {flag}")
                    found_char = True
                    # Если найден "закрывающий" символ - завершаем подбор
                    if char == "}":
                        return flag
                    break
            
            if not found_char:
                print("Не удалось найти следующий символ")
                break
    
    except KeyboardInterrupt:
        print("Выход")
    
    return flag


# Флаг: crypto{p3n6u1n5_h473_3cb}

if __name__ == "__main__":
    flag = find_flag()
    print(f"Флаг: {flag}")