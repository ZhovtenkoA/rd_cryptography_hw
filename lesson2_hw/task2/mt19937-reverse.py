import random
from encrypt import decrypt

class MT19937Reverse:
    """Reverses the Mersenne Twister based on 624 observed outputs.

    The internal state of a Mersenne Twister can be recovered by observing
    624 generated outputs of it. However, if those are not directly
    observed following a twist, another output is required to restore the
    internal index.

    See also https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode .

    """

    def unshiftRight(self, x, shift):
        res = x
        for i in range(32):
            res = x ^ res >> shift
        return res

    def unshiftLeft(self, x, shift, mask):
        res = x
        for i in range(32):
            res = x ^ (res << shift & mask)
        return res

    def untemper(self, v):
        """Reverses the tempering which is applied to outputs of MT19937"""

        v = self.unshiftRight(v, 18)
        v = self.unshiftLeft(v, 15, 0xEFC60000)
        v = self.unshiftLeft(v, 7, 0x9D2C5680)
        v = self.unshiftRight(v, 11)
        return v

    def reverse(self, outputs, forward=True):
        """Reverses the Mersenne Twister based on 624 observed values.

        Args:
            outputs (List[int]): list of >= 624 observed outputs from the PRNG.
                However, >= 625 outputs are required to correctly recover
                the internal index.
            forward (bool): Forward internal state until all observed outputs
                are generated.

        Returns:
            Returns a random.Random() object.
        """

        result_state = None

        assert len(outputs) >= 624  # need at least 624 values

        ivals = []
        for i in range(624):
            ivals.append(self.untemper(outputs[i]))

        if len(outputs) >= 625:
            # We have additional outputs and can correctly
            # recover the internal index by bruteforce
            challenge = outputs[624]
            for i in range(1, 626):
                state = (3, tuple(ivals + [i]), None)
                r = random.Random()
                r.setstate(state)

                if challenge == r.getrandbits(32):
                    result_state = state
                    break
        else:
            # With only 624 outputs we assume they were the first observed 624
            # outputs after a twist -->  we set the internal index to 624.
            result_state = (3, tuple(ivals + [624]), None)

        rand = random.Random()
        rand.setstate(result_state)

        if forward:
            for i in range(624, len(outputs)):
                assert rand.getrandbits(32) == outputs[i]

        return rand




with open("lesson2_hw\\task2\\sequence.txt", "r") as f:
    content = f.read().strip() 
    content = content[1:-1] 
    sequence = [int(num) for num in content.split(", ")] 

print(f"Количество в последовательности: {len(sequence)}")


# Возвращаем внутреннее состояние генератора
reverser = MT19937Reverse()
recovered_rng = reverser.reverse(sequence)


with open("lesson2_hw\\task2\\data.bmp.enc", "rb") as f:
    encrypted_data = f.read()

# Цикл поиска ключа
for i in range(640):  # перебираем 640 вариантов, к примеру
    key = recovered_rng.getrandbits(128)
    key_hex = f"0x{key:032x}"
    print(f"Попытка {i + 1}: Ключ = {key_hex}")
    try:
        decrypted_data = decrypt("lesson2_hw\\task2\\data.bmp.enc", key)
    except Exception as e:
        print(f"Ошибка расшифровки: {e}")
        continue

    # Проверка первых двух байтов
    if decrypted_data[:2] == b'BM':
        print("правильный ключ найден!")
        print(f"Ключ: {key_hex}")

        with open("data.bmp", "wb") as f:
            f.write(decrypted_data)

        with open("key.txt", "w") as f:
            f.write(key_hex)

        break
else:
    print("Ключ не найден, увеличьте диапазон поиска")