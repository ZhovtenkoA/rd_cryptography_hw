import datetime


class MT19937:
    def __init__(self, seed):
        self.mt = [0] * 624
        self.mti = 624
        self.mt[0] = seed & 0xFFFFFFFF
        for i in range(1, 624):
            self.mt[i] = 1812433253 * (self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) + i
            self.mt[i] &= 0xFFFFFFFF

    def extract_number(self):
        if self.mti >= 624:
            self.twist()
        y = self.mt[self.mti]
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        self.mti += 1
        return y

    def twist(self):
        for i in range(624):
            x = (self.mt[i] & 0x80000000) + (self.mt[(i + 1) % 624] & 0x7FFFFFFF)
            xA = x >> 1
            if x % 2 != 0:
                xA = xA ^ 0x9908B0DF
            self.mt[i] = self.mt[(i + 397) % 624] ^ xA
        self.mti = 0


if __name__ == "__main__":
    mt = MT19937(int(datetime.datetime.now().timestamp()))
    print(mt.extract_number())
