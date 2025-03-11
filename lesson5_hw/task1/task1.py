import bcrypt

password_1 = "qwertyuiop"
password_2 = "sofPed-westag-jejzo1"
password_3 = "f3Fg#Puu$EA1mfMx2"
password_4 = "TIMCfJDkKBRm9/zwcFbHhE6zaMcSxR7nke1mJKcVqXpvCzg69d7Mf2quanMoAfmPJXyqT4gyGpLoL1lTHoqmwVmaUwrpOPRecB8GAU17eUJJHiksv3qrqcVxhgpMkX/UlKaLdFSwFIr7cVoJmBqQ/buWzxJNCIo7qbtIi3fSi62NwMHh"


"""

Выбор метода хэширования - bcrypt.
Как по мне, должен хорошо справлятся с хэшированием паролей разной сложности (с разным уровнем энтропии)
Использует соль для каждого пароля
Параметр rounds отвечает за количество итераций для генерации хэша (12 = 2^12 итераций)

"""


passwords_list = [password_1, password_2, password_3, password_4]


hashed_passwords = []
for p in passwords_list:
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(p.encode('utf-8'), salt)
    hashed_passwords.append(hashed.decode('utf-8'))


with open("hashed_passwords.txt", "w") as file:
    for hashed in hashed_passwords:
        file.write(hashed + "\n")