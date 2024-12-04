import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass
import json
import re

# Створення унікального імені для файлу, щоб уникнути перезапису існуючих файлів
def create_unique_filename(filename):
    base_name, ext = os.path.splitext(filename)
    directory = os.path.dirname(filename) if os.path.dirname(filename) else os.getcwd()

    # Перевірка наявності файлів з подібними іменами
    if os.path.exists(filename):
        pattern = re.compile(rf"^{re.escape(base_name)}\((\d+)\){re.escape(ext)}$")
        existing_files = [f for f in os.listdir(directory) if pattern.match(f)]
        if existing_files:
            numbers = [int(pattern.match(f).group(1)) for f in existing_files]
            new_number = max(numbers) + 1
        else:
            new_number = 1
        new_filename = f"{base_name}({new_number}){ext}"

        # Перевірка, чи нове ім'я файлу вже існує
        while os.path.exists(os.path.join(directory, new_filename)):
            new_number += 1
            new_filename = f"{base_name}({new_number}){ext}"

        return new_filename
    else:
        # Якщо файл не існує, повертається оригінальне ім'я
        return filename

# Генерація AES-ключа за допомогою пароля та солі
def generate_aes_key(password: bytes, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

# Шифрування файлу за допомогою AES
def encrypt_aes(file_path, password):
    try:
        # Генерація випадкової солі
        # Генерація випадкового ініціалізаційного вектора (IV)
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = generate_aes_key(password, salt)

        with open(file_path, 'rb') as f:
            data = f.read()

        # Додавання паддінгу до даних
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        # Шифрування даних за допомогою AES у режимі CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Генерація HMAC для перевірки цілісності даних
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(encrypted_data)
        mac = h.finalize()

        # Формування зашифрованого вмісту у вигляді JSON
        encrypted_content = {
            "salt": salt.hex(),
            "iv": iv.hex(),
            "mac": mac.hex(),
            "encrypted_data": encrypted_data.hex()
        }

        file_name = f"{file_path}.aes"
        file_name = create_unique_filename(file_name)

        if file_name == f"{file_path}.aes":
            with open(file_name, 'w') as f:
                json.dump(encrypted_content, f)
        else:
            with open(file_name, 'w') as f:
                json.dump(encrypted_content, f)
        print(f"Файл '{file_path}' успішно зашифровано і збережено як '{file_name}'!")

    finally:
        # Очищення секретних змінних
        del key, salt, iv, encrypted_data, mac, password

# Дешифрування файлу за допомогою AES
def decrypt_aes(encrypted_file_path, password):
    try:
        # Завантаження зашифрованих даних із JSON
        with open(encrypted_file_path, 'r') as f:
            encrypted_content = json.load(f)

        # Перетворення даних із шістнадцяткових рядків назад у байти
        salt = bytes.fromhex(encrypted_content["salt"])
        iv = bytes.fromhex(encrypted_content["iv"])
        mac = bytes.fromhex(encrypted_content["mac"])
        encrypted_data = bytes.fromhex(encrypted_content["encrypted_data"])

        # Відновлення ключа для дешифрування
        key = generate_aes_key(password, salt)

        # Перевірка цілісності даних за допомогою HMAC
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(encrypted_data)
        h.verify(mac)

        # Дешифрування даних
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Видалення паддінгу після дешифрування
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        # Збереження дешифрованих даних
        file_path = encrypted_file_path.rsplit('.aes', 1)[0]

        if os.path.exists(file_path):
            print(f"Файл '{file_path}' вже існує! Будь ласка, переназвіть файл.")
        else:
            with open(file_path, 'wb') as f:
                f.write(data)
                print(f"Файл успішно дешифровано і збережено як '{file_path}'!")
    finally:
        # Очищення секретних змінних
        del key, salt, iv, encrypted_data, mac, password

# Функція для взаємодії з користувачем
def function_aes():
    while True:
        # Вибір операції: шифрування, розшифрування або вихід
        try:
            print("Оберіть операцію:")
            print("1: Шифрування")
            print("2: Дешифрування")
            print("3: Вийти")
            choice = input("Ваш вибір (1/3): ")

            # Шифрування
            if choice == "1":
                file_path = input("Введіть назву файлу для шифрування: ")
                if not os.path.exists(file_path):
                    print("Файл не знайдено. Спробуйте ще раз.")
                    continue
                password = getpass("Введіть пароль: ").encode()
                encrypt_aes(file_path, password)
                del password
            # Дешифрування
            elif choice == "2":
                file_path = input("Введіть ім'я зашифрованого файлу: ")
                password = getpass("Введіть пароль: ").encode()
                if not os.path.exists(file_path):
                    print("Файл не знайдено. Спробуйте ще раз.")
                    continue
                decrypt_aes(file_path, password)
                del password
            elif choice == "3":
                print("Вихід із програми.")
                break
            else:
                print("Невірний вибір. Спробуйте ще раз.")
        except Exception as e:
            print(f"Сталася помилка: {e}")

function_aes()
