import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


# Шляхи до ключів
PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH = "public_key.pem"

# Генерація ключів і збереження у файлах
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("Ключі успішно згенеровані та збережені.")

# Завантаження ключів
def load_keys():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return private_key, public_key

# Шифрування даних
def encrypt_data(public_key, data):
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# Підписання даних
def sign_data(private_key, data):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Розшифрування даних
def decrypt_data(private_key, encrypted_data):
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

# Перевірка підпису
def verify_signature(public_key, data, signature):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Читання вмісту файлу
def read_file(file_path):
    with open(file_path, "rb") as f:
        return f.read()

# Запис даних у файл
def write_file(file_path, data):
    with open(file_path, "wb") as f:
        f.write(data)

# Очищення змінних
def clear_sensitive_data(*args):
    for arg in args:
        if isinstance(arg, memoryview):
            del arg

# Функція для взаємодії з користувачем
def function_rsa():
    while True:
        try:
            # Вибір операції: шифрування, розшифрування або вихід
            print("\nОберіть операцію:")
            print("1: Шифрування")
            print("2: Розшифрування")
            print("3: Вийти")

            choice = input("Ваш вибір (1/3): ")

            if choice == "1":
                generate_keys()
                private_key, public_key = load_keys()
                # Отримання файлу для шифрування та перевірка його існування
                file_path = input("Введіть назву файлу для шифрування: ")
                if not os.path.exists(file_path):
                    print("Файл не знайдено. Спробуйте ще раз.")
                    continue

                data = read_file(file_path)
                # Шифрування даних та створення цифрового підпису
                encrypted = encrypt_data(public_key, data)
                signature = sign_data(private_key, data)
                # Збереження зашифрованих даних
                file_name, file_extension = os.path.splitext(file_path)
                save_encrypted_path = f"{file_name}_enc{file_extension}"
                if os.path.exists(save_encrypted_path):
                    new_file_name = input(
                        f"Файл '{save_encrypted_path}' вже існує! Введіть нове ім'я для файлу (без розширення): ")
                    save_encrypted_path = f"{new_file_name}_enc{file_extension}"
                write_file(save_encrypted_path, encrypted)
                print(f"Файл зашифровано та збережено як '{save_encrypted_path}'.")

                # Збереження цифрового підпису
                file_name, file_extension = os.path.splitext(file_path)
                save_signature_path = f"{file_name}_sig.txt"
                if os.path.exists(save_signature_path):
                    new_file_name = input(
                        f"Файл '{save_signature_path}' вже існує! Введіть нове ім'я для файлу (без розширення): ")
                    save_signature_path = f"{new_file_name}_sig.txt"
                write_file(save_signature_path, signature)
                print(f"Цифровий підпис збережено як '{save_signature_path}'.")
                clear_sensitive_data(private_key, public_key, encrypted, signature)

            elif choice == "2":
                # Завантаження ключів перед розшифруванням
                private_key, public_key = load_keys()
                # Запит на вибір зашифрованого файлу та підпису
                encrypted_file_path = input("Введіть ім'я зашифрованого файлу: ")
                if not os.path.exists(encrypted_file_path):
                    print("Зашифрований файл не знайдено. Спробуйте ще раз.")
                    continue
                signature_file_path = input("Введіть ім'я файлу з підписом: ")
                if not os.path.exists(signature_file_path):
                    print("Файл з підписом не знайдено. Спробуйте ще раз.")
                    continue
                # Розшифрування даних
                encrypted_data = read_file(encrypted_file_path)
                signature = read_file(signature_file_path)
                decrypted = decrypt_data(private_key, encrypted_data)
                filename, extension = os.path.splitext(encrypted_file_path)
                new_filename = filename.replace("_enc", "")
                # Перевірка наявності файлу з такою назвою
                if os.path.exists(f"{new_filename}{extension}"):
                    save_decrypted_path = input(
                        f"Файл '{new_filename}{extension}' вже існує. Введіть інше ім'я для збереження (або залиште порожнім для '{new_filename}_decrypted{extension}'): ")
                    if not save_decrypted_path:
                        save_decrypted_path = f"{new_filename}_decrypted{extension}"
                else:
                    save_decrypted_path = f"{new_filename}{extension}"
                write_file(save_decrypted_path, decrypted)

                # Перевірка підпису
                if verify_signature(public_key, decrypted, signature):
                    print("Підпис валідний.")
                else:
                    print("Підпис недійсний!")

                print(f"Розшифровані дані у файл {save_decrypted_path}")
                clear_sensitive_data(private_key, public_key, encrypted_data, signature, decrypted)

            elif choice == "3":
                print("Вихід із програми.")
                break
            else:
                print("Невірний вибір. Спробуйте ще раз.")
        except Exception as e:
            print(f"Сталася помилка: {e}")

function_rsa()
