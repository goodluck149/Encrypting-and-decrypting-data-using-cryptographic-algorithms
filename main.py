from subprocess import call

def main():
    while True:
        print("Виберіть алгоритм з наведених варіантів:")
        print("1. AES")
        print("2. RSA")
        print("3. Вийти з програми")
        try
            choice = input("Ваш вибір (1, 2, 3): ")
        except KeyboardInterrupt:
            print("\nПрограма була перервана користувачем.")
            break
        if choice == '1':
            call(["python", "aes.py"])
        elif choice == '2':
            call(["python", "rsa.py"])
        elif choice == '3':
            print("Вихід з програми...")
            break
        else:
            print("Невірний вибір. Спробуйте ще раз.\n")

if __name__ == "__main__":
    main()
