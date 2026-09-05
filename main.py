from classical import run_substitution_cipher, run_double_transposition
from des import run_des
from aes import run_aes
from rsa_final import run_rsa
from ecc import run_ecc


def classical_section():
    while True:
        print("\n-- Classical Cryptography --")
        print("1. Substitution Cipher")
        print("2. Double Transposition Cipher")
        print("3. Back")
        choice = input("Choice: ").strip()

        if choice == "1":
            run_substitution_cipher()
        elif choice == "2":
            run_double_transposition()
        elif choice == "3":
            break
        else:
            print("Invalid choice, pick 1 to 3.")


def symmetric_section():
    while True:
        print("\n-- Symmetric-Key Cryptography --")
        print("1. DES")
        print("2. AES")
        print("3. Back")
        choice = input("Choice: ").strip()

        if choice == "1":
            run_des()
        elif choice == "2":
            run_aes()
        elif choice == "3":
            break
        else:
            print("Invalid choice, pick 1 to 3.")


def public_key_section():
    while True:
        print("\n-- Public-Key Cryptography --")
        print("1. RSA")
        print("2. ECC + ECDH")
        print("3. Back")
        choice = input("Choice: ").strip()

        if choice == "1":
            run_rsa()
        elif choice == "2":
            run_ecc()
        elif choice == "3":
            break
        else:
            print("Invalid choice, pick 1 to 3.")


def main():
    while True:
        print("\n========== MAIN MENU ==========")
        print("Choose between 1 to 4")
        print("1. Classical Cryptography")
        print("2. Symmetric-Key Cryptography")
        print("3. Public-Key Cryptography")
        print("4. Exit")
        print("================================")
        choice = input("Enter choice: ").strip()

        if choice == "1":
            classical_section()
        elif choice == "2":
            symmetric_section()
        elif choice == "3":
            public_key_section()
        elif choice == "4":
            print("Exit")
            break
        else:
            print("Invalid choice, pick 1 to 4.")


main()