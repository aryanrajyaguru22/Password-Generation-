import random
import string
import hashlib
import base64
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox, simpledialog


class PasswordGenerator:
    def __init__(self):
        # Character sets for password generation
        self.lowercase_chars = string.ascii_lowercase
        self.uppercase_chars = string.ascii_uppercase
        self.digit_chars = string.digits
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    def generate_password(self, length):
        # Validate password length
        if length < 8 or length > 16:
            raise ValueError("Password length must be between 8 and 16 characters")

        # Ensure at least one character from each character set
        password = [
            random.choice(self.lowercase_chars),
            random.choice(self.uppercase_chars),
            random.choice(self.digit_chars),
            random.choice(self.special_chars)
        ]

        # Fill the remaining length with random characters
        remaining_length = length - len(password)
        all_chars = (
                self.lowercase_chars +
                self.uppercase_chars +
                self.digit_chars +
                self.special_chars
        )

        password.extend(random.choice(all_chars) for _ in range(remaining_length))

        # Shuffle the password characters
        random.shuffle(password)

        return ''.join(password)


class PasswordEncryption:
    def __init__(self):
        # Generate a key for encryption
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)

    def encrypt_password(self, password):
        # Encrypt the password
        encrypted_password = self.cipher_suite.encrypt(password.encode())
        return encrypted_password

    def decrypt_password(self, encrypted_password):
        # Decrypt the password
        decrypted_password = self.cipher_suite.decrypt(encrypted_password)
        return decrypted_password.decode()


class PasswordApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Strong Password Generator")
        self.root.geometry("500x400")

        # Initialize password generator and encryption
        self.password_generator = PasswordGenerator()
        self.password_encryption = PasswordEncryption()

        # Create UI Components
        self.create_ui()

    def create_ui(self):
        # Password Length Input
        tk.Label(self.root, text="Enter Password Length (8-16):").pack(pady=10)
        self.length_entry = tk.Entry(self.root)
        self.length_entry.pack(pady=5)

        # Generate Password Button
        generate_btn = tk.Button(
            self.root,
            text="Generate Password",
            command=self.generate_and_encrypt_password
        )
        generate_btn.pack(pady=10)

        # Display Generated Password
        self.password_display = tk.Text(
            self.root,
            height=5,
            width=50,
            state='disabled'
        )
        self.password_display.pack(pady=10)

        # Decrypt Password Button
        decrypt_btn = tk.Button(
            self.root,
            text="Decrypt Password",
            command=self.decrypt_password
        )
        decrypt_btn.pack(pady=10)

    def generate_and_encrypt_password(self):
        try:
            # Get password length
            length = int(self.length_entry.get())

            # Generate password
            password = self.password_generator.generate_password(length)

            # Encrypt password
            encrypted_password = self.password_encryption.encrypt_password(password)

            # Display results
            self.update_password_display(
                f"Generated Password: {password}\n"
                f"Encrypted Password: {encrypted_password.decode()}\n"
                f"Encryption Key: {self.password_encryption.key.decode()}"
            )

        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def decrypt_password(self):
        # Prompt user for encrypted password and key
        encrypted_pwd = simpledialog.askstring(
            "Decrypt",
            "Enter Encrypted Password:"
        )
        encryption_key = simpledialog.askstring(
            "Decrypt",
            "Enter Encryption Key:"
        )

        try:
            # Set the encryption key
            self.password_encryption.cipher_suite = Fernet(encryption_key.encode())

            # Decrypt password
            decrypted_password = self.password_encryption.decrypt_password(
                encrypted_pwd.encode()
            )

            # Display decrypted password
            messagebox.showinfo(
                "Decrypted Password",
                f"Decrypted Password: {decrypted_password}"
            )

        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def update_password_display(self, message):
        self.password_display.config(state='normal')
        self.password_display.delete('1.0', tk.END)
        self.password_display.insert(tk.END, message)
        self.password_display.config(state='disabled')


def main():
    root = tk.Tk()
    app = PasswordApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()