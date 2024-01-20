import tkinter as tk
from encryption_metamorphic import MetamorphicEncryption
from tkinter import simpledialog
from tkinter import messagebox
import requests

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Encryption Application")

        # Create GUI elements
        self.label = tk.Label(master, text="Enter Message:")
        self.message_entry = tk.Entry(master, width=30)
        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt_message)
        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt_message)

        # Layout GUI elements
        self.label.pack(pady=10)
        self.message_entry.pack(pady=10)
        self.encrypt_button.pack(pady=5)
        self.decrypt_button.pack(pady=5)

        # Create an instance of the MetamorphicEncryption class
        self.crypto_system = MetamorphicEncryption()

    def encrypt_message(self):
        message = self.message_entry.get()
        response = requests.post('http://127.0.0.1:5000/encrypt', json={"message": message})
        result = response.json()
        messagebox.showinfo("Encrypted Message", f"Encrypted Message: {result['encrypted_message']}")

    def decrypt_message(self):
        ciphertext_hex = simpledialog.askstring("Decryption", "Enter Encrypted Message (in hexadecimal):")
        try:
            response = requests.post('http://127.0.0.1:5000/decrypt', json={"ciphertext_hex": ciphertext_hex})
            result = response.json()
            decrypted_message = result.get('decrypted_message')
            if decrypted_message:
                messagebox.showinfo("Decrypted Message", f"Decrypted Message: {decrypted_message}")
            elif 'error' in result:
                messagebox.showerror("Error", result['error'])
        except ValueError:
            messagebox.showerror("Error", "Invalid hexadecimal input.")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()