import tkinter as tk
from encryption_metamorphic import MetamorphicEncryption
from tkinter import simpledialog
import requests
from tkinter import messagebox
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class EncryptionApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Encryption Application")
        self.failed_attempts = 0
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
        try:
            message = self.message_entry.get()
            response = requests.post('https://localhost:5000/encrypt', json={'message': message},cert=('cert.pem', 'key.pem'), verify=False)
            if response.status_code == 200:
                encrypted_message = response.json()['encrypted_message']
                messagebox.showinfo("Encrypted Message", f"Encrypted Message: {encrypted_message}")
            else:
                messagebox.showerror("Error", "Failed to encrypt message.")
        except requests.exceptions.ConnectionError as e:
            print(f"Failed to connect to server: {e}")

    def decrypt_message(self):
        try:
            ciphertext_hex = simpledialog.askstring("Decryption", "Enter Encrypted Message (in hexadecimal):")
            response = requests.post('https://localhost:5000/decrypt', json={'ciphertext_hex': ciphertext_hex}, cert=('cert.pem', 'key.pem'), verify=False)
            if response.status_code == 200:
                decrypted_message = response.json()['decrypted_message']
                messagebox.showinfo("Decrypted Message", f"Decrypted Message: {decrypted_message}")
                self.failed_attempts = 0  # Reset the counter if decryption is successful
            else:
                self.failed_attempts += 1  # Increment the counter if decryption fails
                if self.failed_attempts >= 2:
                    messagebox.showinfo("Message Destroyed", "The message has been destroyed after two failed decryption attempts.")
                    # Here you can add code to destroy the message
                else:
                    messagebox.showerror("Error", "Failed to decrypt message.")
        except requests.exceptions.ConnectionError as e:
            print(f"Failed to connect to server: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()