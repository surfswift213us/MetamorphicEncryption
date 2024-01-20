import tkinter as tk

from tkinter import messagebox

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
        message = self.message_entry.get().encode('utf-8')
        encrypted_message = self.crypto_system.encrypt(message)
        messagebox.showinfo("Encrypted Message", f"Encrypted Message: {encrypted_message.hex()}")

    def decrypt_message(self):
        ciphertext_hex = messagebox.askstring("Decryption", "Enter Encrypted Message (in hexadecimal):")
        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
            decrypted_message = self.crypto_system.decrypt(ciphertext)
            if decrypted_message:
                messagebox.showinfo("Decrypted Message", f"Decrypted Message: {decrypted_message.decode('utf-8')}")
        except ValueError:
            messagebox.showerror("Error", "Invalid hexadecimal input.")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
