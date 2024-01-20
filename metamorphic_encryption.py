from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from apscheduler.schedulers.background import BackgroundScheduler
import time


class MetamorphicEncryption:
    def __init__(self):
        self.key = self.generate_key()
        self.store_key(self.key)  # Store the key in a file
        self.failure_count = 0
        self.max_failure_threshold = 2  # Set the maximum number of decryption failures allowed
        self.scheduler = BackgroundScheduler()
        self.scheduler.add_job(self.rotate_key, 'interval', hours=1)
        self.scheduler.start()

    def generate_key(self):
        # Generate a random key for encryption
        return b'0123456789ABCDEF'  # Replace with a secure random key generation

    def rotate_key(self):
        # Rotate the encryption key at set intervals
        self.key = self.generate_key()

    def encrypt(self, plaintext):
        padder = padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return ciphertext

    def store_key(self, key):
        with open('encryption_key.key', 'wb') as key_file:
            key_file.write(key)

    def load_key(self):
        with open('encryption_key.key', 'rb') as key_file:
            key = key_file.read()
        return key

    def decrypt(self, ciphertext):
        try:
            key = self.load_key()  # Load the key from the file
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            self.failure_count = 0  # Reset the failure count after a successful decryption
            return plaintext
        except Exception as e:
            self.failure_count += 1  # Increment the failure count after a failed decryption
            if self.failure_count >= self.max_failure_threshold:
                ciphertext = b''  # Self-destruct the message
                print("The message has been self-destructed after two failed decryption attempts.")
            else:
                print(f"Decryption failed: {str(e)}. Attempt {self.failure_count} of {self.max_failure_threshold}.")
            return None


# Create an instance of the MetamorphicEncryption class
crypto_system = MetamorphicEncryption()

# Encrypt a message
message = b"Hello, Bob!"  # The message must be a bytes-like object
encrypted_message = crypto_system.encrypt(message)
print(f"Encrypted Message: {encrypted_message}")

# Decrypt the message
decrypted_message = crypto_system.decrypt(encrypted_message)
print(f"Decrypted Message: {decrypted_message}")
