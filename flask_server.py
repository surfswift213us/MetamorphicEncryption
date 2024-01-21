from flask import Flask, request, jsonify
from flask_talisman import Talisman
from encryption_metamorphic import MetamorphicEncryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import binascii

app = Flask(__name__)
class ServerConversation:
    def __init__(self):
        self.parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        self.private_key = self.parameters.generate_private_key()
        self.session_key = None

    def get_public_key(self):
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def derive_session_key(self, client_public_key):
        shared_key = self.private_key.exchange(
            serialization.load_pem_public_key(client_public_key, backend=default_backend())
        )

        # Use HKDF to derive a session key from the shared key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        )

        self.session_key = hkdf.derive(shared_key)

server_conversation = ServerConversation()

@app.route('/initiate_key_exchange', methods=['GET'])
def initiate_key_exchange():
    public_key_server = server_conversation.get_public_key()
    return jsonify({'public_key': public_key_server})

# Path: encryption_client.py
crypto_system = MetamorphicEncryption()

parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
private_key_server = parameters.generate_private_key()
public_key_server = private_key_server.public_key().public_bytes(
encoding=serialization.Encoding.PEM,
format=serialization.PublicFormat.SubjectPublicKeyInfo
)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    message = data['message']

    # Convert the message to bytes
    message_bytes = message.encode('utf-8')

    # Encrypt the message
    encrypted_message_bytes = crypto_system.encrypt(message_bytes)

    # Convert the encrypted message to a base64 string
    encrypted_message = base64.b64encode(encrypted_message_bytes).decode('utf-8')

    return jsonify({'encrypted_message': encrypted_message})

decryption_attempts = {}
@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    ciphertext_hex = data['ciphertext_hex']

    # If this is the third attempt to decrypt the message, destroy the message
    if decryption_attempts.get(ciphertext_hex, 0) >= 2:
        del decryption_attempts[ciphertext_hex]
        return jsonify({'status': 'Message destroyed after two unsuccessful attempts'}), 403

    # Check if the input is correctly padded
    missing_padding = len(ciphertext_hex) % 4
    if missing_padding:
        ciphertext_hex += '='* (4 - missing_padding)

    # Convert the base64 string back to bytes
    try:
        encrypted_message_bytes = base64.b64decode(ciphertext_hex)
    except binascii.Error as e:
        return jsonify({'status': 'Decryption failed, invalid base64-encoded string'}), 400

    try:
        # Decrypt the message
        decrypted_message_bytes = crypto_system.decrypt(encrypted_message_bytes)

        # Convert the decrypted message bytes back to a string
        decrypted_message = decrypted_message_bytes.decode('utf-8')

        # If decryption is successful, reset the number of attempts for this message
        decryption_attempts[ciphertext_hex] = 0

        return jsonify({'decrypted_message': decrypted_message})
    except Exception as e:
        # If decryption fails, increment the number of attempts for this message
        decryption_attempts[ciphertext_hex] = decryption_attempts.get(ciphertext_hex, 0) + 1
        return jsonify({'status': 'Decryption failed'}), 400

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    message = data['message']

    # Encrypt the message
    crypto_system.encrypt(message)

    # Send the encrypted message to the receiver (You need to implement this part)
    # Example: You can use a database to store messages and implement a mechanism for retrieval.

    return jsonify({'status': 'Message sent successfully'})

talisman = Talisman(app)

if __name__ == '__main__':
    app.run(debug=True, ssl_context=(r'cert.pem', r'key.pem'))
