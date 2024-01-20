from flask import Flask, request, jsonify
from flask_talisman import Talisman
from encryption_metamorphic import MetamorphicEncryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

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
        # Use a key derivation function (KDF) to derive a session key from the shared key
        self.session_key = some_kdf_function(shared_key)

server_conversation = ServerConversation()

@app.route('/initiate_key_exchange', methods=['GET'])
def initiate_key_exchange():
    public_key_server = server_conversation.get_public_key()
    return jsonify({'public_key': public_key_server})

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    client_public_key = data['client_public_key']

    # Derive the session key for this conversation
    server_conversation.derive_session_key(client_public_key)

    # Now you have the session key, and you can use it for encryption/decryption
    encrypted_message = crypto_system.encrypt(data['message'], key=server_conversation.session_key)

    # Send the encrypted message to the receiver (You need to implement this part)
    # Example: You can use a database to store messages and implement a mechanism for retrieval.

    return jsonify({'status': 'Message sent successfully'})

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('ca-cert.pem', 'ca-key.pem'))

# Path: encryption_client.py
crypto_system = MetamorphicEncryption()

parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
private_key_server = parameters.generate_private_key()
public_key_server = private_key_server.public_key().public_bytes(
encoding=serialization.Encoding.PEM,
format=serialization.PublicFormat.SubjectPublicKeyInfo
)
@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    message = data['message']

    # Encrypt the message
    encrypted_message = crypto_system.encrypt(message)

    # Send the encrypted message to the receiver (You need to implement this part)
    # Example: You can use a database to store messages and implement a mechanism for retrieval.

    return jsonify({'status': 'Message sent successfully'})

talisman = Talisman(app)

if __name__ == '__main__':
    app.run(debug=True, ssl_context=(r'ca-cert.pem', r'ca-key.pem'))
