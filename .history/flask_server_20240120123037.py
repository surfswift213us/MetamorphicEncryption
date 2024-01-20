from flask import Flask, request, jsonify
from flask_talisman import Talisman
from encryption_metamorphic import MetamorphicEncryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)









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
