from flask import Flask, request, jsonify
from metamorphic_encryption import MetamorphicEncryption

app = Flask(__name__)
crypto_system = MetamorphicEncryption()

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    sender = data['sender']
    receiver = data['receiver']
    message = data['message']

    # Encrypt the message
    encrypted_message = crypto_system.encrypt(message)

    # Send the encrypted message to the receiver (You need to implement this part)
    # Example: You can use a database to store messages and implement a mechanism for retrieval.

    return jsonify({'status': 'Message sent successfully'})

if __name__ == '__main__':
    app.run(debug=True)
