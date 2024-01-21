import requests
from encryption_metamorphic import MetamorphicEncryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization


crypto_system = MetamorphicEncryption()

class ClientConversation:
    def __init__(self):
        self.session_key = None

    def initiate_key_exchange(self):
        response = requests.get('https://localhost:5000/initiate_key_exchange')
        data = response.json()
        public_key_server = data['public_key']

        # Derive the session key for this conversation
        shared_key = crypto_system.derive_shared_key(public_key_server)
        self.session_key = some_kdf_function(shared_key)

client_conversation = ClientConversation()

def send_message(sender, receiver, message):
    # Initiate key exchange
    client_conversation.initiate_key_exchange()

    # Encrypt the message using the derived session key
    encrypted_message = crypto_system.encrypt(message, key=client_conversation.session_key)

    # Send the encrypted message to the server
    url = 'https://localhost:5000/send_message'
    data = {'client_public_key': client_conversation.get_public_key(), 'message': encrypted_message}
    response = requests.post(url, json=data, verify='cert.pem')

    print(response.json())

if __name__ == '__main__':
    send_message(sender='Alice', receiver='Bob', message='Hello, Bob!')
