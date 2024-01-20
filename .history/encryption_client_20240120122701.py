import requests
from encryption_metamorphic import MetamorphicEncryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
crypto_system = MetamorphicEncryption()

public_key_client = deserialize_received_public_key()  # Implement a function to deserialize the received key
private_key_client = parameters.generate_private_key()
shared_key = private_key_client.exchange(public_key_client)

def send_message(sender, receiver, message):
    # Encrypt the message
    encrypted_message = crypto_system.encrypt(message)

    # Send the encrypted message to the server
    url = 'https://localhost:5000/send_message'  # Update with your server's URL
    data = {'sender': sender, 'receiver': receiver, 'message': encrypted_message}
    response = requests.post(url, json=data, verify='ca-cert.pem')

    print(response.json())

if __name__ == '__main__':
    send_message(sender='Alice', receiver='Bob', message='Hello, Bob!')