import requests
from metamorphic_encryption import MetamorphicEncryption

crypto_system = MetamorphicEncryption()

def send_message(sender, receiver, message):
    # Encrypt the message
    encrypted_message = crypto_system.encrypt(message)

    # Send the encrypted message to the server
    url = 'https://localhost:5000/send_message'  # Update with your server's URL
    data = {'sender': sender, 'receiver': receiver, 'message': encrypted_message}
    response = requests.post(url, json=data, verify='C:\Users\MainFrame\')

    print(response.json())

if __name__ == '__main__':
    send_message(sender='Alice', receiver='Bob', message='Hello, Bob!')