
# CipherApp

A simple Python application using tkinter for the GUI and the cryptography library for encrypting and decrypting messages with RSA encryption.

## Features

- Generate RSA key pairs.
- Encrypt messages using a recipient's public key.
- Decrypt messages using your private key.
- Save your RSA private key securely.
- Load an RSA private key for decryption.

## Requirements

- Python 3
- tkinter
- cryptography

## Installation

Ensure you have Python 3 installed on your system.

Install the required Python packages using pip:

```
pip install cryptography tkinter
```

## Usage

Run the script using Python:

```
python main.py
```

Follow the GUI prompts to generate keys, encrypt, and decrypt messages.

## Generating Keys

- Click 'Generate Public Key' to create a new key pair.
- The public key will be displayed in the application.
- You will be prompted to save your private key to a secure location.

## Encrypting Messages

- Paste the recipient's public key into the designated text area.
- Type or paste the plaintext message into the main text area.
- Click 'Cipher' to encrypt the message.
- The ciphertext will be displayed in base64 format in the main text area.

## Decrypting Messages

- Click 'Decipher' after pasting the base64-encoded ciphertext into the main text area.
- You will be prompted to load your private key.
- After successful decryption, the plaintext message will be displayed in the main text area.

## Note

The application is for educational purposes and not intended for production use.
