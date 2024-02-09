import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64

class CipherApp:
    def __init__(self, master):
        self.master = master
        master.title("Cipher App")

        # Label for text input
        self.label_text_area = tk.Label(master, text="Text to cipher/decipher:")
        self.label_text_area.pack()

        # Text input area
        self.text_area = tk.Text(master, height=10, width=50)
        self.text_area.pack()

        # Cipher/Decipher Buttons
        self.cipher_button = tk.Button(master, text="Cipher", command=self.cipher_message)
        self.cipher_button.pack(side=tk.LEFT)

        self.decipher_button = tk.Button(master, text="Decipher", command=self.decipher_message)
        self.decipher_button.pack(side=tk.RIGHT)

        # Generate Public Key Button and Display Area
        self.generate_key_button = tk.Button(master, text="Generate Public Key", command=self.generate_keys)
        self.generate_key_button.pack()

        self.public_key_display = tk.Text(master, height=5, width=50)
        self.public_key_display.pack()

        # Label for public key input
        self.label_public_key = tk.Label(master, text="Recipient's Public Key (for ciphering):")
        self.label_public_key.pack()

        # Public key input
        self.public_key_input = tk.Text(master, height=5, width=50)
        self.public_key_input.pack()

    def generate_keys(self):
        # Generate a new RSA key pair
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.public_key = self.private_key.public_key()

        # Display the public key
        pub_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key_display.delete(1.0, tk.END)  # Clear previous key if any
        self.public_key_display.insert(tk.END, pub_key_pem.decode('utf-8'))

        # Ask the user to save the private key
        self.save_private_key()

    def save_private_key(self):
        # Serialize the private key to PEM format
        priv_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')  # Use a strong, user-provided password
        )
        
        # Prompt user to save the private key file
        file_path = filedialog.asksaveasfilename(defaultextension=".pem", title="Save your private key", filetypes=[("PEM files", "*.pem")])
        if file_path:  # Check if the user selected a file path
            with open(file_path, 'wb') as f:
                f.write(priv_key_pem)
            messagebox.showinfo("Key Saved", "Your private key has been saved securely.")
        else:
            messagebox.showwarning("Key Not Saved", "Your private key was not saved. You will need it to decrypt messages.")


    def cipher_message(self):
    # Get the recipient's public key from the input
        recipient_pub_key_pem = self.public_key_input.get(1.0, tk.END)
        try:
            recipient_pub_key = serialization.load_pem_public_key(
                recipient_pub_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            # Cipher the message
            plaintext = self.text_area.get(1.0, tk.END).encode('utf-8')
            ciphertext = recipient_pub_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Encode ciphertext in base64 to safely display it
            b64_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
            self.text_area.delete(1.0, tk.END)  # Clear the text area
            self.text_area.insert(tk.END, b64_ciphertext)
        except Exception as e:
            messagebox.showerror("Error", "Failed to cipher message: " + str(e))

    def load_private_key(self):
        # Prompt user to select the private key file
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if not file_path:
            messagebox.showerror("Error", "No file selected")
            return None
        try:
            with open(file_path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=b'mypassword',  # Prompt the user for the password
                    backend=default_backend()
                )
            return private_key
        except Exception as e:
            messagebox.showerror("Error", "Failed to load the private key: " + str(e))
            return None

    def decipher_message(self):
        private_key = self.load_private_key()
        if private_key is None:
            return  # No private key loaded, can't decrypt

        # The ciphertext should be base64-encoded, so decode it before decryption
        b64_ciphertext = self.text_area.get(1.0, tk.END)
        try:
            ciphertext = base64.b64decode(b64_ciphertext.encode('utf-8'))
            # Decipher the message
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Display the decrypted message
            self.text_area.delete(1.0, tk.END)  # Clear the text area
            self.text_area.insert(tk.END, plaintext.decode('utf-8'))
        except Exception as e:
            messagebox.showerror("Error", "Failed to decipher message: " + str(e))

root = tk.Tk()
app = CipherApp(root)
root.mainloop()
