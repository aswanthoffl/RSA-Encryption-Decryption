import os
from flask import Flask, render_template, request

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet

app = Flask(__name__)

def generate_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return public_key, private_key

def encrypt_file(input_filename, output_filename, public_key):
    symmetric_key = Fernet.generate_key()

    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key[:32]), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(b'') + encryptor.update(open(input_filename, 'rb').read()) + encryptor.finalize()

    output_directory = os.path.dirname(os.path.abspath(output_filename))
    os.makedirs(output_directory, exist_ok=True)

    with open(output_filename, 'wb') as file:
        file.write(encrypted_symmetric_key)
        file.write(iv)
        file.write(ciphertext)

def decrypt_file(input_filename, output_filename, private_key):
    with open(input_filename, 'rb') as file:
        encrypted_symmetric_key = file.read(private_key.key_size // 8)
        iv = file.read(16)
        ciphertext = file.read()

    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(symmetric_key[:32]), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    output_directory = os.path.dirname(os.path.abspath(output_filename))
    os.makedirs(output_directory, exist_ok=True)

    with open(output_filename, 'wb') as file:
        file.write(plaintext)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file = request.files["file"]
        if file:
            public_key, private_key = generate_keypair()

            input_filename = os.path.join("uploads", file.filename)
            encrypted_filename = os.path.join("uploads", "encrypted_" + file.filename)
            decrypted_filename = os.path.join("uploads", "decrypted_" + file.filename)

            file.save(input_filename)

            encrypt_file(input_filename, encrypted_filename, public_key)
            decrypt_file(encrypted_filename, decrypted_filename, private_key)

            return render_template("index.html", encrypted_filename=encrypted_filename, decrypted_filename=decrypted_filename)

    return render_template("index.html")

if __name__ == "__main__":
    os.makedirs("uploads", exist_ok=True)
    app.run(debug=True)

