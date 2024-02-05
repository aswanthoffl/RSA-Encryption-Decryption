import os
from flask import Flask, render_template, request, session, send_file
from flask_session import Session
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from io import BytesIO

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'  # Use the filesystem for session storage
app.config['SESSION_PERMANENT'] = False
Session(app)

def generate_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    return public_key, private_key_pem

def encrypt_file(input_filename, public_key):
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

    encrypted_data = {
        "encrypted_symmetric_key": encrypted_symmetric_key,
        "iv": iv,
        "ciphertext": ciphertext
    }

    return encrypted_data

def decrypt_file(encrypted_data, private_key):
    symmetric_key = private_key.decrypt(
        encrypted_data["encrypted_symmetric_key"],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(symmetric_key[:32]), modes.CFB(encrypted_data["iv"]))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(encrypted_data["ciphertext"]) + decryptor.finalize()

    return plaintext

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file = request.files["file"]
        if file:
            public_key, private_key_pem = generate_keypair()

            input_filename = os.path.join("uploads", file.filename)

            file.save(input_filename)

            # Encrypt the file and store encryption details in session
            encrypted_data = encrypt_file(input_filename, public_key)
            session["private_key_pem"] = private_key_pem
            session["encrypted_data"] = encrypted_data

            return render_template("index.html", encrypted_link="/download/encrypted", decrypted_link=None)

    return render_template("index.html", encrypted_link=None, decrypted_link=None)

@app.route("/decrypt", methods=["POST"])
def decrypt():
    private_key_pem = session.get("private_key_pem")
    encrypted_data = session.get("encrypted_data")

    if private_key_pem and encrypted_data:
        # Deserialize the private key from PEM format
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )

        decrypted_data = decrypt_file(encrypted_data, private_key)
        decrypted_filename = os.path.join("uploads", "decrypted_" + os.path.basename(input_filename))

        with open(decrypted_filename, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        return render_template("index.html", encrypted_link="/download/encrypted", decrypted_link="/download/decrypted")

    return render_template("index.html", encrypted_link=None, decrypted_link=None)

@app.route("/download/encrypted")
def download_encrypted():
    encrypted_data = session.get("encrypted_data", {})

    encrypted_data_bytes = BytesIO()
    encrypted_data_bytes.write(encrypted_data.get("encrypted_symmetric_key", b""))
    encrypted_data_bytes.write(encrypted_data.get("iv", b""))
    encrypted_data_bytes.write(encrypted_data.get("ciphertext", b""))

    encrypted_data_bytes.seek(0)

    return send_file(
        encrypted_data_bytes,
        as_attachment=True,
        download_name="encrypted_file"
    )

@app.route("/download/decrypted")
def download_decrypted():
    decrypted_data = BytesIO()

    decrypted_data.write(session.get("decrypted_data", b""))

    decrypted_data.seek(0)

    return send_file(
        decrypted_data,
        as_attachment=True,
        download_name="decrypted_file"
    )

if __name__ == "__main__":
    os.makedirs("uploads", exist_ok=True)
   
