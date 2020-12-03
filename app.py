from flask import Flask, request, render_template
from Crypto.Cipher import AES
from Crypto.Util import Counter
import os

FLAG = os.environ.get("FLAG") or "PLEASE_SET_A_FLAG"
KEY = os.environ.get("KEY") or os.urandom(32)
SALT = os.environ.get("SALT") or os.urandom(15)

app = Flask(__name__)

class Encryptor(object):
    def __init__(self, key, salt):
        self.salt = salt
        self.key = key

        try:
            self.salt = self.salt.encode()
        except Exception:
            pass

        try:
            self.key = self.key.encode()
        except Exception:
            pass
    
    def encrypt(self, plaintext):
        nonce = self.salt + os.urandom(16 - len(self.salt))
        key = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = key.encrypt_and_digest(plaintext.encode())
        return nonce.hex() + ":" + ciphertext.hex() + ":" + tag.hex()
    
    def decrypt(self, ciphertext):
        words = [bytes.fromhex(c) for c in ciphertext.split(":")]
        nonce = words[0]
        ciphertext = words[1]
        tag = words[2]
        key = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        return key.decrypt_and_verify(ciphertext, tag)

encryptor = Encryptor(KEY, SALT)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    plaintext = request.form.get('plaintext')

    if not plaintext or len(plaintext) == 0:
        return "Something wents wrong"

    return encryptor.encrypt(plaintext + FLAG)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    ciphertext = request.form.get('ciphertext')

    plaintext = encryptor.decrypt(ciphertext)
    if not plaintext.decode().endswith(FLAG):
        return "Something wents wrong"
    else:
        return plaintext[:-len(FLAG)]

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
