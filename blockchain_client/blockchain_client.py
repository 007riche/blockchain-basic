from flask import Flask, render_template, jsonify, request
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
import binascii
from collections import OrderedDict
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from flask_cors import CORS


# render_template allows us to render a web page template

class Transaction:
    def __init__(self, sender_public_key, sender_private_key, receiver_public_key, amount):
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key
        self.receiver_public_key = receiver_public_key
        self.amount = amount

    def to_dict(self):
        # 'sender_private_key': self.sender_private_key,
        return OrderedDict({
            'sender_public_key': self.sender_public_key,
            'receiver_public_key': self.receiver_public_key,
            'amount': self.amount,
        })

    def to_transact_sign(self):
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        hashVal = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(hashVal)).decode('ascii')


app = Flask(__name__)
CORS(app)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/make/transactions')
def make_transaction():
    return render_template('make_transaction.html')


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    sender_public_key = request.form['sender_public_key']
    sender_private_key = request.form['sender_private_key']
    receiver_public_key = request.form['receiver_public_key']
    amount = request.form['amount']
    transaction = Transaction(sender_public_key, sender_private_key, receiver_public_key, amount)
    response = {
        'transaction': transaction.to_dict(),
        'signature': transaction.to_transact_sign(),
    }
    return jsonify(response), 200


@app.route('/view/transactions')
def view_transaction():
    return render_template('view_transaction.html')


@app.route('/wallet/new')
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.public_key()
    response = {
        'private_key': binascii.hexlify(private_key.export_key(format('DER'))).decode('ascii'),
        'public_key': binascii.hexlify(public_key.export_key(format('DER'))).decode('ascii')
    }
    return jsonify(response), 200


# Running the script from inside it
if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8081, type=int, help='port on which to listen to')
    args = parser.parse_args()
    port = args.port
    app.run(host="127.0.0.1", port=port, debug=True)
