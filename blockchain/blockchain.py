import binascii
from Crypto.PublicKey import RSA
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from time import time
from collections import OrderedDict
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from uuid import uuid4
import json
import hashlib
import requests
from urllib.parse import urlparse

MINING_SENDER = "The Blockchain"
MINING_REWARD = 12
MINING_DIFFICULTY = 2


class Blockchain:
    def __init__(self):
        self.transactions = []
        self.nodes = set()  # contains peers or other nodes info
        self.node_id = str(uuid4()).replace('-', '')
        self.chain = []
        # Creating the genesis block
        self.create_block(0, '00')  # This is the genesis block of the blockchain

    def create_block(self, nonce, previous_hash):
        """"
        Add a block of transaction to the blockchain
        """
        block = {
            'block_number': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.transactions,
            'nonce': nonce,
            'previous_hash': previous_hash
        }
        # Flush the current list of transactions
        self.transactions = []
        self.chain.append(block)
        return block

    def verify_transaction_signature(self, sender_public_key, signature, transaction):
        public_key = RSA.importKey(binascii.unhexlify(sender_public_key))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaction).encode('utf8'))
        try:
            verifier.verify(h, binascii.unhexlify(signature))
            return True
        except ValueError:
            return False

    def submit_transaction(self, sender_public_key, receiver_public_key, signature, amount):
        # TODO: Reward the miner
        # TODO: Signature
        # 'signature': signature,
        transaction = OrderedDict({
            'sender_public_key': sender_public_key,
            'receiver_public_key': receiver_public_key,
            'amount': amount
        })
        # Reward for mining
        if sender_public_key == MINING_SENDER:
            self.transactions.append(transaction)
            return len(self.chain) + 1
        else:
            # Normal transaction
            signature_verification = self.verify_transaction_signature(sender_public_key, signature, transaction)
            if signature_verification:
                self.transactions.append(transaction)
                return len(self.chain) + 1
            else:
                return False

    def check_valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            if block['previous_hash'] != self.hasH(last_block):
                return False
            transactions = block['transactions'][:-1]
            transaction_elements = ['sender_public_key', 'receiver_public_key', 'amount']
            transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in
                            transactions]
            if not self.valid_proof_of_work(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False
            last_block = block
            current_index += 1

            return True

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None  # Current longest chain and ultimately the  Final chain on which synchronization has to be
        # done
        max_length = len(self.chain)  # length of the chain on the current blockchain node or peer
        for node in neighbours:
            response = requests.get('http://' + node + '/chain')
            if response.status_code == 200:
                length = response.json()['length']  # length of the other queried node
                chain = response.json()['chain']  # chain of transaction of the other queried node

                if length > max_length and self.check_valid_chain(chain):
                    max_length = length
                    new_chain = chain

            if new_chain:  # After seeking for the longest node, if the longest chains' node is not empty
                self.chain = new_chain
                return True

            return False

    @staticmethod
    def valid_proof_of_work(transactions, last_hash, nonce, difficult=MINING_DIFFICULTY):
        guess = (str(transactions) + str(last_hash) + str(nonce)).encode('utf8')
        hashVal = hashlib.new('sha256')
        hashVal.update(guess)
        hashed_guess = hashVal.hexdigest()
        return hashed_guess[:difficult] == '0' * difficult

    def proof_of_work(self):
        last_block = self.chain
        last_hash = self.hasH(last_block)
        nonce = 0
        while self.valid_proof_of_work(self.transactions, last_hash, nonce) is False:
            nonce += 1

        return nonce

    @staticmethod
    def hasH(block):
        # Note: Ensure that the block dictionary is always ordered in order to get consistent hashes
        block_json_string = json.dumps(block, sort_keys=True).encode('utf8')
        hashVal = hashlib.new('sha256')
        hashVal.update(block_json_string)
        # Final hash of the object
        return hashVal.hexdigest()

    def register_new_node(self, node_url):
        parsed_url = urlparse(node_url)  # Checking if the url is valid
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


# Instantiate the Blockchain
blockchain = Blockchain()

# Instantiate Node
app = Flask(__name__)
CORS(app)


@app.route('/')
def index():
    return render_template('./index.html')


@app.route('/configuration')
def configuration():
    return render_template('./configuration.html')


@app.route('/chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    # Check the proof of work using its algorithm
    nonce = blockchain.proof_of_work()
    blockchain.submit_transaction(sender_public_key=MINING_SENDER,
                                  receiver_public_key=blockchain.node_id,
                                  signature='',
                                  amount=MINING_REWARD)
    last_block = blockchain.chain[-1]
    previous_hash = blockchain.hasH(last_block)
    current_block_mined = blockchain.create_block(nonce, previous_hash)
    response = {
        'message': 'New block created',
        'block_number': current_block_mined['block_number'],
        'transactions': current_block_mined['transactions'],
        'nonce': current_block_mined['nonce'],
        'previous_hash': current_block_mined['previous_hash']

    }

    return jsonify(response), 200


@app.route('/transaction/get', methods=['GET'])
def get_transaction():
    transactions = blockchain.transactions
    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/transaction/new', methods=['POST'])
def new_transaction():
    values = request.form
    # TODO: check the required fields
    required = ['confirmation_sender_public_key', 'confirmation_recipient_public_key', 'transaction_signature',
                'confirmation_amount']
    if not all(k in values for k in required):
        return "Missing values", 400
    transaction_results = blockchain.submit_transaction(values['confirmation_sender_public_key'],
                                                        values['confirmation_recipient_public_key'],
                                                        values['transaction_signature'],
                                                        values['confirmation_amount']
                                                        )
    if not transaction_results:
        response = {
            'message': 'Invalid transaction'
        }
        return jsonify(response), 406
    else:
        response = {
            'message': 'The transaction will be added to the block ' + str(transaction_results)
        }
        return jsonify(response), 201


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_new_node():
    values = request.form  # Retrieve information from a form
    nodes = values.get('nodes').replace(' ', '').split(',')  # Replacing all the spaces in the list of nodes by no
    # char and splitting the list into a list
    if nodes is None:
        return 'Error: Please provide a valid list of nodes', 400
    for node in nodes:
        blockchain.register_new_node(node)

    response = {
        'message': 'Nodes have been added',
        'total_nodes': [node for node in blockchain.nodes]
    }
    return jsonify(response), 200


# Running the script from inside it
# Here used to start the server with custom configurations
if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5001, type=int, help='port on which to listen to')
    args = parser.parse_args()
    port = args.port
    app.run(host="127.0.0.1", port=port, debug=True)
