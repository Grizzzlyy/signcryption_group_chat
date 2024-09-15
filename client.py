import argparse
import random
import socket
import threading
import json
from signcryption import gen_keys, signcryption, unsigncryption
from constants import CURVE


class Client:
    def __init__(self, username: str, host: str, port: int, group_name: str):
        self.username = username
        self.private_key, self.public_key = gen_keys()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.group_members = []

        # Connect to server
        self.server.connect((host, port))

        # Register
        self.register()

        # Join group
        self.join_group(group_name)

        # Receive messages thread
        threading.Thread(target=self.receive_messages).start()

    def send(self, data):
        self.server.send(json.dumps(data).encode())

    def receive_messages(self):
        while True:
            try:
                data = self.server.recv(1024)
                if data:
                    response = json.loads(data.decode())
                    if response['action'] == 'new_member':
                        self.group_members.append({'username': response['member_name'], 'public_key': CURVE.decode_point(response['member_public_key'])})
                    elif response['action'] == 'msg':
                        group_name = response['group']
                        sender_name = response['sender']
                        R, C, s = response['signcrypted_msg']
                        signcrypted_msg = CURVE.decode_point(R), C, s

                        for member in self.group_members:
                            if member['username'] == sender_name:
                                sender_pub_key = member['public_key']
                                break
                        msg = unsigncryption(signcrypted_msg, sender_name, self.username, sender_pub_key, self.private_key)
                        print(f"[{group_name}] {sender_name}: {msg}")
                    else:
                        print('Unknown action in receive_messages()')
            except (ConnectionResetError, json.JSONDecodeError):
                break

    # Register and verify public key
    def register(self):
        # Send user info and commitment
        commitment_r = random.randint(1, CURVE.order - 1)
        commitment_R = commitment_r * CURVE.generator
        data = {'action': 'register',
                'username': self.username,
                'public_key': CURVE.encode_point(self.public_key),
                'commitment': CURVE.encode_point(commitment_R)}
        self.send(data)

        response = json.loads(self.server.recv(1024).decode())
        if response['status'] == 'challenge':
            #  Send zkksp_response
            challenge = response['challenge']
            zkksp_response = (commitment_r + challenge * self.private_key) % CURVE.order
            data = {'action': 'prove',
                    'zkksp_response': zkksp_response}
            self.send(data)

            response = json.loads(self.server.recv(1024).decode())
            if response['status'] == 'registered':
                print(f"Registered as {self.username}, Public Key: {self.public_key}")
            else:
                print(f"Not registered =(")
                exit()
        else:
            print("Server didn't accept challenge")
            exit()

    def join_group(self, group_name):

        self.send({'action': 'join_group', 'username': self.username, 'group': group_name})
        response = json.loads(self.server.recv(1024).decode())
        if response['status'] == 'joined group':
            for member in response['members']:
                self.group_members.append({"username": member['username'], "public_key": CURVE.decode_point(member["public_key"])})
            print(f"Successfully joined group '{group_name}'")
        else:
            print('Error occured when joining group')

    def send_message(self, group_name, msg):
        for reciever in self.group_members:
            if reciever['username'] != self.username: # exclude himself
                (R, C, s) = signcryption(msg, self.username, reciever['username'], self.private_key, reciever['public_key'])
                self.send({'action': 'send_message', 'group': group_name, 'reciever': reciever['username'], 'signcrypted_msg': (CURVE.encode_point(R), C, s)})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host", type=str, help="server IP address")
    parser.add_argument("port", type=int, help="server port")
    args = parser.parse_args()

    # Example client usage
    username = input("Enter username: ")
    group_name = input("Enter group to join: ")

    client = Client(username, args.host, args.port, group_name)

    # Sending messages in a loop
    while True:
        input()
        client.send_message(group_name, message)
