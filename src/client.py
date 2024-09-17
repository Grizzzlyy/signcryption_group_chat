import argparse
import random
import socket
import threading
import json

from signcryption import gen_keys, signcryption, unsigncryption
from constants import CURVE, BUFF_SIZE


class Client:
    def __init__(self, host: str, port: int, username: str, group_name: str, keys_path: str):
        self.username = username
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.group_name = group_name
        self.group_members = {}  # Map usernames to public keys

        # Read keys
        with open(keys_path, 'r') as fp:
            keys = json.load(fp)
            self.private_key = keys["private"]
            self.public_key = CURVE.decode_point(keys["public"])

        # Connect to server
        self.server.connect((host, port))

        # Authentication (ZKKSP)
        self.authentication()

        # Receive messages thread
        threading.Thread(target=self.receive_messages).start()

        # Sending messages in an infinite loop
        while True:
            message = input()
            self.send_message(message)

    # Authenticate (ZKKSP) and connect to group
    def authentication(self):
        # Send user info and commitment
        commitment_r = random.randint(1, CURVE.order - 1)
        commitment_R = commitment_r * CURVE.generator
        data = {'action': 'authentication',
                'username': self.username,
                'group_name': self.group_name,
                'commitment': CURVE.encode_point(commitment_R)}
        self.send(data)

        response = self.recv()
        if response['status'] == 'challenge':
            #  Send zkksp_response
            challenge = response['challenge']
            zkksp_response = (commitment_r + challenge * self.private_key) % CURVE.order
            data = {'action': 'prove',
                    'zkksp_response': zkksp_response}
            self.send(data)

            response = self.recv()
            if response['status'] == 'success':
                members = response['members']
                self.group_members.update(members)
                print(f"[INFO] Successfully connected to group '{self.group_name}'")
                print("Users in chat:")
                for username in self.group_members:
                    print(f'- {username}')
            elif response['status'] == 'denied':
                print(f"[ERROR] Access to group '{self.group_name}' denied. Reason: {response['reason']}")
            else:
                print(f"[ERROR] Unexpected responce from server.")
                exit()
        else:
            print("Server didn't accept challenge")
            exit()

    def send(self, data):
        self.server.send(json.dumps(data).encode())

    def recv(self):
        return json.loads(self.server.recv(BUFF_SIZE).decode())

    def receive_messages(self):
        while True:
            try:
                response = self.recv()

                if response['action'] == 'new_member':
                    username = response['member_name']
                    public_key = response['member_public_key']
                    self.group_members[username] = public_key
                    # self.group_members.append({'username': username,
                    #                            'public_key': public_key})
                    print(f"[INFO] New member: {username}")
                elif response['action'] == 'msg':
                    # Get signcrypted message
                    sender_name = response['sender']
                    R, C, s = response['signcrypted_msg']
                    signcrypted_msg = CURVE.decode_point(R), C, s

                    # Find sender public key
                    sender_pub_key = self.group_members[sender_name]

                    # Unsigncrypt
                    try:
                        msg = unsigncryption(signcrypted_msg, sender_name, self.username,
                                             CURVE.decode_point(sender_pub_key),
                                             self.private_key)
                    except ValueError:
                        msg = None
                    if msg is None:
                        print(f"[WARNING] user '{sender_name}' sent malicious message")
                    else:
                        print(f"{sender_name}: {msg}")
                else:
                    raise ValueError(f"Unknown action in receive_messages(): {response['action']}")
            except (ConnectionResetError, json.JSONDecodeError):
                break

    # Register user and verify private key possession (Zero-Knowledge Key-Statement Proof)
    # def register(self):
    #     # Send user info and commitment
    #     commitment_r = random.randint(1, CURVE.order - 1)
    #     commitment_R = commitment_r * CURVE.generator
    #     data = {'action': 'register',
    #             'username': self.username,
    #             'public_key': CURVE.encode_point(self.public_key),
    #             'commitment': CURVE.encode_point(commitment_R)}
    #     self.send(data)
    #
    #     response = self.recv()
    #     if response['status'] == 'challenge':
    #         #  Send zkksp_response
    #         challenge = response['challenge']
    #         zkksp_response = (commitment_r + challenge * self.private_key) % CURVE.order
    #         data = {'action': 'prove',
    #                 'zkksp_response': zkksp_response}
    #         self.send(data)
    #
    #         response = self.recv()
    #         if response['status'] == 'registered':
    #             print(f"Registered as {self.username}, Public Key: {self.public_key}")
    #         else:
    #             print(f"Not registered =(")
    #             exit()
    #     else:
    #         print("Server didn't accept challenge")
    #         exit()
    #
    # def join_group(self, group_name):
    #     data = {'action': 'join_group',
    #             'username': self.username,
    #             'group': group_name}
    #     self.send(data)
    #
    #     response = self.recv()
    #     if response['status'] == 'joined_group':
    #         # Save group members usernames and private keys to send them messages later
    #         for member in response['members']:
    #             self.group_members.append(
    #                 {"username": member['username'],
    #                  "public_key": CURVE.decode_point(member["public_key"])})
    #
    #         # Print info
    #         print(f"Successfully joined group '{group_name}'")
    #         print(f"Members in chat:")
    #         for member in self.group_members:
    #             print(f"- {member['username']}")
    #     else:
    #         print('Error occured when joining group')

    def send_message(self, msg):
        for username, public_key in self.group_members.items():
            if username != self.username:  # exclude himself
                # Signcrypt message to every member in chat and send
                (R, C, s) = signcryption(msg, self.username, username, self.private_key,
                                         CURVE.decode_point(public_key))
                signcrypted_msg = (CURVE.encode_point(R), C, s)
                self.send({'action': 'send_message', 'group': self.group_name, 'reciever': username,
                           'signcrypted_msg': signcrypted_msg})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host", type=str, help="server IP address")
    parser.add_argument("port", type=int, help="server port")
    parser.add_argument("username", type=str, help="username")
    parser.add_argument("groupname", type=str, help="group name")
    parser.add_argument("keys_path", type=str, help="path to json with public/private key pair")
    args = parser.parse_args()

    client = Client(args.host, args.port, args.username, args.groupname, args.keys_path)
