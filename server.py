import socket
import threading
import random
import json
import argparse

from constants import CURVE, BUFF_SIZE


# User class to store user information
class User:
    def __init__(self, username, public_key):
        self.username = username
        self.public_key = public_key


# Group class to manage group memberships and messages
class Group:
    def __init__(self, name):
        self.name = name
        self.members = []

    def add_member(self, user):
        self.members.append(user)

    def remove_member(self, user):
        self.members.remove(user)

    def get_members(self):
        return [{'username': member.username, 'public_key': CURVE.encode_point(member.public_key)} for member in
                self.members]


# Server class to handle client connections and group chat logic
class Server:
    def __init__(self, host: str, port: int):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen(5)
        print(f"Server started on {host}:{port}")

        self.clients = {}  # Maps socket to user
        self.groups = {}  # Maps group name to Group object

    def encode_data(self, data):
        return json.dumps(data).encode()

    def decode_data(self, data):
        return json.loads(data.decode())

    def broadcast_new_member(self, group_name, new_member):
        group = self.groups[group_name]
        for member in group.members:
            if member.username != new_member.username:  # Skip sender
                recipient_socket = next(sock for sock, user in self.clients.items() if user.username == member.username)
                data = self.encode_data({
                    'action': 'new_member',
                    'group': group_name,
                    'member_name': new_member.username,
                    'member_public_key': CURVE.encode_point(new_member.public_key)
                })
                recipient_socket.send(data)

    def send_msg(self, group_name, sender, reciever, signcrypted_msg):
        for sock, user in self.clients.items():
            if user.username == reciever:
                recipient_socket = sock
                break

        data = self.encode_data({
            'action': 'msg',
            'sender': sender.username,
            'group': group_name,
            'signcrypted_msg': signcrypted_msg
        })
        recipient_socket.send(data)

    # Zero-Knowledge Key-Statement Proof
    def verify_client_key(self, client_socket, public_key, commitment):
        challenge = random.randint(1, CURVE.order - 1)
        data = self.encode_data({
            'status': 'challenge',
            'challenge': challenge,
        })
        client_socket.send(data)

        data = client_socket.recv(BUFF_SIZE)
        request = self.decode_data(data)
        zkksp_response = request['zkksp_response']

        if zkksp_response * CURVE.generator == commitment + challenge * public_key:
            return True
        else:
            return False

    def handle_client(self, client_socket):
        while True:
            try:
                data = client_socket.recv(BUFF_SIZE)
                if not data:
                    break

                request = self.decode_data(data)
                action = request['action']

                if action == 'register':
                    username = request['username']
                    public_key = CURVE.decode_point(request['public_key'])
                    commitment = CURVE.decode_point(request['commitment'])

                    if self.verify_client_key(client_socket, public_key, commitment):
                        user = User(username, public_key)
                        self.clients[client_socket] = user
                        print(f"User {username} registered.")
                        client_socket.send(self.encode_data({'status': 'registered'}))
                    else:
                        print(f"User {username} couldn't prove his public key.")
                        client_socket.send(
                            json.dumps({'status': 'denied', 'reason': "Public key is not proved."}).encode())
                        break

                elif action == 'join_group':
                    group_name = request['group']
                    user = self.clients[client_socket]

                    if group_name not in self.groups:
                        self.groups[group_name] = Group(group_name)
                        print(f"Group '{group_name}' registered")
                    self.groups[group_name].add_member(user)

                    # Send success status to client and share members of group
                    data = self.encode_data({'status': 'joined_group',
                                             'group_name': group_name,
                                             'members': self.groups[group_name].get_members()})
                    client_socket.send(data)

                    # Broadcast message about new member to group members
                    self.broadcast_new_member(group_name, self.clients[client_socket])

                elif action == 'send_message':
                    sender = self.clients[client_socket]
                    group_name = request['group']
                    reciever = request['reciever']
                    signcrypted_msg = request['signcrypted_msg']
                    self.send_msg(group_name, sender, reciever, signcrypted_msg)

            except (ConnectionResetError, json.JSONDecodeError):
                break

        print(f"Client disconnected: {self.clients[client_socket].username}")
        # Delete client from group
        for i in self.groups:
            gr = self.groups[i]
            for j in range(len(gr.members)):
                if gr.members[j].username == self.clients[client_socket].username:
                    del gr.members[j]
        del self.clients[client_socket]
        client_socket.close()

    def run(self):
        while True:
            client_socket, addr = self.server.accept()
            print(f"Connection from {addr}")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host", type=str, help="server IP address")
    parser.add_argument("port", type=int, help="server port")
    args = parser.parse_args()

    server = Server(args.host, args.port)
    server.run()
