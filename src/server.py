import socket
import threading
import random
import json
import argparse

from constants import CURVE, BUFF_SIZE
from server_structs import ServerDatabase, Sessions


# Server class to handle client connections and group chat logic
class Server:
    def __init__(self, host: str, port: int, db_path: str):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen(5)
        print(f"[INFO] Server started on {host}:{port}")

        self.database = ServerDatabase(db_path)
        self.active_sessions = Sessions()

    @staticmethod
    def encode_data(data):
        return json.dumps(data).encode()

    @staticmethod
    def decode_data(data):
        return json.loads(data.decode())

    def send_msg(self, sender_socket, reciever_username, signcrypted_msg):
        data = self.encode_data({
            'action': 'msg',
            'sender': self.active_sessions.get_username(sender_socket),
            'signcrypted_msg': signcrypted_msg
        })

        group_name = self.active_sessions.get_group_name(sender_socket)
        recipient_socket = self.active_sessions.get_socket(reciever_username, group_name)
        if recipient_socket is not None:
            recipient_socket.send(data)

    # Zero-Knowledge Key-Statement Proof
    def verify_client_key(self, client_socket, public_key, commitment):
        public_key = CURVE.decode_point(public_key)
        commitment = CURVE.decode_point(commitment)

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

                if action == 'authentication':
                    username = request['username']
                    group_name = request['group_name']
                    commitment = request['commitment']

                    # Verify that user has private key (ZKKSP)
                    public_key = self.database.get_public_key(username)
                    if self.verify_client_key(client_socket, public_key, commitment):
                        print(f"[INFO] User {client_socket.getpeername()} authenticated as '{username}'.")
                    else:
                        print(f"[WARNING] User '{client_socket.getpeername()}' authentication as '{username}' FAIL.")
                        client_socket.send(
                            self.encode_data({'status': 'denied', 'reason': "Authentication fail."}))
                        break

                    # Check user access to group
                    if not self.database.check_access_to_group(username, group_name):
                        data = self.encode_data({'status': 'denied',
                                                 'reason': f"You have no access to group '{group_name}'."})
                        client_socket.send(data)
                        print(
                            f"[WARNING] User '{username}' has no access to group '{group_name}'. Terminating connection.")
                        break
                    else:
                        print(f"[INFO] User '{username}' connected to group '{group_name}'.")

                    if self.active_sessions.get_socket(username,
                                                       group_name) is not None:  # There is active session with user already
                        data = self.encode_data({'status': 'denied',
                                                 'reason': f"You already have active session."})
                        client_socket.send(data)
                        print(
                            f"[WARNING] User '{username}' tried to connect, but already have active session. Terminating.")
                        break

                    # Save active session
                    self.active_sessions.add_session(client_socket, username, group_name)

                    # Send success code and members info
                    group_usernames = self.active_sessions.get_group_members(client_socket)
                    public_keys = [self.database.get_public_key(usr) for usr in group_usernames]
                    members_data = {}
                    for username, public_key in zip(group_usernames, public_keys):
                        members_data[username] = public_key
                    data = self.encode_data({'status': 'success',
                                             'members': members_data})
                    client_socket.send(data)

                    # Tell group members that there is new active member
                    self.broadcast_new_member(client_socket)

                elif action == 'send_message':
                    # sender = self.active_sessions.get_username(client_socket)
                    reciever = request['reciever']
                    signcrypted_msg = request['signcrypted_msg']
                    self.send_msg(client_socket, reciever, signcrypted_msg)
                else:
                    print(
                        f"[WARNING] Unknown action '{action}. Terminating connection.")
                    break

            except (ConnectionResetError, json.JSONDecodeError):
                break

        # Client disconnected
        print(f"[INFO] Client disconnected: {client_socket.getpeername()}")
        if self.active_sessions.get_username(client_socket) is not None:  # Check if client was authenticated
            self.broadcast_member_disconnect(client_socket)
        self.active_sessions.del_session(client_socket)
        client_socket.close()

    def broadcast_new_member(self, new_member_socket):
        # New member data
        new_username = self.active_sessions.get_username(new_member_socket)
        new_public_key = self.database.get_public_key(new_username)

        # Send message to other group members
        members_sockets = self.active_sessions.get_other_group_sockets(new_member_socket)
        for sock in members_sockets:
            data = self.encode_data({
                'action': 'new_member',
                'member_name': new_username,
                'member_public_key': new_public_key
            })
            sock.send(data)

    def broadcast_member_disconnect(self, client_socket):
        username = self.active_sessions.get_username(client_socket)

        # Send message to other group members
        members_sockets = self.active_sessions.get_other_group_sockets(client_socket)
        for sock in members_sockets:
            data = self.encode_data({
                'action': 'member_leave',
                'username': username
            })
            sock.send(data)

    def run(self):
        while True:
            client_socket, addr = self.server.accept()
            print(f"[INFO] Connection from {addr}")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host", type=str, help="server IP address")
    parser.add_argument("port", type=int, help="server port")
    parser.add_argument("db_path", type=str, help="path to json with server data about users and groups")
    args = parser.parse_args()

    server = Server(args.host, args.port, args.db_path)
    server.run()
