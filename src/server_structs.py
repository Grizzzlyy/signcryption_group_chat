import json


class User:
    def __init__(self, username, public_key):
        self.username = username
        self.public_key = public_key


class Group:
    def __init__(self, group_name):
        self.group_name = group_name
        self.members = {}

    def add_member(self, user_obj):
        self.members[user_obj.username] = user_obj

    def is_member(self, username):
        return username in self.members.keys()


class Session:
    def __init__(self, username, group_name):
        self.username = username
        self.group_name = group_name


class Sessions:

    def __init__(self):
        self.sessions = {}  # Map socket to Session

    def add_session(self, socket, username, group_name):
        self.sessions[socket] = Session(username, group_name)

    def del_session(self, socket):
        try:
            del self.sessions[socket]
        except KeyError:
            pass

    def get_username(self, socket):
        try:
            return self.sessions[socket].username
        except KeyError:
            return None

    def get_group_name(self, socket):
        return self.sessions[socket].group_name

    def get_socket(self, username, group_name):
        for socket, session in self.sessions.items():
            if (session.username, session.group_name) == (username, group_name):
                return socket
        return None

    def get_group_members(self, socket):
        group_name = self.sessions[socket].group_name
        res = []
        for sock, session in self.sessions.items():
            if session.group_name == group_name:
                res.append(session.username)
        return res

    def get_other_group_sockets(self, socket):
        # socket - new member socket
        # returns: sockets, that belong to same group as socket
        res = []
        group_name = self.sessions[socket].group_name
        for sock, session in self.sessions.items():
            if sock != socket:  # exclude argument
                if session.group_name == group_name:
                    res.append(sock)
        return res


class ServerDatabase:
    def __init__(self, path: str):
        self.users = {}  # Maps username to User object
        self.groups = {}  # Maps group_name to Group object

        # Load data
        with open(path, 'r') as fp:
            data = json.load(fp)

        # Get users data
        for user_info in data["users"]:
            username, public_key = user_info['username'], user_info['public_key']
            self.users[username] = User(username, public_key)

        # Get groups data
        for group_info in data["groups"]:
            group_name, group_members = group_info["group_name"], group_info["members"]
            self.groups[group_name] = Group(group_name)
            for username in group_members:
                self.groups[group_name].add_member(self.users[username])

    def check_access_to_group(self, username, group_name):
        try:
            group = self.groups[group_name]
            return group.is_member(username)
        except KeyError: # no such group
            return False

    def get_public_key(self, username):
        return self.users[username].public_key
