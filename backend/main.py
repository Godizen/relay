from socket import SHUT_RDWR
import socketserver
from nacl.encoding import Base64Encoder
import json
import psycopg
import nacl
from nacl.public import PublicKey, PrivateKey, Box
import secrets
from typing import Any
from socket import socket


class User:
    """
    The User class that handles the communication with the client(s) and handles database connections for each user.
    """

    def __init__(self, conn: socket, addr: "tuple(str,int)",
                 db: "dict[str,str]") -> None:
        """
        Initializes the User class.
        :param conn: The connection to the client.
        :param addr: The address of the client.
        :param db: The database connection configuration.
        """
        self.conn: socket = conn
        self.addr: "tuple(str,int)" = addr
        self.private: nacl.public.PrivateKey = nacl.public.PrivateKey.generate(
        )
        self.conn.sendall(self.private.public_key.encode(Base64Encoder))
        self.box: nacl.public.Box = nacl.public.Box(
            self.private,
            nacl.public.PublicKey(self.conn.recv(4096), Base64Encoder))
        self.dbcur: psycopg.ServerCursor = psycopg.connect(
            **db, autocommit=True).cursor()

    @classmethod
    def create_object(cls, conn: socket, addr: "tuple(str,int)",
                      db: "dict[str,str]") -> "User":
        """
        The class method that creates a new User object.
        :param conn: The connection to the client.
        :param addr: The address of the client.
        :param db: The database connection configuration.
        :return: The new User object.
        """
        return cls(conn, addr, db)

    def send(self, msg) -> None:
        """
        The function that sends encrypted data to the client.
        :param msg: The message to send.
        """
        self.conn.sendall(self.box.encrypt(json.dumps(msg).encode()))

    def recv(self) -> "dict[str,Any]":
        """
        The function that receives encrypted data from the client and decrypts it.
        :return: The decrypted data in the form of a dictionary.
        """
        return json.loads(self.box.decrypt(self.conn.recv(4096)).decode())

    def session_check(self, check) -> bool:
        """
        The function that checks if the session id is valid.
        :param check: The session id to check.
        :return: True if the session id is valid, False otherwise.
        """
        if self.sess == check:
            return True
        else:
            return False

    def login(self, dat) -> bool:
        """
        The function that handles the login request.
        :param dat: The login data.
        :return: True if the login was successful, False otherwise.
        """
        self.dbcur.execute("SELECT * FROM users WHERE username = %s",
                           (dat["uname"], ))
        user: "list[str]" = self.dbcur.fetchone()
        if user is None:
            self.send({"type": "login", "id": 0})
            return False
        if user[2] != dat["passwd"]:
            self.send({"type": "login", "id": 0})
            return False
        if dat["uname"] in usersendmap:
            self.send({"type": "login", "id": -1})
            return False
        self.uname: str = user[1]
        self.sess: str = secrets.token_urlsafe(256)
        self.send({"type": "login", "id": 1, "sessionId": self.sess})
        usersendmap[self.uname]: function = self.send
        return True

    def register(self, dat) -> bool:
        """
        The function that handles the registration request.
        :param dat: The registration data.
        :return: True if the registration was successful, False otherwise.
        """
        self.dbcur.execute("SELECT * FROM users WHERE username = %s",
                           (dat["uname"], ))
        user: "list[str]" = self.dbcur.fetchone()
        if user is not None:
            self.send({"type": "register", "id": 0})
            return False
        self.dbcur.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (dat["uname"], dat["passwd"]),
        )
        self.public: str = dat["pub"]
        self.dbcur.execute(
            "INSERT INTO keys (username, public) VALUES (%s, %s)",
            (dat["uname"], self.public),
        )
        self.uname: str = dat["uname"]
        self.sess: str = secrets.token_urlsafe(256)
        self.send({"type": "register", "id": 1, "sessionId": self.sess})
        usersendmap[self.uname]: function = self.send
        return True

    def logout(self, dat) -> bool:
        """
        The function that handles the logout request.
        :param dat: The logout data.
        :return: True if the logout was successful, False otherwise.
        """
        if self.sess != dat["sessionId"]:
            self.send({"type": "logout", "id": 0})
            return False
        else:
            self.send({"type": "logout", "id": 1})
            del usersendmap[self.uname]
        self.__del__()

    def get_key(self, dat) -> bool:
        """
        The function that handles the get key request.
        :param dat: The get key data.
        :return: True if the get key was successful, False otherwise.
        """
        if self.sess != dat["sessionId"]:
            self.send({"type": "get_key", "id": -1})
            return False
        self.dbcur.execute("SELECT public FROM keys WHERE username = %s",
                           (dat["uname"], ))
        if requested_key := self.dbcur.fetchone()[0]:
            self.send({"type": "get_key", "id": 1, "key": requested_key})
            return True
        else:
            self.send({"type": "get_key", "id": 0})
            return False

    def get_online(self, dat) -> bool:
        """
        The function that handles the get online request.
        :param dat: The get online data.
        :return: True if the get online was successful, False otherwise.
        """
        if self.sess != dat["sessionId"]:
            self.send({"type": "get_online", "id": -1})
            return False
        current = list(usersendmap.keys())
        self.send({"type": "get_online", "id": 1, "online": current})
        return True

    def message(self, dat) -> bool:
        """
        The function that handles the message request.
        :param dat: The message data.
        :return: True if the message was successful, False otherwise.
        """
        if self.sess != dat["sessionId"]:
            self.send({"type": "message", "id": -1})
            return False
        del dat["sessionId"]
        if dat["rUname"] in usersendmap.keys():
            usersendmap[dat["rUname"]](dat)
            self.send({"type": "message", "id": 1})
            return True
        else:
            self.send({"type": "message", "id": 0})
            return False

    def save_message(self, dat) -> bool:
        """
        The function that handles the save message request.
        :param dat: The save message data.
        :return: True if the save message was successful, False otherwise.
        """
        if self.sess != dat["sessionId"]:
            self.send({"type": "saved_message", "id": -1})
            return False
        del dat["sessionId"]
        if dat["rUname"] in usersendmap.keys():
            usersendmap[dat["rUname"]](dat)
            self.send({"type": "saved_message", "id": 1})
            return True
        else:
            self.send({"type": "saved_message", "id": 0})
            return False

    def manage(self) -> None:
        """
        The function that handles the manage request.
        :return: None.
        """
        while True:
            dat: "dict[str,str]" = self.recv()
            if dat["type"] == "login":
                self.login(dat)
            elif dat["type"] == "register":
                self.register(dat)
            elif dat["type"] == "logout":
                self.logout(dat)
                break
            elif dat["type"] == "get_key":
                self.get_key(dat)
            elif dat["type"] == "get_online":
                self.get_online(dat)
            elif dat["type"] == "message":
                self.message(dat)
            elif dat["type"] == "saved_message":
                self.save_message(dat)

    def __del__(self) -> None:
        """
        The function that handles the deletion of the client.
        :return: None.
        """
        self.conn.shutdown(SHUT_RDWR)
        self.conn.close()
        self.dbcur.connection.close()
        self.dbcur.close()
        del usersendmap[self.uname]


class ThreadedRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):
        u: User = User(
            self.request,
            self.client_address,
            {
                "host": "",
                "dbname": "postgres",
                "user": "postgres",
                "password": "postgres",
            },
        )
        u.manage()


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    usersendmap = {}
    ThreadedTCPServer(("0.0.0.0", 58008),
                      ThreadedRequestHandler).serve_forever()
