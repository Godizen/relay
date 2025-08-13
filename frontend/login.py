from tkinter import (
    Listbox,
    Tk,
    Canvas,
    Label,
    Entry,
    Button,
    Frame,
    PhotoImage,
    Event,
)
import tkinter.scrolledtext as st
from random import randint, choice
from time import sleep
from math import sin, cos, pi
from socket import socket, AF_INET, SOCK_STREAM, error
from json import loads, dumps
from signal import signal, SIGINT, SIGTERM
import rsa
from queue import Queue
from threading import Thread
from base64 import b64encode, b64decode
import nacl, nacl.hash
from nacl.public import PublicKey, PrivateKey, Box
from typing import Any
from playsound import playsound
from datetime import datetime
import speech_recognition


class relayClient(Tk):
    """The relay client window class."""

    def __init__(self) -> None:
        """Creates the login page."""

        Tk.__init__(self)

        while True:
            try:
                # 65.2.55.172
                self.s: socket = socket(AF_INET, SOCK_STREAM)
                self.s.connect(("relay.elektron.space", 58008))
                pks: PublicKey = PublicKey(self.s.recv(4096).decode(),
                                           encoder=nacl.encoding.Base64Encoder)
                sk: PrivateKey = PrivateKey.generate()
                pk: bytes = sk.public_key.encode(
                    encoder=nacl.encoding.Base64Encoder)
                self.s.send(pk)
                break
            except Exception as err:
                sleep(2)
                print("Cannot connect to server. Retrying in 2s.")

        self.messageStat: Queue = Queue()
        self.data: Queue = Queue()
        self.message: Queue = Queue()
        self.saveMessage: Queue = Queue()
        self.session_manager: Queue = Queue()
        self.getting_key: Queue = Queue()
        self.getting_online: Queue = Queue()

        def reciever() -> None:
            """Receives packets, decrypts and passes them to the packet classifier."""
            self.b: Box = Box(sk, pks)
            while True:
                try:
                    rPacket: "dict[str,Any]" = loads(
                        self.b.decrypt(self.s.recv(4096)).decode())
                    self.data.put(rPacket)
                except OSError:
                    print("Exit", end="")
                    sleep(5)
                except nacl.exceptions.ValueError:
                    print("", end="")
                except nacl.exceptions.CryptoError:
                    print("", end="")

        def data_classifier() -> None:
            """Classifies the packets into their respective queues."""
            while True:
                d: "dict[str,Any]" = self.data.get()
                if d["type"] == "message" and "id" not in d:
                    self.message.put(d)
                elif (d["type"] == "message") or (d["type"] == "saved_message"
                                                  and "id" in d):
                    self.messageStat.put(d)
                elif d["type"] == "saved_message":
                    self.saveMessage.put(d)
                elif d["type"] in ["logout", "login", "register"]:
                    self.session_manager.put(d)
                elif d["type"] == "get_key":
                    self.getting_key.put(d)
                elif d["type"] == "get_online":
                    self.getting_online.put(d)
                self.data.task_done()

        def on_message_recieve() -> None:
            """Receives message packet and sends it to the display message function."""
            while True:
                m: "dict[str,Any]" = self.message.get()
                self.displayMessage(m)
                self.message.task_done()
                pass

        def saveMessageDaemon() -> None:
            """Handles packet when other user saved the messages"""
            while True:
                m: "dict[str,Any]" = self.saveMessage.get()
                self.saveMessages(otherSave=m)
                self.saveMessage.task_done()
                pass

        Thread(target=data_classifier, daemon=True).start()
        Thread(target=on_message_recieve, daemon=True).start()
        Thread(target=saveMessageDaemon, daemon=True).start()
        Thread(target=reciever, daemon=True).start()

        signal(SIGINT, self.logout)
        signal(SIGTERM, self.logout)

        self.rotate: bool = True
        self.onlineUsers: "list[str]" = [""]
        self.cUname: str = ""
        self.pubKeys: "dict[str,Any]" = {}
        self.messages: "dict[str,Any]" = {}
        self.clicked: "str" = ""

        self.attributes("-fullscreen", True)
        self.geometry("1600x900")
        self["bg"] = "#000000"
        self.h: int = self.winfo_screenheight()
        self.w: int = self.winfo_screenwidth()
        self.scaleFactor: float = self.w / 1600
        self.title("RELAY")
        self.iconphoto(False, PhotoImage(file="./logo.png"))
        self.protocol("WM_DELETE_WINDOW", self.logout)
        self.resizable(False, False)
        self.c: Canvas = Canvas(self,
                                width=self.w,
                                height=self.h,
                                bg="#000000",
                                highlightthickness=0)
        self.loginButtonFrame: Frame = Frame(self, width=100, height=50)
        self.signupButtonFrame: Frame = Frame(self, width=100, height=50)
        self.showPasswdButtonFrame: Frame = Frame(self, width=25, height=25)
        self.sendButtonFrame: Frame = Frame(self, width=50, height=50)
        self.saveMessageButtonFrame: Frame = Frame(self, width=100, height=50)
        self.voiceButtonFrame: Frame = Frame(self, width=50, height=50)
        self.exitButtonFrame: Frame = Frame(self, width=50, height=50)

        self.login_btn: PhotoImage = PhotoImage(file="./Loginbutton.png")
        self.signup_btn: PhotoImage = PhotoImage(file="./Signupbutton.png")
        self.showpasswd_btn: PhotoImage = PhotoImage(file="./Showpasswd.png")
        self.relayLogo: PhotoImage = PhotoImage(file="./logo100x100.png")
        self.getKeys: PhotoImage = PhotoImage(file="./get_key.png")
        self.send_btn: PhotoImage = PhotoImage(file="./sendButton.png")
        self.saveMSG: PhotoImage = PhotoImage(file="./saveMSGButton.png")
        self.voiceImage: PhotoImage = PhotoImage(file="./voiceButton.png")
        self.exitImage: PhotoImage = PhotoImage(file="./exitButton.png")

        self.loginButton: Button = Button(
            self.loginButtonFrame,
            image=self.login_btn,
            bd=0,
            activebackground="#000000",
            bg="#000000",
            command=lambda: self.login(self.uEntry.get(), self.pEntry.get()),
            relief="sunken",
        )
        self.signupButton: Button = Button(
            self.signupButtonFrame,
            image=self.signup_btn,
            bd=0,
            activebackground="#000000",
            bg="#000000",
            command=self.pageSignup,
            relief="sunken",
        )
        self.showPasswdButton: Button = Button(
            self.showPasswdButtonFrame,
            image=self.showpasswd_btn,
            activebackground="#000000",
            bg="#000000",
            command=self.showPasswd,
            relief="sunken",
        )

        self.unameLabel: Label = Label(self,
                                       text="Username",
                                       bg="#000000",
                                       fg="#00ff00",
                                       font=("Arial", 14))
        self.passwdLabel: Label = Label(self,
                                        text="Password",
                                        bg="#000000",
                                        fg="#00ff00",
                                        font=("Arial", 14))
        self.passwdConfirmLabel: Label = Label(
            self,
            text="Confirm    ",
            bg="#000000",
            fg="#00ff00",
            font=("Arial", 14),
        )
        self.relayLabel: Label = Label(self,
                                       text="RELAY",
                                       bg="#000000",
                                       fg="#00ff00",
                                       font=("Arial", 40))
        self.relayLogoLabel: Label = Label(self,
                                           image=self.relayLogo,
                                           bg="#000000")
        self.pNotSameLabel: Label = Label(
            self,
            text="Failed to confirm password",
            bg="#000000",
            fg="#ff0000",
            font=("Arial", 14),
        )

        self.uEntry: Entry = Entry(
            self,
            bg="#000000",
            fg="#00ff00",
            font=("Arial", 14),
            insertbackground="#00ff00",
            highlightthickness=0,
        )
        self.pEntry: Entry = Entry(
            self,
            bg="#000000",
            fg="#00ff00",
            font=("Arial", 14),
            show="*",
            insertbackground="#00ff00",
            highlightthickness=0,
        )
        self.pConfirm: Entry = Entry(
            self,
            bg="#000000",
            fg="#00ff00",
            font=("Arial", 14),
            show="*",
            insertbackground="#00ff00",
            highlightthickness=0,
        )

        self.c.pack(fill="both")
        self.loginButtonFrame.place(relx=0.55, rely=0.6, anchor="center")
        self.signupButtonFrame.place(relx=0.45, rely=0.6, anchor="center")
        self.showPasswdButtonFrame.place(relx=0.65, rely=0.5, anchor="center")
        self.loginButton.place(relx=0.5, rely=0.47, anchor="center")
        self.signupButton.place(relx=0.5, rely=0.47, anchor="center")
        self.showPasswdButton.place(relx=0.45, rely=0.45, anchor="center")
        self.unameLabel.place(relx=0.4, rely=0.4, anchor="center")
        self.passwdLabel.place(relx=0.4, rely=0.5, anchor="center")
        self.relayLogoLabel.place(relx=0.5, rely=0.1, anchor="center")
        self.relayLabel.place(relx=0.5, rely=0.2, anchor="center")
        self.uEntry.place(width=self.w / 5.48,
                          relx=0.53,
                          rely=0.4,
                          anchor="center")
        self.pEntry.place(width=self.w / 5.48,
                          relx=0.53,
                          rely=0.5,
                          anchor="center")

        self.stars: "list[Canvas._CanvasItemId]" = []
        self.scoords: "list[list[int, int, float]]" = []

        for i in range(10000):
            x: int = randint(-self.w * 2, self.w * 2)
            y: int = randint(-self.h * 2, self.h * 2)
            self.stars.append(
                self.c.create_line(
                    x,
                    y,
                    x + 1,
                    y + 1,
                    fill=choice(["yellow", "orange", "cyan", "white"]),
                ))
            if x != self.w / 2:
                self.scoords.append(
                    [x, y, (y - self.h / 2) / (x - self.w / 2)])
            else:
                self.scoords.append(
                    [x, y, (y - self.h / 2) / (x - self.w / 2 + 1)])
        self.update()

        self.theta: float = 0
        while self.rotate:
            for i in range(5000):
                self.c.move(
                    self.stars[i],
                    cos(self.theta) * 0.5,
                    sin(self.theta) * 0.5,
                )
            for i in range(5000, 7500):
                self.c.move(self.stars[i],
                            cos(self.theta) * 1,
                            sin(self.theta) * 1)
            for i in range(7500, 10000):
                self.c.move(self.stars[i],
                            cos(self.theta) * 2,
                            sin(self.theta) * 2)
            self.update()
            sleep(1 / 24)
            self.theta += pi / 1024

    def logout(self, *kwargs) -> None:
        """Sends the logout packet and exits the app if logged out."""
        try:
            self.s.send(
                self.b.encrypt(
                    dumps({
                        "type": "logout",
                        "sessionId": self.cook
                    }).encode()))
            k: "dict[str,Any]" = self.session_manager.get()
            self.session_manager.task_done()
            if k["id"] == 1:
                self.s.close()
                exit()
            else:
                pass

        except Exception as err:
            if self.cUname == "":
                self.s.close()
                exit()
            else:
                print("Server error")

    def login(self, u: str, p: str) -> None:
        """Sends the login packet and tries to login with the credentials."""
        try:
            p: bytes = self.hashPass(p)
            self.s.send(
                self.b.encrypt(
                    dumps({
                        "type": "login",
                        "uname": u,
                        "passwd": p
                    }).encode()))
            k: "dict[str,Any]" = self.session_manager.get()
            self.session_manager.task_done()
            if k["id"] == 0:
                self.pNotSameLabel.configure(text="Invalid Username/Password")
                self.pNotSameLabel.place(relx=0.5, rely=0.7, anchor="center")
            elif k["id"] == -1:
                self.pNotSameLabel.configure(text="User Already Online")
                self.pNotSameLabel.place(relx=0.5, rely=0.7, anchor="center")
            elif k["id"] == 1:
                self.rotate = False
                self.cook: str = k["sessionId"]
                self.cUname = u
                self.explode()

        except error as err:
            print("Server error")

    def signup(self, u: str, p: str, c: str) -> None:
        """Sends the signup packet and tries to signup with the credentials."""
        if p == c and len(p) >= 8 and len(u) >= 5 and u.isalnum():
            pkey: rsa.PublicKey = self.rsa_keys(u)
            p: bytes = self.hashPass(p)
            try:
                self.s.send(
                    self.b.encrypt(
                        dumps({
                            "type": "register",
                            "uname": u,
                            "passwd": p,
                            "pub": pkey.save_pkcs1().decode("utf-8"),
                        }).encode()))
                k: "dict[str,Any]" = self.session_manager.get()
                self.session_manager.task_done()
                if k["id"] == 0:
                    self.pNotSameLabel.configure(text="Internal Server Error")
                    self.pNotSameLabel.place(relx=0.5,
                                             rely=0.8,
                                             anchor="center")
                elif k["id"] == -1:
                    self.pNotSameLabel.configure(text="User already exists")
                    self.pNotSameLabel.place(relx=0.5,
                                             rely=0.8,
                                             anchor="center")
                elif k["id"] == 1:
                    self.rotate = False
                    self.cook: str = k["sessionId"]
                    self.cUname = u
                    self.explode()
            except error as err:
                print("Server error")

        elif not p == c:
            self.pNotSameLabel.place(relx=0.5, rely=0.8, anchor="center")

        elif len(p) < 8:
            self.pNotSameLabel.configure(
                text="Password should have 8 or more characters")
            self.pNotSameLabel.place(relx=0.5, rely=0.8, anchor="center")

        elif len(u) < 5:
            self.pNotSameLabel.configure(
                text="Username should have 5 or more characters")
            self.pNotSameLabel.place(relx=0.5, rely=0.8, anchor="center")
        elif not u.isalnum():
            self.pNotSameLabel.configure(
                text="Username must not have special characters or spaces")
            self.pNotSameLabel.place(relx=0.5, rely=0.8, anchor="center")

    def rsa_keys(self, usrname: str) -> rsa.PublicKey:
        """Creates an RSA key pair for message encryption and decryption."""
        keys: "tuple(rsa.PublicKey,rsa.PrivateKey)" = rsa.newkeys(2048)
        publicKey: rsa.PublicKey = keys[0]
        privateKey: rsa.PrivateKey = keys[1]
        privfile = open(f".{usrname}priv.pem", "x")
        privfile.write(privateKey.save_pkcs1().decode("utf-8"))
        privfile.close()
        return publicKey

    def hashPass(self, p) -> bytes:
        """Hashes the password with sha512 hashing algorithm and encodes the hash with base64."""
        hasher: function = nacl.hash.sha512
        digest: bytes = b64encode(
            hasher(p.encode(), encoder=nacl.encoding.HexEncoder)).decode()
        return digest

    def showPasswd(self) -> None:
        """Shows the password in clear text in the password and confirm password fields."""
        self.pConfirm.configure(show="")
        self.pEntry.configure(show="")
        self.showPasswdButton.configure(command=self.hidePasswd)

    def hidePasswd(self) -> None:
        """Shows password in asterisks in the password and confirm password fields."""
        self.pConfirm.configure(show="*")
        self.pEntry.configure(show="*")
        self.showPasswdButton.configure(command=self.showPasswd)

    def pageLogin(self) -> None:
        """Switches the page to the login page."""
        self.passwdConfirmLabel.place_forget()
        self.pConfirm.place_forget()
        self.loginButtonFrame.place_configure(relx=0.55,
                                              rely=0.6,
                                              anchor="center")
        self.signupButtonFrame.place_configure(relx=0.45,
                                               rely=0.6,
                                               anchor="center")
        self.loginButton.configure(
            command=lambda: self.login(self.uEntry.get(), self.pEntry.get()))
        self.signupButton.configure(command=self.pageSignup)
        self.pNotSameLabel.place_forget()
        self.pEntry.configure(show="*")
        self.showPasswdButton.configure(command=self.showPasswd)

    def pageSignup(self) -> None:
        """Switches the page to the signup page."""
        self.passwdConfirmLabel.place(relx=0.4, rely=0.6, anchor="center")
        self.pConfirm.place(width=self.w / 5.48,
                            relx=0.53,
                            rely=0.6,
                            anchor="center")
        self.loginButtonFrame.place(relx=0.55, rely=0.7, anchor="center")
        self.signupButtonFrame.place(relx=0.45, rely=0.7, anchor="center")
        self.loginButton.configure(command=self.pageLogin)
        self.signupButton.configure(command=lambda: self.signup(
            self.uEntry.get(), self.pEntry.get(), self.pConfirm.get()))
        self.pNotSameLabel.place_forget()
        self.pConfirm.configure(show="*")
        self.pEntry.configure(show="*")
        self.showPasswdButton.configure(command=self.showPasswd)

    def explode(self) -> None:
        """Transition from login/signup to the messages page."""
        forgetters: "list[Any]" = [
            self.loginButtonFrame,
            self.signupButtonFrame,
            self.showPasswdButtonFrame,
            self.loginButton,
            self.signupButton,
            self.showPasswdButton,
            self.unameLabel,
            self.passwdLabel,
            self.passwdConfirmLabel,
            self.relayLogoLabel,
            self.relayLabel,
            self.uEntry,
            self.pEntry,
            self.pConfirm,
            self.pNotSameLabel,
        ]
        for i in forgetters:
            i.place_forget()
        while len(self.stars) > 0:
            for i in range(len(self.stars)):
                try:
                    x, y, m = self.scoords[i]
                    if m > 0:
                        if x > self.w / 2 and y > self.h / 2:
                            nc = ((x + (y / m) * 0.01), (y + (m * x) * 0.01))
                            self.c.coords(self.stars[i], x, y, nc[0], nc[1])
                            self.scoords[i] = [nc[0], nc[1], m]
                        elif x > self.w / 2 and y < self.h / 2:
                            nc = ((x + (y / m) * 0.01), (y - (m * x) * 0.01))
                            self.c.coords(self.stars[i], x, y, nc[0], nc[1])
                            self.scoords[i] = [nc[0], nc[1], m]
                        elif x < self.w / 2 and y > self.h / 2:
                            nc = ((x - (y / m) * 0.01), (y + (m * x) * 0.01))
                            self.c.coords(self.stars[i], x, y, nc[0], nc[1])
                            self.scoords[i] = [nc[0], nc[1], m]
                        else:
                            nc = ((x - (y / m) * 0.01), (y - (m * x) * 0.01))
                            self.c.coords(self.stars[i], x, y, nc[0], nc[1])
                            self.scoords[i] = [nc[0], nc[1], m]
                    elif m < 0:
                        if x > self.w / 2 and y > self.h / 2:
                            nc = ((x - (y / m) * 0.01), (y - (m * x) * 0.01))
                            self.c.coords(self.stars[i], x, y, nc[0], nc[1])
                            self.scoords[i] = [nc[0], nc[1], m]
                        elif x > self.w / 2 and y < self.h / 2:
                            nc = ((x - (y / m) * 0.01), (y + (m * x) * 0.01))
                            self.c.coords(self.stars[i], x, y, nc[0], nc[1])
                            self.scoords[i] = [nc[0], nc[1], m]
                        elif x < self.w / 2 and y > self.h / 2:
                            nc = ((x + (y / m) * 0.01), (y - (m * x) * 0.01))
                            self.c.coords(self.stars[i], x, y, nc[0], nc[1])
                            self.scoords[i] = [nc[0], nc[1], m]
                        else:
                            nc = ((x + (y / m) * 0.01), (y + (m * x) * 0.01))
                            self.c.coords(self.stars[i], x, y, nc[0], nc[1])
                            self.scoords[i] = [nc[0], nc[1], m]
                    else:
                        if x > self.w / 2 and y > self.h / 2:
                            nc = (
                                (x + (y / (m + 10**-2)) * 0.01),
                                (y + ((m + 10**-2) * x) * 0.01),
                            )
                            self.c.coords(self.stars[i], x, y, nc[0], nc[1])
                            self.scoords[i] = [nc[0], nc[1], m]
                        elif x > self.w / 2 and y < self.h / 2:
                            nc = (
                                (x + (y / (m + 10**-2)) * 0.01),
                                (y - ((m + 10**-2) * x) * 0.01),
                            )
                            self.c.coords(self.stars[i], x, y, nc[0], nc[1])
                            self.scoords[i] = [nc[0], nc[1], m]
                        elif x < self.w / 2 and y > self.h / 2:
                            nc = (
                                (x - (y / (m + 10**-2)) * 0.01),
                                (y + ((m + 10**-2) * x) * 0.01),
                            )
                            self.c.coords(self.stars[i], x, y, nc[0], nc[1])
                            self.scoords[i] = [nc[0], nc[1], m]
                        else:
                            nc = (
                                (x - (y / (m + 10**-2)) * 0.01),
                                (y - ((m + 10**-2) * x) * 0.01),
                            )
                            self.c.coords(self.stars[i], x, y, nc[0], nc[1])
                            self.scoords[i] = [nc[0], nc[1], m]

                    x, y, x2, y2 = self.c.coords(self.stars[i])
                    if ((x > self.w or x < 0) and
                        (x2 > self.w or x2 < 0)) or ((y > self.h or y < 0) and
                                                     (y2 > self.h or y2 < 0)):
                        self.c.delete(self.stars[i])
                        self.stars.pop(i)
                        self.scoords.pop(i)
                except Exception as err:
                    break

            self.update()
            sleep(1 / 120)

        self.postLogin()

    def postLogin(self) -> None:
        """Creates the messages page."""
        self.c.create_rectangle(
            -(self.w - 850 * self.scaleFactor),
            self.h,
            -self.h,
            0,
            fill="#080808",
            outline="#080808",
            tag="Chats",
        )
        self.c.create_rectangle(
            250 * self.scaleFactor,
            self.h * 2,
            self.w,
            self.h * 2 - 100 * self.scaleFactor,
            fill="#111111",
            outline="#111111",
            tag="MessageEntry",
        )

        for i in range(30):
            self.c.move("Chats", 30 * self.scaleFactor, 0)
            self.c.move("MessageEntry", 0, -30 * self.scaleFactor)
            self.update()
            sleep(1 / 60)

        self.mEntry: Entry = Entry(
            self,
            bg="#080808",
            fg="#AAAAAA",
            font=("Arial", 14),
            insertbackground="#00ff00",
            highlightthickness=0,
        )

        self.sendButton: Button = Button(
            self.sendButtonFrame,
            text="SEND",
            bd=0,
            image=self.send_btn,
            relief="sunken",
            command=lambda: self.send(self.mEntry.get()),
        )

        self.mEntry.place(
            relx=0.575,
            rely=0.95,
            anchor="center",
            height=self.h - (self.h - 50 * self.scaleFactor),
            width=self.w - 400 * self.scaleFactor,
        )
        self.sendButtonFrame.place(relx=0.975, rely=0.95, anchor="center")
        self.sendButton.place(relx=0.48, rely=0.48, anchor="center")

        self.drop: Listbox = Listbox(
            self,
            height=int(33 * self.scaleFactor),
            bg="#000000",
            fg="#00ff00",
            font=("Arial", 14),
            selectmode="single",
            highlightbackground="#000000",
        )

        self.drop.place(relx=0.0775, rely=0.465, anchor="center")

        self.onlineLabel: Label = Label(self,
                                        text="Online",
                                        bg="#080808",
                                        fg="#00ff00",
                                        font=("Arial", 14))

        self.onlineLabel.place(relx=0.0775, rely=0.0185, anchor="center")

        self.c.coords("Chats", 250 * self.scaleFactor, self.h, 0, 0)
        self.c.coords(
            "MessageEntry",
            250 * self.scaleFactor,
            self.h,
            self.w,
            self.h - 100 * self.scaleFactor,
        )

        self.mDisplayFrame: Frame = Frame(self, bg="#000000")

        self.mDisplay: st.ScrolledText = st.ScrolledText(
            self.mDisplayFrame,
            bg="#000000",
            fg="#00ff00",
            font=("Arial", 14),
            state="disabled",
            highlightbackground="#004400",
        )
        self.mDisplay.vbar.configure(
            troughcolor="#000000",
            bg="#004400",
            activebackground="#004400",
            relief="sunken",
        )

        self.mDisplayFrame.place(
            height=self.h - 100 * self.scaleFactor,
            width=self.w - 250 * self.scaleFactor,
            relx=0.578,
            rely=0.445,
            anchor="center",
        )
        self.mDisplay.place(
            height=self.h - 100 * self.scaleFactor,
            width=self.w - 250 * self.scaleFactor,
            relx=0.5,
            rely=0.5,
            anchor="center",
        )

        self.saveMessageButton: Button = Button(
            self.saveMessageButtonFrame,
            image=self.saveMSG,
            bg="#080808",
            fg="#00ff00",
            command=self.saveMessages,
            relief="sunken",
        )

        self.voiceButton: Button = Button(
            self.voiceButtonFrame,
            image=self.voiceImage,
            bg="#111111",
            fg="#00ff00",
            command=self.recognizeVoice,
            relief="sunken",
        )

        self.cUnameLabel: Label = Label(self,
                                        text=self.cUname,
                                        bg="#080808",
                                        fg="#00ff00",
                                        font=("Arial", 14))

        self.cUnameLabel.place(relx=0.0775, rely=0.9, anchor="center")
        self.saveMessageButtonFrame.place(relx=0.0789,
                                          rely=0.95,
                                          anchor="center")
        self.saveMessageButton.place(relx=0.49, rely=0.48, anchor="center")

        self.voiceButtonFrame.place(relx=0.175, rely=0.95, anchor="center")
        self.voiceButton.place(relx=0.48, rely=0.48, anchor="center")

        self.exitButton: Button = Button(
            self.exitButtonFrame,
            image=self.exitImage,
            bg="#080808",
            fg="#00ff00",
            command=self.logout,
            relief="sunken",
        )

        self.exitButton.place(relx=0.48, rely=0.48, anchor="center")
        self.exitButtonFrame.place(relx=0.0135, rely=0.0235, anchor="center")

        Thread(target=self.getOnline, daemon=True).start()

        self.dispname: str = ""
        self.after(100, self.chngChat)

        self.bind("<<ListboxSelect>>", self.setClicked)
        self.bind("<Key>", self.sendmsg)
        self.mainloop()

    def setClicked(self, event: Event) -> None:
        """Sets the clicked username variable."""
        try:
            self.clicked = self.onlineUsers[self.drop.curselection()[0]]
        except Exception as err:
            self.clicked = ""

    def sendmsg(self, event: Event) -> None:
        """Sends the message if return is pressed."""
        if event.keysym == "Return":
            self.send(self.mEntry.get())

    def chngChat(self) -> None:
        """Changes the chat to the one with the selected user in the dropdown menu."""
        if self.clicked != self.dispname:
            self.dispname = self.clicked
            try:
                self.mDisplay.configure(state="normal")
                self.mDisplay.delete("1.0", "end")
                self.mDisplay.insert("end", self.messages[self.dispname])
                self.mDisplay.configure(state="disabled")
                self.mDisplay.see("end")
            except KeyError:
                self.mDisplay.configure(state="normal")
                self.mDisplay.delete("1.0", "end")
                self.mDisplay.configure(state="disabled")
                self.mDisplay.see("end")
        self.after(100, self.chngChat)

    def send(self, m: str) -> None:
        """Sends message to the selected user in dropdown menu. If no user selected, gets list of online users and updates the dropdown menu."""
        try:
            if self.clicked != "" and m != "":
                if self.clicked not in self.pubKeys:
                    self.getKey()
                encKey = rsa.PublicKey.load_pkcs1(self.pubKeys[self.clicked])
                self.s.send(
                    self.b.encrypt(
                        dumps({
                            "type":
                            "message",
                            "sessionId":
                            self.cook,
                            "sUname":
                            self.cUname,
                            "rUname":
                            self.clicked,
                            "message":
                            b64encode(rsa.encrypt(m.encode(),
                                                  encKey)).decode(),
                        }).encode()))
                k: "dict[str,Any]" = self.messageStat.get()
                self.messageStat.task_done()
                timeStamp: str = (
                    "[" + str(datetime.now()).split()[1].split(".")[0][:5] +
                    "] ")
                if k["id"] == 1:
                    self.mDisplay.configure(state="normal")
                    self.mDisplay.insert(
                        "end",
                        ("\n" + timeStamp + "<" + self.cUname + "> " + m))
                    self.mDisplay.configure(state="disabled")
                    self.mDisplay.see("end")
                    self.mEntry.delete(0, "end")
                    self.mEntry.insert(0, "")

                    if self.clicked in self.messages:
                        self.messages[self.clicked] = (
                            self.messages[self.clicked] + "\n" + timeStamp +
                            "<" + self.cUname + "> " + m)
                    else:
                        self.messages[self.clicked] = (timeStamp + "<" +
                                                       self.cUname + "> " + m)
                elif k["id"] == 0:
                    print("user not online. WIP")
                else:
                    print("Session expired")

        except error as err:
            print("Server error")

    def getOnline(self) -> None:
        """Gets list of online users and updates the dropdown menu."""
        while True:
            try:
                self.s.send(
                    self.b.encrypt(
                        dumps({
                            "type": "get_online",
                            "sessionId": self.cook
                        }).encode()))
                k: "dict[str,Any]" = self.getting_online.get()
                k["online"].remove(self.cUname)
                self.getting_online.task_done()
                self.onlineUsers = k["online"]
                self.drop.delete(0, "end")
                for i in range(len(self.onlineUsers)):
                    self.drop.insert(i, self.onlineUsers[i])
            except error as err:
                print("Server error")
            sleep(30)

    def getKey(self) -> None:
        """Gets RSA public key of the selected user in the dropdown menu and updates the dropdown menu."""
        try:
            self.s.send(
                self.b.encrypt(
                    dumps({
                        "type": "get_key",
                        "uname": self.clicked,
                        "sessionId": self.cook,
                    }).encode()))
            k: "dict[str,Any]" = self.getting_key.get()
            self.getting_key.task_done()
            self.pubKeys[self.clicked] = k["key"]
        except error as err:
            print("Server error")

    def displayMessage(self, msgPacket: "dict[str,Any]") -> None:
        """Displays the message received in the chat area and updates the stored messages."""
        with open(f".{self.cUname}priv.pem", mode="rb") as privatefile:
            keydata: bytes = privatefile.read()
        privKey = rsa.PrivateKey.load_pkcs1(keydata)
        msg: str = rsa.decrypt(b64decode(msgPacket["message"].encode()),
                               privKey).decode()
        timeStamp: str = "[" + str(
            datetime.now()).split()[1].split(".")[0][:5] + "] "
        try:
            self.messages[msgPacket["sUname"]] = (
                self.messages[msgPacket["sUname"]] + "\n" + timeStamp + "<" +
                msgPacket["sUname"] + "> " + msg)
        except KeyError:
            self.messages[msgPacket["sUname"]] = (timeStamp + "<" +
                                                  msgPacket["sUname"] + "> " +
                                                  msg)

        if msgPacket["sUname"] == self.clicked:
            self.mDisplay.configure(state="normal")
            self.mDisplay.insert(
                "end",
                ("\n" + timeStamp + "<" + msgPacket["sUname"] + "> " + msg))
            self.mDisplay.configure(state="disabled")
            self.mDisplay.see("end")
        else:
            playsound("beep.mp3")

    def saveMessages(self, otherSave: "dict[str,Any]" = {}) -> None:
        """Saves the stored messages in a file."""
        try:
            if otherSave == {}:
                user: str = self.clicked
                with open(f"{self.cUname}-{user}.rel", "w") as savefile:
                    savefile.write(self.messages[user])

                self.s.send(
                    self.b.encrypt(
                        dumps({
                            "type": "saved_message",
                            "sessionId": self.cook,
                            "sUname": self.cUname,
                            "rUname": user,
                        }).encode()))

                k: "dict[str,Any]" = self.messageStat.get()
                self.messageStat.task_done()
                if k["id"] == 1:
                    if user == self.clicked:
                        self.mDisplay.configure(state="normal")
                        self.mDisplay.insert("end", ("\nYou saved the chat"))
                        self.mDisplay.configure(state="disabled")
                        self.mDisplay.see("end")
                        self.mEntry.delete(0, "end")
                        self.mEntry.insert(0, "")
                    self.messages[
                        user] = self.messages[user] + "\nYou saved the chat"

                elif k["id"] == 0:
                    print("user not online. WIP")
                else:
                    print("Session expired")

            else:
                user = otherSave["sUname"]
                if user == self.clicked:
                    self.mDisplay.configure(state="normal")
                    self.mDisplay.insert("end", (f"\n{user} saved the chat"))
                    self.mDisplay.configure(state="disabled")
                    self.mDisplay.see("end")
                    self.mEntry.delete(0, "end")
                    self.mEntry.insert(0, "")

                self.messages[
                    user] = self.messages[user] + f"\n{user} saved the chat"

        except KeyError:
            print("What do you want me to save?")

    def recognizeVoice(self):
        try:
            mic = speech_recognition.Microphone()
            recogniser = speech_recognition.Recognizer()
            with mic as source:
                audio = recogniser.listen(source)
            self.mEntry.insert("end", recogniser.recognize_google(audio))
        except Exception as err:
            print("There is an error with your mic")


if __name__ == "__main__":
    relayClient()
