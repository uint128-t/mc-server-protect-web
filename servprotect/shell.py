import readline
from . import login

def shell():
    while True:
        cmd = input("sp> ").strip().split()
        if cmd[0]=="exit":
            return
        if cmd[0]=="set":
            user = cmd[1]
            password = " ".join(cmd[2:])
            login.set_passsword(user,password)
            print(f"Password for user {user} set")
        if cmd[0]=="set_hashed":
            user = cmd[1]
            hashed = cmd[2]
            login.set_hashed_password(user,hashed)
            print(f"Hashed password for user {user} set")
        if cmd[0]=="login":
            user = cmd[1]
            address = cmd[2]
            login.login(user,None,address,bypass=True)
            print(f"User {user} logged in from {address} (bypass)")
