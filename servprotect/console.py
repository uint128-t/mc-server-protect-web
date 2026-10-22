import readline
import sys
from . import login

def prompt():
    while True:
        cmd = input("sp> ").strip().split()
        if not cmd:
            continue
        try:
            if cmd[0]=="exit":
                sys.exit(0)
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
        except Exception as e:
            print("Error:",e)

def log(*args):
    print(end="\0337",flush=True)
    print("\r",flush=True)
    print(*args,flush=True,end="")
    print("sp> ",readline.get_line_buffer(),end="\0338",flush=True)