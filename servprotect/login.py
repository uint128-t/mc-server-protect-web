import heapq
import threading
import time
import hashlib

code_user = {}
with open("passwords.txt","r") as f:
    for line in f:
        user,hash = line.strip().split(":")
        code_user[hash] = user

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

logins = {}
def ip_logged_in(address):
    return address in logins
def user_logged_in(address,user):
    return logins.get(address) == user

def delay_logout(address,delay):
    time.sleep(delay)
    logins.pop(address, None)

def login(code,address):
    # Simplified login logic - replace with actual authentication
    code = hash_password(code)
    if code in code_user:
        user = code_user[code]
        logins[address] = user
        print(f"User {user} logged in from {address}")
        threading.Thread(target=delay_logout,args=(address,60),daemon=True).start() # Auto logout after 60 seconds
        return user
    return None
