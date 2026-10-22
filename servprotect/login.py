from collections import deque
import threading
import time
import hashlib
import sqlite3
from . import console

con = sqlite3.connect("passwords.db",check_same_thread=False)
db = con.cursor()
db.execute("CREATE TABLE IF NOT EXISTS login (user TEXT PRIMARY KEY, password TEXT)")
database_lock = threading.Lock()

def set_passsword(user,password):
    password = hash_password(password)
    set_hashed_password(user,password)

def set_hashed_password(user,hashed):
    with database_lock:
        db.execute("INSERT OR REPLACE INTO login (user,password) VALUES (?,?)",(user,hashed))
        con.commit()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

logins = {} # user: address
def user_logged_in(address,user):
    return logins.get(user) == address

logout_queue = deque() # (logout_time, user)
def logout_thread():
    while True:
        if not logout_queue:
            time.sleep(1)
            continue
        now = time.monotonic()
        lgt,usr = logout_queue.popleft()
        time.sleep(max(0,lgt-now))
        logins.pop(usr,None)
        console.log(f"User {usr} logged out after timeout")

threading.Thread(target=logout_thread,daemon=True).start()

def login(user,code,address,bypass=False):
    global logout_queue
    # Simplified login logic - replace with actual authentication
    code = hash_password(code)
    with database_lock:
        res = db.execute("SELECT user FROM login WHERE user=? AND password=?", (user, code)).fetchone()
    if bypass or res:
        logins[user] = address
        console.log(f"User {user} logged in from {address}")
        logout_queue.append((time.monotonic() + 60, user))  # Logout after 60 seconds
        return user
    return None
