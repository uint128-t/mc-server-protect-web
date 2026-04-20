import hashlib
import getpass
pwd = getpass.getpass("Password: ")
print("SHA256:",hashlib.sha256(pwd.encode()).hexdigest())