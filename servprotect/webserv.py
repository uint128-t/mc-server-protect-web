from . import login
import flask
app = flask.Flask(__name__)
@app.route("/")
def index():
    print("Request from",flask.request.remote_addr)
    return flask.send_file("index.html")
@app.route("/login", methods=["POST"])
def login_post():
    name = flask.request.form["name"]
    code = flask.request.form["code"]
    print("Login request from",flask.request.remote_addr)
    if user:=login.login(name, code, flask.request.remote_addr):
        return f"Login successful as {user}. You have 60 seconds to connect to the Minecraft server."
    print("Login failed for",flask.request.remote_addr)
    return "Login failed", 401