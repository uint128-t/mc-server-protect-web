from . import login,console
import flask
app = flask.Flask(__name__)
@app.route("/")
def index():
    console.log("Request from",flask.request.remote_addr)
    return flask.send_file("index.html")
@app.route("/login", methods=["POST"])
def login_post():
    name = flask.request.form["name"]
    code = flask.request.form["code"]
    console.log("Login request from",flask.request.remote_addr)
    if user:=login.login(name, code, flask.request.remote_addr):
        return f"Login successful as {user}. You have 60 seconds to connect to the Minecraft server."
    console.log("Login failed for",flask.request.remote_addr)
    return "Login failed", 401