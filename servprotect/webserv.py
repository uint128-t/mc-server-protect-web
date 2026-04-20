from . import login
import flask
app = flask.Flask(__name__)
@app.route("/")
def index():
    return flask.send_file("index.html")
@app.route("/login", methods=["POST"])
def login_post():
    code = flask.request.form["code"]
    if user:=login.login(code, flask.request.remote_addr):
        return f"Login successful as {user}. You have 60 seconds to connect to the Minecraft server."
    return "Login failed", 401