from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Demo credentials
USERNAME = "admin"
PASSWORD = "admin123"


@app.route("/")
def login():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def authenticate():

    username = request.form.get("username")
    password = request.form.get("password")

    if username == USERNAME and password == PASSWORD:
        return redirect(url_for("dashboard"))

    return "Invalid Username or Password"


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


if __name__ == "__main__":
 app.run(host="0.0.0.0", port=5000, debug=True)