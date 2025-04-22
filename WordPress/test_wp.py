from flask import Flask, request

app = Flask(__name__)

@app.route("/wp-login.php", methods=["POST"])
def login():
    if request.form["username"] == "admin" and request.form["password"] == "admin":
        return "Dashboard"
    return "Login failed."

if __name__ == "__main__":
    app.run(debug=True)
    #app.run(host="0.0.0.0", port=8081)