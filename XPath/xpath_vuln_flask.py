from flask import Flask, request, make_response
import xml.etree.ElementTree as ET

app = Flask(__name__)

users_xml = """<?xml version="1.0"?>
<users>
    <user>
        <username>admin</username>
        <password>electraadmin123</password>
    </user>
    <user>
        <username>user</username>
        <password>electrauser123</password>
    </user>
</users>
"""

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return """
<form method="POST" action="/login">
    Username: <input type='text' name='username' /><br>
    Password: <input type='password' name='password' /><br>
    <input type='submit' value='Login' />
</form>
"""

    username = request.values.get("username", "")
    password = request.values.get("password", "")
    try:
        root = ET.fromstring(users_xml)
        xpath_expr = f".//user[username]='{username}' and password='{password}'"
        user = root.find(xpath_expr)

        if user is not None:
            return f"Welcome, {username}!"
        else:
            return "Invalid credentials."
    
    except ET.ParseError:
        return make_response("XML parsing error.", 500)
    except Exception as e:
        return make_response(f"An error occurred: {e}", 500)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)