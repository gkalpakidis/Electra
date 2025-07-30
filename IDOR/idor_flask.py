from flask import Flask, request, jsonify

app = Flask(__name__)

#Vuln DB
users = {
    1: {"id": 1, "username": "admin", "email": "admin@example.com"},
    2: {"id": 2, "username": "bob", "email": "bob@example.com"},
    3: {"id": 3, "username": "alice", "email": "alice@example.com"},
    4: {"id": 4, "username": "charlie", "email": "charlie@example.com"},
    5: {"id": 5, "username": "eve", "email": "eve@example.com"},
}

@app.route("/user", methods=["GET", "POST"])
def get_user():
    user_id = request.args.get("id") if request.method == "GET" else request.form.get("id")

    if not user_id or not user_id.isdigit():
        return jsonify({"error": "Invalid or missing ID"}), 400
    
    user_id = int(user_id)

    if user_id in users:
        return jsonify(users[user_id])
    else:
        return jsonify({"error": "User not found"}), 404
    
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)