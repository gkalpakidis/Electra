from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/")
def index():
    print("\nWelcome to the Electra SSRF Server!")
    return "Welcome to the Electra SSRF Server!"

@app.route("/metadata")
def metadata():
    print("\nSSRF Attacked by Electra!")
    response_data = {
        "MOTD": "SSRF Attacked by Electra!",
        "Dev": "Georgios Kalpakidis"
    }

    return jsonify(response_data)

@app.route("/ssrf")
def ssrf():
    target = request.args.get("url")
    if target:
        print(f"\nReceived SSRF request for: {target}")
        if "169.254.169.254" in target:
            return jsonify({
                "SSRF": "Cloud SSRF Vulnerability!"
            })
        if "metadata" in target:
            return jsonify({
                "MOTD": "SSRF Attacked by Electra!",
                "Dev": "Georgios Kalpakidis"
            })
    return jsonify({
        "SSRF": "None"
    })

if __name__ == "__main__":
    app.run(debug=True)
    #app.run(host="0.0.0.0", port=8081)