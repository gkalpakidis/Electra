from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

@app.route("/")
def index():
    return "Electra CORS Vuln Flask Server."

@app.route("/api")
def api():
    response = make_response(jsonify({"message": "Vulnerable API data"}))

    #Vulnerable CORS misconfig
    origin = request.headers.get("Origin")

    #Reflect origin
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    
    return response

@app.route("/public")
def public():
    response = make_response(jsonify({"message": "Public Data"}))
    #Secure CORS config
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response

@app.route("/safe")
def safe():
    response = make_response(jsonify({"message": "Strictly configured"}))
    return response

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)