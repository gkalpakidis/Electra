from flask import Flask, make_response, request

app = Flask(__name__)

@app.route("/")
def index():
    response = make_response("<h1>Welcome to CookieServer!</h1>")

    response.set_cookie("SessionID", "ELECTRA123", secure=False, httponly=False)
    response.set_cookie("SessionID", "Electra123", secure=True, httponly=False)
    response.set_cookie("SessionID", "electra123", secure=True, httponly=True)
    response.set_cookie("UserPrefs", "darkmode=true")
    response.set_cookie("CSRFToken", "ELECTRA2025", secure=True, httponly=True, samesite="Lax")
    response.set_cookie("CSRFToken", "Electra2025", secure=False, httponly=False, samesite="Lax")
    return response

@app.route("/poison", methods=["GET"])
def poison_check():
    test_cookie = request.cookies.get("SessionID")
    #if test_cookie == "ELECTRA123" or test_cookie == "Electra123" or test_cookie == "electra123":
    if test_cookie == "Electra_Test_Cookie":
        return "<h2>Cookie Poisoning Detected</h2>", 403
    return "<h2>No Cookie Poisoning Detected</h2>"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)