from flask import Flask, request, make_response

app = Flask(__name__)

@app.route("/")
def home():
    resp = make_response("<h1>Welcome to Electra Advanced Cookie Server.</h1>")
    resp.set_cookie("sessionid", "electra1")
    resp.set_cookie("userprefs", "darkmode=true", httponly=True)
    resp.set_cookie("csrftoken", "electra123", secure=True, httponly=True, samesite="Strict")
    return resp

@app.route("/steal")
def steal():
    cookie = request.args.get("c")
    print(f"[!] Stolen cookie: {cookie}")
    return "Cookie stolen."

@app.route("/csrf", methods=["POST"])
def csrf():
    origin = request.headers.get("Origin")
    if origin and "127.0.0.1" in origin:
        return "CSRF vulnerability."
    return "No CSRF vulnerability.", 403

@app.route("/poison")
def poison():
    if request.cookies.get("sessionid") == "admin":
        return "<h2>Welcome admin!</h2>"
    return "<h2>User privileges</h2>"

@app.route("/rom")
def rom():
    resp = make_response("RomPager/4.07 UPnP/1.0")
    resp.headers["Server"] = "RomPager/4.07"
    return resp

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)