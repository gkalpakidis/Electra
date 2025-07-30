from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    param = request.args.get("q") if request.method == "GET" else request.form.get("q")
    safe_param = escape(param) if param else "No input provided."

    response = f"""
<html>
    <body>
        <h1>Electra Secure Flask SSI Server</h1>
        <h2>Your input was:</h2>
        <div>{safe_param}</div>
    </body>
</html>
"""
    return response

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)