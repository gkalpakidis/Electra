from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    param = request.args.get("q") if request.method == "GET" else request.form.get("q")
    #SSI output (insecure echo of input)
    template = f"""
<html>
    <body>
        <h1>Electra Vulnerable Flask SSI Server</h1>
        <h2>The input was:</h2>
        <div>{param}</div>
    </body>
</html>
"""
    return render_template_string(template)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)