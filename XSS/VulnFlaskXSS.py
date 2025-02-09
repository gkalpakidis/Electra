from flask import Flask, request, render_template_string

app = Flask(__name__)

memory = []

@app.route("/")
def root():
    return """
<h1>Vuln Flask XSS Website</h1>
<h2>Endpoints:</h2>
<ul>
    <li>
        <a href="/reflected?input=Electra">Reflected XSS</a>
    </li>
    <li>
        <a href="/stored">Stored XSS</a>
    </li>
    <li>
        <a href="/dom">DOM-based XSS</a>
    </li>
</ul>
"""

@app.route("/reflected")
def reflected():
    input = request.args.get("input", "")
    return f"<h3>Reflected XSS Test</h3><p>Input: {input}</p>"

@app.route("/stored", methods=["GET", "POST"])
def stored():
    global memory
    if request.method == "POST":
        input = request.form.get("input", "")
        memory.append(input)
    return render_template_string("""
<h3>Stored XSS Test</h3>
<form method="POST">
    <input type="text" name="input">
    <button type="submit">Submit</button>
</form>
<p>Stored Data:</p>
<ul>
    {% for item in memory %}
        <li>{{ item | safe }}</li>
    {% endfor %}
</ul>
""", memory=memory)

@app.route("/dom")
def dom():
    return """
<h3>DOM-based XSS Test</h3>
<input type="text" id"input" oninput="updateContent()">
<p id="output"></p>
<script>
    function updateContent() {
        var input = document.getElementById("input").value;
        document.getElementById("output").innerHTML = input;
    }
</script>
"""

if __name__ == "__main__":
    #app.run(debug=True, host="0.0.0.0", port=5000)
    app.run(debug=True)