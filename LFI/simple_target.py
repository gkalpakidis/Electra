from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/")
def lfi():
    path = request.args.get("page", "")
    try:
        if ".." in path:
            return open(path).read()
        else:
            return "Nothing here."
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    app.run(debug=True)
    #app.run(port=5000)

"""
Command to run:
python .\Electra.py lfi -u "http://localhost:5000/?page=FUZZ" -w .\lfi\payloads.txt -t 5 -A
"""