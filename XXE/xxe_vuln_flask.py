#!/usr/bin/env python3

from flask import Flask, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

@app.route("/xml", methods=["POST"])

def xml():
    try:
        xml_data = request.data.decode()
        root = ET.fromstring(xml_data)
        response = f"Received: {root.findtext('data')}"
        return response, 200
    except Exception as e:
        return f"Error: {e}", 500

if __name__ == "__main__":
    #app.run(debug=True, host="0.0.0.0", port=5000)
    app.run(debug=True)