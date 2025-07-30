from flask import Flask, request, Response, make_response
from xml.etree.ElementTree import Element, SubElement, tostring
import os

app = Flask(__name__)
UPLOAD_DIR = os.path.join("webdav", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route("/", methods=["OPTIONS", "PROPFIND", "PUT"])
@app.route("/<path:filename>", methods=["OPTIONS", "PROPFIND", "PUT"])
def handle_webdav(filename=""):
    method = request.method

    #OPTIONS (Vuln)
    if method == "OPTIONS":
        resp = make_response()
        resp.headers["Allow"] = "OPTIONS, PROPFIND, PUT"
        resp.headers["DAV"] = "1, 2"
        resp.headers["Content-Length"] = "0"
        return resp
    
    #OPTIONS (Sec)
    elif method == "OPTIONS":
        resp = make_response()
        resp.headers["Allow"] = "OPTIONS, GET, HEAD"
        resp.headers["Content-Length"] = "0"
        return resp
    
    #PROPFIND (Vuln)
    elif method == "PROPFIND":
        response = Element("{DAV:}multistatus")
        href = SubElement(response, "{DAV:}response")
        uri = SubElement(href, "{DAV:}href")
        uri.text = f"/{filename}" if filename else "/"
        return Response(
            tostring(response),
            status=207,
            mimetype="application/xml",
            headers={
                "DAV": "1, 2",
                "Content-Type": "application/xml"
            }
        )
    
    #PROPFIND (Sec)
    elif method == "PROPFIND":
        return Response("PROPFIND not supported", status=405)
    
    #PUT (Vuln)
    elif method == "PUT":
        file_path = os.path.join(UPLOAD_DIR, filename)
        with open(file_path, "wb") as f:
            f.write(request.data)
        return Response(f"Uploaded to {file_path}", status=201)
    
    #PUT (Sec)
    elif method == "PUT":
        return Response("Upload not allowed", status=403)
    
    return Response("Method not allowed", status=405)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)