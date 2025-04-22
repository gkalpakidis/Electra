from flask import Flask, request, abort
import os

app = Flask(__name__)

filesystem = {
    "etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/sh",
    "proc/self/environ": "PATH=/usr/local/sbin:/usr/local/bin\nUSER=www-data\n",
    "windows/win.ini": "[fonts]\n[extensions]\n",
    "boot.ini": "[boot loader]\ntimeout=30\n",
    "system32/drivers/etc/hosts": "127.0.0.1 localhost\n192.168.1.1 router.local",
    "var/log/apache2/access.log": "192.168.0.1 - - [01/Jan/2023:00:00:01 +0000] GET /"
}

@app.route("/")
def lfi():
    path = request.args.get("page", "")
    original_path = path

    #Simulate null byte bypass (trim extensions after %00)
    if "%00" in path:
        path = path.split("%00")[0]
    
    #Normalize traversal (prevent /../../ abuse)
    #path = os.path.normpath(path).lstrip(".")
    path = os.path.normpath(path).replace("..", "").lstrip("/")

    #Simulate extension appending (.php etc)
    base_path = path.split(".")[0]
    for ext in ["php", "txt", "log", "ini"]:
        if path.endswith(f".{ext}") and f"{base_path}.{ext}" in filesystem:
            content = filesystem.get(f"{base_path}.{ext}")
            break
    else:
        content = filesystem.get(path, None)
    
    if content:
        return f"<pre>{content}</pre>"
    else:
        return f"File '{original_path}' not found or access denied.", 404

if __name__ == "__main__":
        app.run(debug=True, port=5001)
    #app.run(port=5000)

"""
Access page at: http://localhost:5001/?page=FUZZ
Command to run:
python .\Electra.py lfi -u "http://localhost:5001/?page=FUZZ" -w .\lfi\advanced_target_payloads.txt -t 10 -a "Electra/1.0" -d 0.1 -N -A -D 8 -E php,txt,log
"""