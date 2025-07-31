
# ℹ️ Electra

- **Electra (The Master Plot Planner)** is a custom penetration testing tool, written in python, containing many useful functions for an average penetration test.<br>
- Currently, Electra has **41** commands which range from **simple ones** _(system and network scanning)_ to **complex ones** _(api scanning and exploitation)_.<br>
- Many commands have their own directories with **vulnerable & secure test servers, payloads, wordlists, etc**. Most of the vulnerable targets are also written in **python** using **flask**.<br>
- This tool was developed because I wanted to sharpen my skills both in coding/scripting and cybersecurity/penetration testing.<br>
👍 I hope you find this tool useful and helpful. **_Happy penetration testing!_**


![](https://raw.githubusercontent.com/gkalpakidis/Electra/refs/heads/main/Misc/electra-logo.png)

## ▶️ Run - Use Tool

Clone the project

```bash
  git clone https://github.com/gkalpakidis/Electra
```

Go to the project directory

```bash
  cd Electra
```

Install requirements / dependencies

```bash
  pip install -r requirements.txt
```

Execute commands

```bash
  python3 Electra.py -h
```


## ⚡ Commands / Features

- sscan = Scans a system using the hostname.
- nscan = Scans a network using an ip address.
- webpass = Performs a Web, Dictionary Password Brute Force attack.
- webuser = Performs a Web, Dictionary Username Brute Force attack.
- hashgen = Generates hash of a specific password.
- hashcrk = Crack a hash or a list of hashes.
- srvatk = Performs service, Dictionary, Password Brute Force attacks.
- webatk = Performs web (Basic & Digest) Username/Password Brute Force attacks.
- subenum = Performs Subdomain enumeration (Passive & Active).
- fuzz = Performs directory, file and parameter fuzzing.
- revsh = Spawns a Reverse Shell Handler.
- netstr = Performs DoS/DDoS attack.
- encheck = Performs service encryption analysis.
- exploit = Performs a search for an exploit.
- passperm = Perform password permutations.
- nanal = Perform network analysis. Capture and Analyse packets.
- codec = Perform encoding & decoding.
- phish = Generate phishing emails or login pages.
- dwrecon = Perform Dark Web Reconnaissance.
- soceng = Perform Social Engineering attacks (Smishing & Vishing).
- cloudsec = Enumerate S3 buckets. Check for misconfigurations. Assess IAM Policies.
- privescdet = Privilege Escalation Detection.
- wifiatk = Perform handshake captures. Analyze signal strength. Detect rogue APs. Crack WPA/WPA2 passwords.
- iotsec = Scan and exploit IoT devices.
- xsscan = Scan for XSS vulnerabilities.
- cryptaudit = Assess cryptographic implementations.
- csrf = Scan for CSRF vulnerabilities.
- ssrf = Scan for SSRF vulnerabilities.
- dbscan = Assess database vulnerabilities.
- dnskit = Generate domain names. Perform DNS queries. Estimate webpage similarity.
- wpscan = Scan wordpress websites.
- lfi = Perform Local File Inclusion vulnerability checks.
- xxe = Scan for XXE vulnerabilities.
- cookie = Scan and exploit cookie vulnerabilities.
- idor = Scan for Insecure Direct Object Reference vulnerability.
- ssi = Scan for Server-Side Includes Injection vulnerability.
- webserv = Scan for SOAP, WSDL and web services vulnerabilities.
- cors = Scan for CORS misconfigurations/vulnerabilities.
- xpath = Scan for XPath Injection Vulnerabilities.
- webdav = Scan and Exploit WebDAV vulnerabilities.
- api = Perform API scanning and exploitation.

📈
**_Total Commands/Features = 41_**

## 🗒️ Using Electra

Examples:

```bash
python3 Electra.py webpass -u http://localhost:3000/Electra/login.php -U george -w ./passwords.txt
```
```bash
python3 Electra.py hashgen -f md5 -p root
```
## 🖼️ Screenshots

- 🔎 nscan

![nscan](https://raw.githubusercontent.com/gkalpakidis/Electra/refs/heads/main/Misc/nscan.png)

- 🗡️ srvatk

![srvatk](https://raw.githubusercontent.com/gkalpakidis/Electra/refs/heads/main/Misc/srvatk-1.png)

![srvatk](https://raw.githubusercontent.com/gkalpakidis/Electra/refs/heads/main/Misc/srvatk-2.png)

➕
**Find more screenshots inside the Misc directory.**

## ✍️ Authors

- [@gkalpakidis](https://github.com/gkalpakidis)
- [@Fl0w3r1](https://github.com/Fl0w3r1)
