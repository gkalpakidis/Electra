
# Electra

Electra - The Master Plot Planner.


![](https://raw.githubusercontent.com/gkalpakidis/Electra/refs/heads/main/Misc/electra-logo.png)

## Run - Use Tool

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


## Commands / Features

- sscan = Scans a system using the hostname.
- nscan = Scans a network using an ip address.
- webpass = Performs a Web, Dictionary Password Brute Force attack.
- webuser = Performs a Web, Dictionary Username Brute Force attack.
- hashgen = Generates hash of a specific password.
- srvatk = Performs service, Dictionary, Password Brute Force attacks.
- webatk = Performs web (Basic & Digest) Username/Password Brute Force attacks.
- subenum = Performs Subdomain enumeration (Passive & Active).
- fuzz = Performs directory, file and parameter fuzzing.
- revsh = Spawns a Reverse Shell Handler.
- netstr = Performs DoS/DDoS attack.
- encheck = Performs service encryption analysis.
- exploit = Performs a search for an exploit.
- passperm = Perform password permutations.
- codec = Perform encoding & decoding.
- phish = Generate phishing emails or login pages.
- dwrecon = Perform Dark Web Reconnaissance.
- soceng = Perform Social Engineering attacks (Smishing & Vishing).
- cloudsec = Enumerate S3 buckets. Check for misconfigurations. Assess IAM Policies.
- privescdet = Privilege Escalation Detection.


## Using Electra

Examples:

```bash
python3 Electra.py webpass -u http://localhost:3000/Electra/login.php -U george -w ./passwords.txt
```
```bash
python3 Electra.py hashgen -f md5 -p root
```
## Screenshots

- sscan

![sscan](https://raw.githubusercontent.com/gkalpakidis/Electra/refs/heads/main/Misc/sscan.png)

- nscan

![nscan](https://raw.githubusercontent.com/gkalpakidis/Electra/refs/heads/main/Misc/nscan.png)

- webpass

![webpass](https://raw.githubusercontent.com/gkalpakidis/Electra/refs/heads/main/Misc/webpass.png)

- srvatk

![srvatk](https://raw.githubusercontent.com/gkalpakidis/Electra/refs/heads/main/Misc/srvatk-1.png)

![srvatk](https://raw.githubusercontent.com/gkalpakidis/Electra/refs/heads/main/Misc/srvatk-2.png)

## Authors

- [@gkalpakidis](https://github.com/gkalpakidis)
- [@Fl0w3r1](https://github.com/Fl0w3r1)
