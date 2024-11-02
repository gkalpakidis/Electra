
# Electra

Electra - The Master Plot Planner.


![](https://raw.githubusercontent.com/gkalpakidis/Electra/refs/heads/main/Misc/electra-logo.png)

## Release Notes

- Electra v1.1

Added nscan Command. Used to perform a network scan.

Added srvatk Command. Used to perform service (ssh, rdp etc) Dictionary Password Brute Force attacks.

Added webatk Command. Used to perform web (Basic & Digest) Username/Password Brute Force attacks.

Fixed bugs.
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

- cdir = Creates a new directory on a specific path.
- sscan = Scans a system using the hostname.
- nscan = Scans a network using an ip address.
- webpass = Performs a Web, Dictionary Password Brute Force attack.
- webuser = Performs a Web, Dictionary Username Brute Force attack.
- hashgen = Generates hash of a specific password.
- srvatk = Performs service, Dictionary, Password Brute Force attacks.
- webatk = Performs web (Basic & Digest) Username/Password Brute Force attacks.
## Using Electra

Examples:

```bash
python3 Electra.py webpass -u http://localhost:3000/Electra/login.php -U george -w ./passwords.txt
```
```bash
python3 Electra.py hashgen -f md5 -p root
```
## Screenshots

- cdir

![cdir](https://raw.githubusercontent.com/gkalpakidis/Electra/refs/heads/main/Misc/cdir.png)

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
