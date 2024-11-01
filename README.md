
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

- cdir = Create a new directory on a specific path.
- sscan = Scan a system using the hostname.
- webpass = Perform a Web, Dictionary Password Brute Force attack.
- webuser = Perform a Web, Dictionary Username Brute Force attack.
- hashgen = Generate hash of a specific password.
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

- webpass

![webpass](https://raw.githubusercontent.com/gkalpakidis/Electra/refs/heads/main/Misc/webpass.png)

## Authors

- [@gkalpakidis](https://github.com/gkalpakidis)
- [@Fl0w3r1](https://github.com/Fl0w3r1)
