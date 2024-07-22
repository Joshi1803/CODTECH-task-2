import nmap
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def scan_open_ports(target, port_range='1-1024'):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, port_range)
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    if nm[host][proto][port]['state'] == 'open':
                        open_ports.append(port)
        return open_ports
    except Exception as e:
        return f"Error scanning ports: {e}"

def check_outdated_software(url):
    try:
        response = requests.get(url, verify=False)
        server = response.headers.get('Server', 'Unknown')
       
        return server
    except requests.exceptions.RequestException as e:
        return f"Error checking software: {e}"

def check_misconfigurations(url):
    misconfigurations = []
    try:
        response = requests.get(url, verify=False)
       
        if "Index of /" in response.text:
            misconfigurations.append("Directory Listing Enabled")

        options_response = requests.options(url, verify=False)
        allowed_methods = options_response.headers.get('Allow', '')
        if 'TRACE' in allowed_methods:
            misconfigurations.append("TRACE method allowed")

    except requests.exceptions.RequestException as e:
        misconfigurations.append(f"Error checking misconfigurations: {e}")
    
    return misconfigurations

def main():
    target_ip = '142.251.46.174'  
    target_url = 'https://www.google.com/'  

    print(f"Scanning for open ports on {target_ip}...")
    open_ports = scan_open_ports(target_ip)
    if isinstance(open_ports, list) and open_ports:
        print(f"Open ports found: {open_ports}")
    elif isinstance(open_ports, list):
        print("No open ports found.")
    else:
        print(open_ports)  

    print(f"\nChecking for outdated software on {target_url}...")
    software_info = check_outdated_software(target_url)
    print(f"Software info: {software_info}")

    print(f"\nChecking for misconfigurations on {target_url}...")
    misconfigurations = check_misconfigurations(target_url)
    if misconfigurations:
        print(f"Misconfigurations found: {misconfigurations}")
    else:
        print("No misconfigurations found.")

if __name__ == "__main__":
    main()
