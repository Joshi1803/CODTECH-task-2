Name :- Shivam Joshi

Company :- CODTECHITSOLUTION

I'd :-CT4CSEH3956

Domain :- Cyber Security & Ethical Hacking

Duration :- July to August

Mentor :- SANTHOSH KUMAR

Vulnerability Scanning Tool


Purpose:

The purpose of this tool is to scan a network or website for common security vulnerabilities, such as open ports, outdated software versions, and common misconfigurations. It leverages nmap for network scanning and requests for HTTP-based checks.

Components:

1)Imports and Configurations:

-import nmap: Imports the python-nmap library, which is a Python wrapper for the nmap command-line tool, used for network scanning.

-import requests: Imports the requests library for making HTTP requests.

-from requests.packages.urllib3.exceptions import InsecureRequestWarning: Imports a specific warning class from the urllib3 package used by requests.

-requests.packages.urllib3.disable_warnings(InsecureRequestWarning): Disables warnings for insecure HTTP requests (useful for ignoring SSL certificate warnings during scans).

 2)Function Definitions:

-scan_open_ports(target):

-Purpose: Scans the specified target IP address for open ports.

Logic:

-Initializes the nmap.PortScanner object.

-Scans ports 1-1024 on the target IP.

-Collects and returns a list of open ports.

-Includes error handling for potential nmap.PortScannerError and other exceptions.

3)check_outdated_software(url):

-Purpose: Checks the target URL for outdated software by inspecting the Server HTTP header.

Logic:

-Makes an HTTP GET request to the target URL.

-Retrieves and returns the Server header, which often includes software and version information.

-Includes error handling for request exceptions.

4)check_misconfigurations(url):

Purpose: Identifies common misconfigurations in the target URL.

Logic:

Makes an HTTP GET request to the target URL.

Checks for directory listing by looking for "Index of /" in the response text.

Makes an HTTP OPTIONS request to check for allowed HTTP methods, identifying insecure methods like TRACE.

Collects and returns a list of detected misconfigurations.

Includes error handling for request exceptions.

Main Function:

main():

Defines target IP and URL for scanning.

Calls the scan_open_ports() function and prints the results.

Calls the check_outdated_software() function and prints the server software info.

Calls the check_misconfigurations() function and prints the list of detected misconfigurations.
![Screenshot 2024-07-22 120248](https://github.com/user-attachments/assets/8cf4754c-84d1-44ad-9ba7-f724cd5f7c78)

Execution Block:

if __name__ == "__main__":: Ensures that the main() function is called only when the script is executed directly, not when imported as a module.
