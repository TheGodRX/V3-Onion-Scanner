Hidden Service Scanner
A Python script to scan and analyze v3 onion hidden services.

Table of Contents
Overview
Features
Requirements
Usage
Example Output
License
Overview
This script uses the Tor control protocol to scan and analyze v3 onion hidden services. It checks for open ports, detects services, and scans for security vulnerabilities.

Features
Scans for open ports on the hidden service
Detects services running on open ports
Scans for security vulnerabilities (e.g. missing security headers)
Checks for SSL/TLS configuration
Analyzes HTML content of the hidden service
Requirements
Python 3.x
stem library (for Tor control protocol)
requests library (for HTTP requests)
BeautifulSoup library (for HTML parsing)
Usage
To use this script, simply run it and enter the v3 onion hidden service to scan and the Tor control password:

python hidden_service_scanner.py
Enter the v3.onion hidden service to scan: <hidden_service>
Enter the Tor control password: <password>
		
Example Output
INFO:root:Hidden service descriptor for <hidden_service>:
INFO:root:HTTP response from <hidden_service>:
INFO:root:Status Code: 200
INFO:root:Content-Type: text/html
INFO:root:Headers: {'Content-Type': 'text/html',...}
INFO:root:Page Title: <title>
INFO:root:Directory found: http://<hidden_service>/admin
INFO:root:File found: http://<hidden_service>/config.php
INFO:root:Open ports on <hidden_service>: [22, 80, 443]
INFO:root:Port 22 banner: SSH-2.0-OpenSSH_7.4p1 Ubuntu-10
		
License
This script is released under the MIT License. See LICENSE.txt for details.
