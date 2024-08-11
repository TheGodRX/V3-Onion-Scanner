import stem
import socks
import requests
import socket
import logging
import time
import getpass
from stem.control import Controller
from bs4 import BeautifulSoup
from requests.exceptions import RequestException, HTTPError
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
SOCKS_PORT = 9050
CONTROL_PORT = 9051
COMMON_PORTS = [22, 80, 443, 8080, 3306, 5432, 6379]  # Extend as needed
DIRECTORIES_TO_CHECK = ['/admin', '/login', '/dashboard', '/uploads', '/config', '/data']
FILES_TO_CHECK = ['/config.php', '/wp-config.php', '/.env', '/admin.php']
TIMEOUT = 10  # Timeout for HTTP requests
RATE_LIMIT = 2  # Rate limit in seconds between requests

def get_hidden_service_descriptor(hidden_service, password):
    try:
        with Controller.from_port(port=CONTROL_PORT) as controller:
            controller.authenticate(password=password)
            descriptor = controller.get_hidden_service_descriptor(hidden_service)
            return descriptor
    except Exception as e:
        logger.error(f"Error getting hidden service descriptor: {e}")
        return None

def check_http_service(hidden_service):
    # Set up Socks proxy
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', SOCKS_PORT)
    socket.socket = socks.socksocket

    try:
        url = f"http://{hidden_service}"
        response = requests.get(url, proxies={'http': 'socks5h://127.0.0.1:9050'}, timeout=TIMEOUT)
        response.raise_for_status()  # Raise an HTTPError for bad responses

        # Analyze HTTP response
        logger.info(f"HTTP response from {hidden_service}:")
        logger.info(f"Status Code: {response.status_code}")
        logger.info(f"Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
        logger.info(f"Headers: {response.headers}")

        # Check security headers
        check_security_headers(response.headers)

        # Extract and analyze HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        logger.info(f"Page Title: {soup.title.string if soup.title else 'No title found'}")

        # Directory and file enumeration
        check_directories(hidden_service)
        check_files(hidden_service)

    except HTTPError as e:
        logger.error(f"HTTP error occurred while accessing {hidden_service}: {e}")
    except RequestException as e:
        logger.error(f"Request error occurred: {e}")

def check_directories(hidden_service):
    for directory in DIRECTORIES_TO_CHECK:
        url = f"http://{hidden_service}{directory}"
        try:
            response = requests.get(url, proxies={'http': 'socks5h://127.0.0.1:9050'}, timeout=TIMEOUT)
            if response.status_code == 200:
                logger.info(f"Directory found: {url}")
        except RequestException as e:
            logger.error(f"Error checking directory {url}: {e}")
        time.sleep(RATE_LIMIT)  # Respect rate limit

def check_files(hidden_service):
    for file in FILES_TO_CHECK:
        url = f"http://{hidden_service}{file}"
        try:
            response = requests.get(url, proxies={'http': 'socks5h://127.0.0.1:9050'}, timeout=TIMEOUT)
            if response.status_code == 200:
                logger.info(f"File found: {url}")
        except RequestException as e:
            logger.error(f"Error checking file {url}: {e}")
        time.sleep(RATE_LIMIT)  # Respect rate limit

def check_security_headers(headers):
    security_headers = {
        'Content-Security-Policy': 'Content-Security-Policy',
        'X-Content-Type-Options': 'X-Content-Type-Options',
        'X-Frame-Options': 'X-Frame-Options',
        'X-XSS-Protection': 'X-XSS-Protection',
        'Strict-Transport-Security': 'Strict-Transport-Security'
    }
    for header, name in security_headers.items():
        if header not in headers:
            logger.warning(f"Missing security header: {name}")

def scan_ports(hidden_service):
    open_ports = []
    for port in COMMON_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((hidden_service, port))
            if result == 0:
                open_ports.append(port)

    if open_ports:
        logger.info(f"Open ports on {hidden_service}: {open_ports}")
        for port in open_ports:
            detect_service(hidden_service, port)
    else:
        logger.info(f"No open ports found on {hidden_service}")

def detect_service(hidden_service, port):
    # Attempt to detect service by connecting and reading banner
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((hidden_service, port))
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            logger.info(f"Port {port} banner: {banner.strip()}")
    except Exception as e:
        logger.error(f"Error detecting service on port {port}: {e}")

def scan_ssl_tls(hidden_service):
    try:
        response = requests.get(f"https://{hidden_service}", proxies={'https': 'socks5h://127.0.0.1:9050'}, timeout=TIMEOUT)
        response.raise_for_status()
        logger.info(f"SSL/TLS is enabled on {hidden_service}")
        # Check SSL/TLS configurations using an external library
        # Example: Use `ssl` library or integrate tools like `sslscan`
    except RequestException as e:
        logger.warning(f"SSL/TLS might not be configured or is misconfigured on {hidden_service}: {e}")

def scan_hidden_service(hidden_service, password):
    try:
        descriptor = get_hidden_service_descriptor(hidden_service, password)
        if descriptor is None:
            logger.error(f"Failed to get hidden service descriptor for {hidden_service}")
            return

        logger.info(f"Hidden service descriptor for {hidden_service}:")
        logger.info(descriptor)

        check_http_service(hidden_service)
        scan_ports(hidden_service)
        scan_ssl_tls(hidden_service)

    except Exception as e:
        logger.error(f"Error scanning hidden service {hidden_service}: {e}")

def main():
    hidden_service = input("Enter the v3.onion hidden service to scan: ")
    password = getpass.getpass("Enter the Tor control password: ")
    scan_hidden_service(hidden_service, password)

if __name__ == "__main__":
    main()
