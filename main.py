import pandas as pd
import subprocess
import json
import xml.etree.ElementTree as ET
import os
import re
import ipaddress
import logging
from colorama import init, Fore, Style
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import requests

logging.basicConfig(filename='scanner.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_ports(ports):
    valid_ports = []
    for port in ports:
        try:
            p = int(port)
            if 0 < p < 65536:
                valid_ports.append(p)
        except ValueError:
            continue
    return valid_ports

def train_model():
    data = pd.read_csv('data.csv')
    X = data.drop('target', axis=1)
    y = data['target']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier()
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    logging.info(f'Model trained with accuracy: {accuracy:.2f}')
    print(f"ML model accuracy: {accuracy:.2f}")

    return model, list(X.columns)


init(autoreset=True)
banner = f"""
{Fore.RED}

 ██ ▄█▀ ██▓▓██   ██▓ ▄▄▄         ▓█████  ███▄    █  ▄▄▄██▀▀▀ ██▓ ██▓        ██▓███   ▒█████   █     █░▓█████  ██▀███  
 ██▄█▒ ▓██▒ ▒██  ██▒▒████▄       ▓█   ▀  ██ ▀█   █    ▒██   ▓██▒▓██▒       ▓██░  ██▒▒██▒  ██▒▓█░ █ ░█░▓█   ▀ ▓██ ▒ ██▒
▓███▄░ ▒██▒  ▒██ ██░▒██  ▀█▄     ▒███   ▓██  ▀█ ██▒   ░██   ▒██▒▒██░       ▓██░ ██▓▒▒██░  ██▒▒█░ █ ░█ ▒███   ▓██ ░▄█ ▒
▓██ █▄ ░██░  ░ ▐██▓░░██▄▄▄▄██    ▒▓█  ▄ ▓██▒  ▐▌██▒▓██▄██▓  ░██░▒██░       ▒██▄█▓▒ ▒▒██   ██░░█░ █ ░█ ▒▓█  ▄ ▒██▀▀█▄  
▒██▒ █▄░██░  ░ ██▒▓░ ▓█   ▓██▒   ░▒████▒▒██░   ▓██░ ▓███▒   ░██░░██████▒   ▒██▒ ░  ░░ ████▓▒░░░██▒██▓ ░▒████▒░██▓ ▒██▒
▒ ▒▒ ▓▒░▓     ██▒▒▒  ▒▒   ▓▒█░   ░░ ▒░ ░░ ▒░   ▒ ▒  ▒▓▒▒░   ░▓  ░ ▒░▓  ░   ▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▓░▒ ▒  ░░ ▒░ ░░ ▒▓ ░▒▓░
░ ░▒ ▒░ ▒ ░ ▓██ ░▒░   ▒   ▒▒ ░    ░ ░  ░░ ░░   ░ ▒░ ▒ ░▒░    ▒ ░░ ░ ▒  ░   ░▒ ░       ░ ▒ ▒░   ▒ ░ ░   ░ ░  ░  ░▒ ░ ▒░
░ ░░ ░  ▒ ░ ▒ ▒ ░░    ░   ▒         ░      ░   ░ ░  ░ ░ ░    ▒ ░  ░ ░      ░░       ░ ░ ░ ▒    ░   ░     ░     ░░   ░ 
░  ░    ░   ░ ░           ░  ░      ░  ░         ░  ░   ░    ░      ░  ░                ░ ░      ░       ░  ░   ░     
            ░ ░                                                                                                       


{Style.RESET_ALL}
"""


def predict_vulnerabilities(model, features):
    pred = model.predict(pd.DataFrame([features]))
    return pred[0]

def scan_with_nmap(target_ip, options=None, timeout=60):
    if not validate_ip(target_ip):
        logging.error(f"Invalid IP address: {target_ip}")
        raise ValueError("Invalid IP address")

    logging.info(f"Starting nmap scan on {target_ip}")
    cmd = ['nmap', '-sV', '-T4', '-oX', '-']
    if options:
        cmd.extend(options)
    cmd.append(target_ip)

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=True)
        xml_output = result.stdout.decode()
        root = ET.fromstring(xml_output)

        scan_data = []
        for host in root.findall('host'):
            for port in host.findall('./ports/port'):
                port_id = int(port.get('portid'))
                protocol = port.get('protocol')
                state = port.find('state').get('state')
                service = port.find('service').get('name') if port.find('service') is not None else 'unknown'

                scan_data.append({
                    'port': port_id,
                    'protocol': protocol,
                    'state': state,
                    'service': service
                })

        logging.info(f"Scan finished on {target_ip} with {len(scan_data)} ports found.")
        return scan_data

    except subprocess.TimeoutExpired:
        logging.warning(f"Nmap scan timed out on {target_ip}")
        return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Nmap scan failed: {e}")
        return None
    except ET.ParseError:
        logging.error("Failed to parse nmap XML output.")
        return None

def fetch_cves(service_name):
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service_name}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            cves = [item['cve']['CVE_data_meta']['ID'] for item in data.get('result', {}).get('CVE_Items', [])]
            return cves[:5]  # return top 5 CVEs
    except Exception as e:
        logging.error(f"Failed to fetch CVEs for {service_name}: {e}")
    return []

VULNERABILITY_DB = {
    "http": {
        "vulnerability": "SQL Injection",
        "tool": "sqlmap",
        "exploit_command": "sqlmap -u http://{ip}/ --batch --dbs"
    },
    "ssh": {
        "vulnerability": "Weak password / brute force",
        "tool": "hydra",
        "exploit_command": "hydra -l root -P passwords.txt ssh://{ip}"
    },
}

def suggest_attacks(ip, services):
    suggestions = []

    for service in services:
        s = service.lower()
        if s in VULNERABILITY_DB:
            cves = fetch_cves(s)
            vuln = VULNERABILITY_DB[s]
            suggestions.append({
                "service": s,
                "vulnerability": vuln["vulnerability"],
                "cve": cves,
                "tool": vuln["tool"],
                "exploit_command": vuln["exploit_command"].format(ip=ip)
            })
        else:
            suggestions.append({
                "service": s,
                "vulnerability": "Unknown or no common exploits found",
                "cve": [],
                "tool": None,
                "exploit_command": None
            })

    return json.dumps(suggestions, indent=4)

def run_exploit(command_list, timeout=120):
    if not isinstance(command_list, list):
        logging.error("Exploit command should be a list of command parts.")
        raise ValueError("Command must be list of args")

    logging.info(f"Running exploit: {' '.join(command_list)}")
    try:
        result = subprocess.run(command_list, capture_output=True, text=True, timeout=timeout)
        logging.info(f"Exploit finished with return code {result.returncode}")
        return {
            "command": command_list,
            "success": result.returncode == 0,
            "output": result.stdout.strip(),
            "error": result.stderr.strip()
        }
    except subprocess.TimeoutExpired:
        logging.warning(f"Exploit timed out: {' '.join(command_list)}")
        return {
            "command": command_list,
            "success": False,
            "output": "",
            "error": "TimeoutExpired"
        }

def generate_report(ip, attacks, results, directory="reports"):
    os.makedirs(directory, exist_ok=True)

    safe_ip = re.sub(r'[^a-zA-Z0-9\-_.]', '_', ip)
    filename = os.path.join(directory, f"report_{safe_ip}.json")

    report = {
        "date": datetime.now().isoformat(),
        "target": ip,
        "attacks": attacks,
        "results": results
    }

    try:
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
        logging.info(f"Report saved to {filename}")
    except IOError as e:
        logging.error(f"Failed to save report: {e}")





if __name__ == "__main__":
    try:
        print(banner)

        model, feature_columns = train_model()

        target_ip = input("Enter target IP: ").strip()
        if not validate_ip(target_ip):
            print("Invalid IP address!")
            exit(1)

        ports_input = input("Enter open ports (comma-separated): ")
        ports = [p.strip() for p in ports_input.split(",")]
        open_ports = validate_ports(ports)
        if not open_ports:
            print("No valid ports entered!")
            exit(1)

        service_input = input("Enter service names (comma-separated): ")
        service_info = [s.strip() for s in service_input.split(",") if s.strip()]

        if service_info:
            sample_features = {col: 0 for col in feature_columns}
            pred = predict_vulnerabilities(model, sample_features)
            print(f"Predicted vulnerability class: {pred}")

        suggestions_json = suggest_attacks(target_ip, service_info)
        print(suggestions_json)

    except Exception as e:
        logging.error(f"Fatal error: {e}")
        print(f"Error occurred: {e}")