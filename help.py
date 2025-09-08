import pandas as pd
import requests
from datetime import datetime, timedelta
import os
from sklearn.preprocessing import StandardScaler, LabelEncoder
import numpy as np
import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ThreatDataCollector:
    def __init__(self):
        self.data_dir = "threat_data"
        os.makedirs(self.data_dir, exist_ok=True)

    def fetch_latest_cves(self, days=7):
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)


        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'resultsPerPage': 20  
        }

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        try:
            response = requests.get(url, params=params, headers=headers, timeout=30)
            
            if response.status_code != 200:
                logging.error(f"API returned status code: {response.status_code}")
                return pd.DataFrame()
                
            data = response.json()
            
            if 'vulnerabilities' not in data:
                logging.error("Unexpected API response format")
                return pd.DataFrame()
            
            cve_list = []
            for item in data['vulnerabilities']:
                cve_data = item['cve']
                metrics = cve_data.get('metrics', {})
                
                severity = 'UNKNOWN'
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    severity = metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']
                elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                    base_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                    if base_score >= 7.0:
                        severity = 'HIGH'
                    elif base_score >= 4.0:
                        severity = 'MEDIUM'
                    else:
                        severity = 'LOW'
                
                cve_list.append({
                    'cve_id': cve_data['id'],
                    'severity': severity,
                    'description': cve_data['descriptions'][0]['value'],
                    'published_date': cve_data['published'],
                    'last_modified': cve_data['lastModified']
                })
            
            return pd.DataFrame(cve_list)
            
        except Exception as e:
            logging.error(f"Error fetching CVEs: {e}")
            return self._generate_sample_cves()

    def _generate_sample_cves(self):
        sample_data = {
            'cve_id': [f'CVE-2023-{1000 + i}' for i in range(10)],
            'severity': ['HIGH', 'MEDIUM', 'CRITICAL', 'LOW', 'HIGH', 
                        'MEDIUM', 'CRITICAL', 'LOW', 'HIGH', 'MEDIUM'],
            'description': [f'Sample vulnerability description {i}' for i in range(10)],
            'published_date': [datetime.now().isoformat() for _ in range(10)],
            'last_modified': [datetime.now().isoformat() for _ in range(10)]
        }
        return pd.DataFrame(sample_data)

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
            cve_path = f"{self.data_dir}/cve_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            cve_data.to_csv(cve_path, index=False)
            logging.info(f"Saved CVE data to {cve_path}")

        if not traffic_data.empty:
            traffic_path = f"{self.data_dir}/traffic_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            traffic_data.to_csv(traffic_path, index=False)
            logging.info(f"Saved traffic data to {traffic_path}")

        return cve_data, traffic_data


class ThreatDataProcessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.encoder = LabelEncoder()

    def load_and_preprocess(self):
        if not os.path.exists('threat_data'):
            logging.warning("threat_data directory does not exist")
            return pd.DataFrame()
            
        cve_files = [f for f in os.listdir('threat_data') if f.startswith('cve_data') and f.endswith('.csv')]
        traffic_files = [f for f in os.listdir('threat_data') if f.startswith('traffic_data') and f.endswith('.csv')]
        
        if not cve_files and not traffic_files:
            logging.warning("No data files found in threat_data directory")
            return pd.DataFrame()
        
        cve_dfs = []
        for f in cve_files:
            try:
                df = pd.read_csv(f"threat_data/{f}")
                cve_dfs.append(df)
            except Exception as e:
                logging.error(f"Error reading {f}: {e}")
        
        traffic_dfs = []
        for f in traffic_files:
            try:
                df = pd.read_csv(f"threat_data/{f}")
                traffic_dfs.append(df)
            except Exception as e:
                logging.error(f"Error reading {f}: {e}")
        
        if cve_dfs:
            cve_df = pd.concat(cve_dfs, ignore_index=True)
            cve_features = self._process_cve_data(cve_df)
        else:
            cve_features = pd.DataFrame()
            
        if traffic_dfs:
            traffic_df = pd.concat(traffic_dfs, ignore_index=True)
            traffic_features = self._process_traffic_data(traffic_df)
        else:
            traffic_features = pd.DataFrame()
        
        if not cve_features.empty and not traffic_features.empty:
            cve_features['merge_key'] = range(len(cve_features))
            traffic_features['merge_key'] = range(len(traffic_features))
            
            combined_df = pd.merge(cve_features, traffic_features, on='merge_key', how='outer')
            combined_df = combined_df.drop('merge_key', axis=1)
        elif not cve_features.empty:
            combined_df = cve_features
        elif not traffic_features.empty:
            combined_df = traffic_features
        else:
            combined_df = pd.DataFrame()
            
        return combined_df.dropna() if not combined_df.empty else combined_df

    def _process_cve_data(self, df):
        if df.empty:
            return df
            
        df['severity_score'] = df['severity'].map({
            'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0
        }).fillna(0)

        return df[['severity_score', 'published_date']]

    def _process_traffic_data(self, df):
        if df.empty:
            return df
            
        df['traffic_risk'] = df['is_malicious'] * df['bytes'] / 1000
        return df[['traffic_risk']]


if __name__ == "__main__":
    collector = ThreatDataCollector()
    cve_data, traffic_data = collector.update_dataset()
    
    print("CVE Data:")
    print(cve_data.head())
    
    print("\nTraffic Data:")
    print(traffic_data.head())
    
    processor = ThreatDataProcessor()
    processed_data = processor.load_and_preprocess()
    
    print("\nProcessed Data:")
    print(processed_data.head())


