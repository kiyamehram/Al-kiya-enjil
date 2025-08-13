import pandas as pd
import requests
from datetime import datetime, timedelta
import os
from sklearn.preprocessing import StandardScaler, LabelEncoder
import numpy as np


class ThreatDataCollector:
    def __init__(self):
        self.data_dir = "threat_data"
        os.makedirs(self.data_dir, exist_ok=True)

    def fetch_latest_cves(self, days=7):
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
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

        combined_df = pd.merge(cve_features, traffic_features, how='outer', left_index=True, right_index=True)
        return combined_df.dropna()

    def _process_cve_data(self, df):
        df['severity_score'] = df['severity'].map({
            'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1
        }).fillna(0)

        return df[['severity_score', 'published_date']]

    def _process_traffic_data(self, df):
        df['traffic_risk'] = df['is_malicious'] * df['bytes'] / 1000
        return df[['traffic_risk']]


if __name__ == "__main__":
    collector = ThreatDataCollector()
    collector.update_dataset()

    processor = ThreatDataProcessor()
    processed_data = processor.load_and_preprocess()
    print(processed_data.head())


