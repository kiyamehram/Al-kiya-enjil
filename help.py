import pandas as pd
import numpy as np

def generate_sample_data(num_samples=1000):
    np.random.seed(42)

    feature1 = np.random.randint(0, 1000, num_samples)
    feature2 = np.random.uniform(0, 1, num_samples)
    feature3 = np.random.normal(50, 15, num_samples)

    attack_types = ['normal', 'brute_force', 'sql_injection', 'dos', 'xss']
    attack_type = np.random.choice(attack_types, num_samples)

    target_map = {'normal': 0, 'brute_force': 1, 'sql_injection': 2, 'dos': 3, 'xss': 4}
    target = [target_map[a] for a in attack_type]

    df = pd.DataFrame({
        'feature1': feature1,
        'feature2': feature2,
        'feature3': feature3,
        'attack_type': attack_type,
        'target': target
    })

    df['attack_type_code'] = df['attack_type'].astype('category').cat.codes
    df.drop(columns=['attack_type'], inplace=True)

    return df

if __name__ == "__main__":
    df = generate_sample_data(1000)
    df.to_csv('data.csv', index=False)
    print("Sample data.csv file created successfully.")

