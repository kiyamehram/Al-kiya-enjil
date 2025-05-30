import pandas as pd

data = {
    "port": [22, 80, 443, 21],
    "service": ["ssh", "http", "https", "ftp"],
    "version": [7.2, 2.4, 1.1, 3.0],
    "target": [1, 1, 0, 0]
}

df = pd.DataFrame(data)

df = pd.get_dummies(df, columns=["service"])

df.to_csv("data.csv", index=False)
print("CSV file created with one-hot encoded 'service' column.")
