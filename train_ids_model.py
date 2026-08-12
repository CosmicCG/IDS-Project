import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split

# Loading the dataset

csv_file = "Tuesday-WorkingHours.pcap_ISCX.csv" 
print(f"[*] Loading dataset from {csv_file}...")

df_raw = pd.read_csv(csv_file)
df_raw.columns = df_raw.columns.str.strip()

#Map & Filter Columns (Adapted to your CSV)

column_mapping = {
    "Destination Port": "dport",
    "Packet Length Mean": "length",
    "SYN Flag Count": "syn_flag",
    "ACK Flag Count": "ack_flag",
    "FIN Flag Count": "fin_flag",
    "Label": "label"                     
}

df = df_raw[list(column_mapping.keys())].rename(columns=column_mapping)


#Cleaning the data

print("[*] Cleaning data...")

# Binarize labels (0 = Normal, 1 = Attack)
df["label"] = df["label"].apply(lambda x: 0 if x == "BENIGN" else 1)

# Drop bad data
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()

feature_names = ["dport", "length", "syn_flag", "ack_flag", "fin_flag"]
for col in feature_names:
    df[col] = pd.to_numeric(df[col], errors='coerce')

df = df.dropna()
print(f"[+] Data cleaned. Usable rows: {len(df)}")

 #Training the Model using RandomForestClassfier

X = df[feature_names]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("[*] Training Random Forest model...")
rf_clf = RandomForestClassifier(
    n_estimators=100,
    max_depth=10, 
    random_state=42,
    n_jobs=-1  
)

rf_clf.fit(X_train, y_train)


#Evaluate and Export
y_pred = rf_clf.predict(X_test)
accuracy = accuracy_score(y_test, y_pred) * 100

print(f"\n[+] Model Accuracy: {accuracy:.2f}%\n")
print("Classification Report:")
print(classification_report(y_test, y_pred))

model_filename = "rf_ids_model.pkl"
joblib.dump(rf_clf, model_filename)
print(f"[+] Model successfully exported to '{model_filename}'")

