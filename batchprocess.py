import pandas as pd
import joblib
import numpy as np

model = joblib.load("malicious_detector.pkl")

data = pd.read_csv("Webpages_Classification_test_data.csv")

data['url_length'] = data['url'].astype(str).apply(len)
data['count_special_char'] = data['url'].astype(str).apply(
    lambda x: sum([1 for ch in x if ch in ['?', '=', '&', '%', '/', ';', '<', '>', '"', "'"]])
)

# Create missing model-required columns with default values
data['url_len'] = data['url_length']                 # or 0
data['js_len'] = 0
data['js_obf_len'] = 0

# Correct order of columns to match training
X = data[['url_length', 'count_special_char', 'url_len', 'js_len', 'js_obf_len']]

# Example simple scoring logic
def calculate_score(row):
    score = 0
    score += min(row['url_length'] / 5, 30)
    score += min(row['count_special_char'] * 10, 30)
    score += min(row['js_len'] / 50, 20)
    score += min(row['js_obf_len'] / 30, 20)
    return int(score)

data['risk_score'] = data.apply(calculate_score, axis=1)

# Predict
pred = model.predict(X)
data['prediction'] = pred

data.to_csv("predicted_361k.csv", index=False)
print("DONE: saved predicted_361k.csv")
