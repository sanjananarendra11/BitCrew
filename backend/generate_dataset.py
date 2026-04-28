import pandas as pd
from feature_extractor import extract_features

# 🔹 Load dataset
df = pd.read_csv("raw_urls.csv")

# 🔹 Normalize column names
df.columns = [col.lower() for col in df.columns]

# 🔹 Rename type → label
df.rename(columns={'type': 'label'}, inplace=True)

# 🔹 Convert labels to numeric
df['label'] = df['label'].map({
    'benign': 0,
    'safe': 0,
    'legitimate': 0,
    'malicious': 1,
    'phishing': 1
})

# 🔹 Drop invalid rows
df = df.dropna(subset=['label', 'url'])

data = []

for _, row in df.iterrows():
    try:
        features = extract_features(row['url'])

        # ✅ MUST MATCH FEATURE COUNT (11 now)
        if len(features) != 11:
            continue

        features.append(int(row['label']))
        data.append(features)

    except Exception:
        continue


# 🔹 Column names (MUST EXACTLY MATCH extract_features)
columns = [
    "url_length",
    "has_ip",
    "has_at",
    "dot_count",
    "https",
    "has_hyphen",
    "subdomain_depth",
    "suspicious_words",
    "double_slash",
    "entropy",
    "brand_spoof",
    "label"
]

# 🔹 Create dataframe
final_df = pd.DataFrame(data, columns=columns)

# 🔥 Handle NaN
final_df = final_df.fillna(0)

# 🔹 Save dataset
final_df.to_csv("dataset.csv", index=False)

print("✅ Dataset created:", final_df.shape)