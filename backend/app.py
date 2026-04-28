from pyexpat import features

from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import pandas as pd
from feature_extractor import extract_features
import os

app = Flask(__name__)
CORS(app)

# 🔍 Debug
print("RUNNING FILE FROM:", os.path.abspath(__file__))

# ✅ Load model & scaler
model = pickle.load(open("model.pkl", "rb"))
scaler = pickle.load(open("scaler.pkl", "rb"))

# ✅ MUST MATCH extract_features() (NOW 11 FEATURES)
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
    "brand_spoof"
]

print("DEBUG → Column count:", len(columns))


# 🔥 PREDICT ROUTE
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.json
        url = data.get("url")

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        # 🔹 Extract features
        features = extract_features(url)

        if len(features) != len(columns):
            return jsonify({
                "error": f"Feature mismatch: expected {len(columns)}, got {len(features)}"
            }), 500

        # 🔹 Convert to DataFrame
        features_df = pd.DataFrame([features], columns=columns)
        features_scaled = scaler.transform(features_df)

        # 🔹 ML Prediction
        prediction = model.predict(features_scaled)[0]
        prob = model.predict_proba(features_scaled)[0][1]

        # =========================================
        # 🔥 HYBRID DECISION (FIXED)
        # =========================================

        # 🚨 Strong phishing (brand spoof)
        # 🔥 FINAL HYBRID DECISION

        if (
            features[1] == 1 or          # IP address
            features[7] > 0 or           # suspicious words
            features[10] == 1 or         # brand spoof
            features[4] == 0 and features[0] > 50  # long + no HTTPS
        ):
            final_pred = "Phishing"

        elif (
            features[4] == 1 and
            features[1] == 0 and
            features[7] == 0 and
            features[10] == 0 and
            features[5] == 0
        ):
            final_pred = "Safe"

        else:
            final_pred = "Phishing" if prob > 0.5 else "Safe"

        # 🔹 Risk score (aligned)
        # 🔥 Better risk score logic

        if final_pred == "Phishing":
            # If strong phishing signals exist → force high risk
            if (
                features[1] == 1 or
                features[7] > 0 or
                features[10] == 1 or
                (features[4] == 0 and features[0] > 50)
            ):
                risk_score = max(int(prob * 100), 85)

            else:
                risk_score = int(prob * 100)

        else:
            risk_score = max(5, int((1 - prob) * 100))

        # =========================================
        # 🔥 LAYER 1 — URL ANALYSIS
        # =========================================
        layer1 = {
            "URL Length": features[0],
            "Uses IP Address": "Yes" if features[1] else "No",
            "@ Symbol": "Yes" if features[2] else "No",
            "Dot Count": features[3],
            "HTTPS": "Yes" if features[4] else "No",
            "Hyphens": features[5],
            "Subdomain Depth": features[6],
            "Suspicious Keywords": features[7],
            "Double Slash": features[8],
            "Entropy": round(features[9], 2),
            "Brand Spoof": "Yes" if features[10] else "No"
        }

        # =========================================
        # 🔥 LAYER 2 — ML CONTRIBUTIONS
        # =========================================
        contributions = []

        if features[10] == 1:
            contributions.append({
                "name": "Brand Spoofing Detected",
                "impact": "+40"
            })

        if features[7] > 0:
            contributions.append({
                "name": "Suspicious Keywords",
                "impact": "+30"
            })

        if features[1] == 1:
            contributions.append({
                "name": "Uses IP Address",
                "impact": "+25"
            })

        if features[4] == 0:
            contributions.append({
                "name": "No HTTPS",
                "impact": "+15"
            })
        
        # Better confidence calculation
        if final_pred == "Safe":
            confidence = 100 - risk_score
        else:
            confidence = risk_score

        # =========================================
        # 🔥 FINAL RESPONSE
        # =========================================
        return jsonify({
            "url": url,
            "prediction": final_pred,
            "risk_score": risk_score,

            "layer1": layer1,

            "layer2": {
                "confidence": confidence,
                "contributions": contributions
            }
        })

    except Exception as e:
        print("ERROR:", e)
        return jsonify({"error": str(e)}), 500


# 🔹 ROOT ROUTE
@app.route("/")
def home():
    return "Phishing Detection API is running!"


# 🚀 RUN SERVER
if __name__ == "__main__":
    app.run(debug=True)