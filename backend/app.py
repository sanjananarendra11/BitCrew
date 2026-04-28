from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import pandas as pd
from feature_extractor import extract_features
import os

app = Flask(__name__)
CORS(app)

# =========================================
# DEBUG
# =========================================

print("RUNNING FILE FROM:", os.path.abspath(__file__))

# =========================================
# LOAD MODEL + SCALER
# =========================================

model = pickle.load(open("model.pkl", "rb"))
scaler = pickle.load(open("scaler.pkl", "rb"))

# MUST MATCH extract_features() EXACTLY (11 FEATURES)
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


# =========================================
# ROOT ROUTE
# =========================================

@app.route("/")
def home():
    return "Phishing Detection API is running!"


# =========================================
# PREDICT ROUTE
# =========================================

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.json
        url = data.get("url")
        content_data = data.get("content_data", {})

        if not url:
            return jsonify({
                "error": "No URL provided"
            }), 400

        # =========================================
        # LAYER 1 → URL FEATURE EXTRACTION
        # =========================================

        features = extract_features(url)

        if len(features) != len(columns):
            return jsonify({
                "error": f"Feature mismatch: expected {len(columns)}, got {len(features)}"
            }), 500

        features_df = pd.DataFrame([features], columns=columns)
        features_scaled = scaler.transform(features_df)

        # =========================================
        # LAYER 2 → ML PREDICTION
        # =========================================

        prediction = model.predict(features_scaled)[0]
        prob = model.predict_proba(features_scaled)[0][1]

        # =========================================
        # LAYER 3 → CONTENT ANALYSIS
        # =========================================

        has_password = content_data.get("hasPasswordField", False)
        form_count = content_data.get("formCount", 0)
        content_words = content_data.get("suspiciousWords", 0)
        external_form = content_data.get("hasExternalFormAction", False)
        redirect_script = content_data.get("hasRedirectScript", False)
        detected_brands = content_data.get("detectedBrands", [])

        # =========================================
        # SMART HYBRID PHISHING SCORE
        # =========================================

        phishing_score = 0

        # Strong URL signals
        if features[1] == 1:  # IP address
            phishing_score += 40

        if features[7] > 0:  # suspicious URL words
            phishing_score += 30

        if features[10] == 1:  # brand spoof
            phishing_score += 35

        if external_form:
            phishing_score += 40

        if has_password and features[10] == 1:
            phishing_score += 35

        # Medium signals
        if features[4] == 0:  # no https
            phishing_score += 10

        if redirect_script:
            phishing_score += 5

        if content_words >= 3:
            phishing_score += 10

        if form_count >= 3:
            phishing_score += 10

        # =========================================
        # FINAL PREDICTION
        # =========================================

        if phishing_score >= 60:
            final_pred = "Phishing"
        else:
            final_pred = "Safe"

        risk_score = min(phishing_score, 100)

        if final_pred == "Phishing":
            confidence = max(risk_score, int(prob * 100))
        else:
            confidence = max(100 - risk_score, int((1 - prob) * 100))

        # =========================================
        # LAYER 3 → THREAT TYPE + EXPLAINABILITY
        # =========================================

        threat_type = "Safe Browsing"
        severity = "Low"
        explanations = []

        # Credential Harvesting
        if has_password and features[10] == 1:
            threat_type = "Credential Harvesting"
            severity = "High"

            explanations.append(
                "Fake login page with password field detected"
            )
            explanations.append(
                "Brand impersonation detected"
            )

        # OTP / Verification Scam
        elif features[7] > 0 and content_words >= 3:
            threat_type = "Account Verification Scam"
            severity = "Medium"

            explanations.append(
                "Suspicious urgency language detected"
            )
            explanations.append(
                "Verify / Secure / Login patterns found"
            )

        # Malware Redirect Attack
        elif redirect_script and external_form:
            threat_type = "Malware / Redirect Attack"
            severity = "High"

            explanations.append(
                "Redirect script detected"
            )
            explanations.append(
                "External suspicious form action found"
            )

        # Financial Phishing
        elif (
            "paypal" in str(detected_brands).lower()
            or "bank" in str(detected_brands).lower()
        ):
            threat_type = "Financial Phishing"
            severity = "High"

            explanations.append(
                "Financial brand impersonation detected"
            )

        # Generic phishing
        elif final_pred == "Phishing":
            threat_type = "Suspicious Phishing Attempt"
            severity = "Medium"

            explanations.append(
                "Multiple phishing indicators detected"
            )

        # Safe browsing
        else:
            explanations.append(
                "No strong phishing indicators detected"
            )

        # =========================================
        # LAYER 1 DISPLAY DATA
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
        # LAYER 2 CONTRIBUTIONS
        # =========================================

        contributions = []

        if features[10] == 1:
            contributions.append({
                "name": "Brand Spoofing Detected",
                "impact": "+35"
            })

        if features[7] > 0:
            contributions.append({
                "name": "Suspicious URL Keywords",
                "impact": "+30"
            })

        if features[1] == 1:
            contributions.append({
                "name": "Uses IP Address",
                "impact": "+40"
            })

        if features[4] == 0:
            contributions.append({
                "name": "No HTTPS",
                "impact": "+10"
            })

        if has_password and features[10] == 1:
            contributions.append({
                "name": "Password Field on Suspicious Domain",
                "impact": "+35"
            })

        if external_form:
            contributions.append({
                "name": "External Form Submission",
                "impact": "+40"
            })

        if redirect_script:
            contributions.append({
                "name": "Redirect Script Found",
                "impact": "+5"
            })

        if content_words >= 3:
            contributions.append({
                "name": "Suspicious Page Content",
                "impact": "+10"
            })

        if form_count >= 3:
            contributions.append({
                "name": "Multiple Forms Detected",
                "impact": "+10"
            })

        if len(detected_brands) > 0:
            contributions.append({
                "name": "Known Brand Names Found",
                "impact": "+10"
            })

        # =========================================
        # FINAL RESPONSE
        # =========================================

        return jsonify({
            "url": url,
            "prediction": final_pred,
            "risk_score": risk_score,

            "layer1": layer1,

            "layer2": {
                "confidence": confidence,
                "contributions": contributions
            },

            "layer3": {
                "threat_type": threat_type,
                "severity": severity,
                "explanations": explanations
            }
        })

    except Exception as e:
        print("ERROR:", e)
        return jsonify({
            "error": str(e)
        }), 500


# =========================================
# RUN SERVER
# =========================================

if __name__ == "__main__":
    app.run(debug=True)