# MAIPS – Multilayer Adaptive Intelligent Phishing System

## Project Overview

MAIPS (Multilayer Adaptive Intelligent Phishing System) is an intelligent browser-based phishing detection system designed to identify phishing websites using a multi-layer security architecture.

Unlike traditional phishing detectors that only classify websites as Safe or Phishing, MAIPS performs:

- URL-based Analysis
- Machine Learning Prediction
- Content Behavior Analysis
- Threat Intent Reasoning
- Explainable AI Detection
- Final Security Verdict Generation
- Real-time Browser Extension Scanning

This makes MAIPS a stronger and more practical cybersecurity solution for real-world phishing detection.

---

# Problem Statement

Traditional phishing detection systems rely only on basic blacklist checking or simple URL matching, which often fails against modern adaptive phishing attacks.

Phishing attackers now use:

- fake login pages
- brand impersonation
- credential harvesting forms
- malicious redirects
- account verification scams

To solve this, MAIPS introduces a multi-layer intelligent phishing detection system that combines rule-based analysis, machine learning, content inspection, and explainable AI for better accuracy and trust.

---

# Project Architecture

## Layer 1 – URL Analysis

### Features Implemented

- URL Length Detection
- IP Address Detection
- HTTPS Verification
- Suspicious Keyword Detection
- Dot Count Analysis
- Double Slash Detection
- Subdomain Depth Analysis
- Entropy Calculation
- Hyphen Detection
- @ Symbol Detection
- Brand Spoof Detection

### Purpose

Detect suspicious URL patterns before the page is fully trusted.

### Output

- Risk Score
- Circular Risk Meter
- URL Suspicion Indicators

---

## Layer 2 – Machine Learning Analysis

### Features Implemented

- Logistic Regression Model
- StandardScaler Integration
- Large Dataset Training
- Confidence Score Generation
- Hybrid Weighted Scoring
- Explainable Feature Contributions

### Purpose

Predict phishing probability intelligently using trained ML models.

### Output

- Safe / Phishing Prediction
- ML Confidence Score
- Circular Confidence Meter
- Feature Contribution Graphs

---

## Layer 3 – Content Analysis + Intent Reasoning

### Features Implemented

- Password Field Detection
- Form Detection
- External Form Action Detection
- Redirect Script Detection
- Suspicious Word Detection
- Known Brand Detection
- Threat Type Identification
- Severity Classification
- Explainable AI (“Why Flagged”)

### Threat Types

- Credential Harvesting
- Account Verification Scam
- Financial Phishing
- Malware / Redirect Attack
- Suspicious Phishing Attempt
- Safe Browsing

### Output

- Threat Type
- Severity Level
- Circular Severity Meter
- Why Flagged Section
- Graph Visualizations

---

## Final Security Verdict

### Final Decision Layer

Combines results from:

- Layer 1
- Layer 2
- Layer 3

to produce one final decision for the user.

### Output Includes

- SAFE WEBSITE / PHISHING DETECTED
- Final Confidence Score
- Threat Level
- Main Reason
- Final Circular Meter
- Final Summary Graph

This improves usability, explainability, and trust.

---

# Browser Extension

## Features

- Chrome Extension Integration
- Real-time Current Tab Scanning
- Automatic URL Detection
- Content Script Communication
- Flask Backend API Integration
- Premium Dashboard UI
- Live Phishing Detection
- Explainable Security Results

---

# UI Features

## Premium Dashboard

### Circular Meters Added For

- Layer 1 → Risk Score
- Layer 2 → ML Confidence
- Layer 3 → Threat Severity
- Final Security Verdict → Final Confidence

### Graph Visualizations Added For

- Feature Contributions
- Content Analysis Signals
- Final Threat Summary

### Visual Design

- Pink / Blue / Purple Gradients
- Animated Glowing Bars
- Professional Dark Security Dashboard
- Premium Extension Styling

This makes the project look like a real cybersecurity product.

---

# Explainable AI

Instead of only showing:

Safe / Phishing

MAIPS explains:

## Why Flagged

Examples:

- Fake login page detected
- Password field found on suspicious domain
- Brand impersonation detected
- Suspicious urgency language detected
- External suspicious form action found

This improves transparency and user trust.

---

# Technologies Used

## Frontend

- HTML
- CSS
- JavaScript

## Backend

- Python
- Flask
- Flask-CORS

## Machine Learning

- Scikit-learn
- Pandas
- NumPy
- Logistic Regression
- StandardScaler

## Browser Extension

- Chrome Extension Manifest V3

---

# Project Structure

```text
MAIPS/
│
├── backend/
│   ├── app.py
│   ├── dataset.csv
│   ├── feature_extractor.py
│   ├── generate_dataset.py
│   └── check_labels.py
│
├── extension/
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.css
│   ├── popup.js
│   ├── content.js
│   └── background.js
│
├── progress.md
├── README.md
└── requirements.txt