import re
import math
from urllib.parse import urlparse
from collections import Counter


def entropy(s):
    if len(s) == 0:
        return 0

    prob = [n / len(s) for n in Counter(s).values()]
    return -sum(p * math.log2(p) for p in prob)


def check_brand_spoof(url):
    url = url.lower()

    suspicious_brands = [
        "google",
        "paypal",
        "amazon",
        "facebook",
        "microsoft",
        "apple",
        "icloud",
        "gmail",
        "instagram",
        "netflix",
        "bank",
        "sbi",
        "hdfc",
        "icici",
        "axis",
        "whatsapp",
        "telegram"
    ]

    for brand in suspicious_brands:
        if brand in url:
            return 1

    return 0


def extract_features(url):
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc if parsed.netloc else ""

        features = []

        # 1 URL length
        features.append(len(url))

        # 2 Uses IP address
        features.append(
            1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', netloc) else 0
        )

        # 3 @ symbol
        features.append(1 if "@" in url else 0)

        # 4 Dot count
        features.append(url.count("."))

        # 5 HTTPS
        features.append(1 if parsed.scheme == "https" else 0)

        # 6 Hyphen in domain
        features.append(1 if "-" in netloc else 0)

        # 7 Subdomain depth
        parts = netloc.split(".") if netloc else []
        depth = len(parts) - 2 if len(parts) > 2 else 0
        features.append(depth)

        # 8 Suspicious words
        suspicious_words = [
            "login",
            "verify",
            "secure",
            "account",
            "update",
            "bank",
            "password",
            "signin",
            "wallet",
            "confirm",
            "payment",
            "alert",
            "suspended"
        ]

        suspicious_count = sum(
            word in url.lower() for word in suspicious_words
        )
        features.append(suspicious_count)

        # 9 Double slash
        features.append(1 if url.count("//") > 1 else 0)

        # 10 Entropy
        features.append(entropy(url))

        # 11 Brand spoof detection
        brand_spoof = check_brand_spoof(url)
        features.append(brand_spoof)

        return features

    except Exception as e:
        print("Feature extraction error:", e)
        return [0] * 11