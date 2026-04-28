from feature_extractor import extract_features

url1 = "https://google.com"
url2 = "http://192.168.1.20/secure-login/verify-account.php"

print("Google:", extract_features(url1))
print("Suspicious:", extract_features(url2))

from feature_extractor import extract_features

url = "https://google.com"
features = extract_features(url)

print(len(features))
print(features)