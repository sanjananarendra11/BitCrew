import pandas as pd
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix

# 🔹 Load dataset
df = pd.read_csv("dataset.csv")

print("Dataset shape:", df.shape)

# 🔹 Handle missing values
df = df.fillna(0)

# 🔹 Split features and label
X = df.drop("label", axis=1)
y = df["label"]

# 🔹 Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 🔹 Train-test split (stratified for better balance)
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

print("Training size:", X_train.shape)
print("Testing size:", X_test.shape)

# 🔹 Model (balanced for phishing detection)
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    random_state=42,
    class_weight="balanced"
)

model.fit(X_train, y_train)

# 🔹 Predictions
y_pred = model.predict(X_test)

# 🔹 Accuracy
accuracy = model.score(X_test, y_test)
print("\nAccuracy:", accuracy)

# 🔥 Detailed evaluation
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# 🔹 Save model + scaler
pickle.dump(model, open("model.pkl", "wb"))
pickle.dump(scaler, open("scaler.pkl", "wb"))

print("\n✅ Model and scaler saved!")