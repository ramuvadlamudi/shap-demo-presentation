import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
import shap
import warnings
warnings.filterwarnings("ignore")

# Load the feature CSV
try:
    df = pd.read_csv("shap_features.csv")
except FileNotFoundError:
    print("Error: shap_features.csv not found. Ensure the file exists in the working directory.")
    exit(1)

# Features for SHAP
features = [
    "is_suspicious_process", "is_high_risk_port", "is_suspicious_domain",
    "high_data_transfer", "high_dns_query_count", "connection_duration_norm",
    "bytes_sent_norm", "bytes_received_norm"
]

# Verify features exist in the dataframe
available_features = [f for f in features if f in df.columns]
if len(available_features) < len(features):
    print(f"Warning: Only {len(available_features)} features found in CSV: {available_features}")
    print(f"Missing features: {[f for f in features if f not in df.columns]}")

if not available_features:
    print("Error: No features available for processing. Exiting.")
    exit(1)

# Prepare data
X = df[available_features]
y = df["alert_label_binary"]

# Check for missing values
if X.isnull().any().any():
    print("Warning: Missing values detected in features. Filling with 0.")
    X = X.fillna(0)

# Check feature variance
variances = X.var()
print("Feature variances:")
for feature, var in variances.items():
    print(f"{feature}: {var:.4f}")
low_variance_features = [f for f, v in variances.items() if v < 0.01]
if low_variance_features:
    print(f"Warning: Low variance features detected (variance < 0.01): {low_variance_features}")

# Debug: Print shapes
print(f"Shape of X: {X.shape}")
print(f"Features used: {available_features}")

# Train a Logistic Regression model (simpler model to ensure all features are used)
model = LogisticRegression(random_state=42, max_iter=1000)
model.fit(X, y)

# Print feature coefficients
print("Feature coefficients:")
for feature, coef in zip(available_features, model.coef_[0]):
    print(f"{feature}: {coef:.4f}")

# Initialize SHAP explainer
explainer = shap.LinearExplainer(model, X)
shap_values = explainer.shap_values(X)

# Debug: Print shape of shap_values
print(f"Shape of shap_values: {shap_values.shape}")

# Prepare SHAP output
shap_output = {
    "_time": df["_time"],
    "host": df["host"],
    "user": df["user"]
}
# Initialize all SHAP columns with zeros
for feature in features:
    shap_output[f"shap_{feature}"] = np.zeros(len(df))

# Map SHAP values to corresponding features
for i, feature in enumerate(available_features):
    shap_output[f"shap_{feature}"] = shap_values[:, i]

# Create DataFrame and save to CSV
try:
    shap_df = pd.DataFrame(shap_output)
    shap_df.to_csv("shap_values_output.csv", index=False)
    print("SHAP values saved to shap_values_output.csv")
except ValueError as e:
    print(f"Error creating DataFrame: {e}")
    print("Inspect shap_output lengths:")
    for key, value in shap_output.items():
        print(f"{key}: {len(value)}")