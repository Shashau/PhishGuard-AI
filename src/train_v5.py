import pandas as pd
import numpy as np
import tldextract
import re
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# ==========================================
# PHISHGUARD AI V5
# Domain-Aware + URL Structure Detection
# ==========================================

DATASET_PATH = "dataset/PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_PATH = "models/phishguard_v5_model.pkl"


# ------------------------------------------
# Feature extraction
# ------------------------------------------

def extract_features(url):
    url = str(url).strip()
    lower_url = url.lower()

    parsed = tldextract.extract(url)

    subdomain = parsed.subdomain
    domain = parsed.domain
    suffix = parsed.suffix

    hostname = ".".join(
        part for part in [subdomain, domain, suffix] if part
    )

    # Basic URL structure
    features = {
        "url": lower_url,

        # Domain structure
        "domain_length": len(domain),
        "subdomain_length": len(subdomain),
        "subdomain_count": subdomain.count(".") + (1 if subdomain else 0),
        "suffix_length": len(suffix),

        # Domain characteristics
        "domain_digit_count": sum(c.isdigit() for c in domain),
        "domain_hyphen_count": domain.count("-"),
        "domain_dot_count": domain.count("."),

        # Full URL characteristics
        "digit_count": sum(c.isdigit() for c in lower_url),
        "dot_count": lower_url.count("."),
        "hyphen_count": lower_url.count("-"),
        "at_count": lower_url.count("@"),
        "question_count": lower_url.count("?"),
        "equals_count": lower_url.count("="),
        "ampersand_count": lower_url.count("&"),
        "percent_count": lower_url.count("%"),

        # Protocol
        "https": int(lower_url.startswith("https://")),

        # IP address detection
        "is_ip": int(
            re.match(
                r"^https?://(\d{1,3}\.){3}\d{1,3}",
                lower_url
            ) is not None
        ),

        # Suspicious URL words
        "login_word": int("login" in lower_url),
        "signin_word": int("signin" in lower_url),
        "verify_word": int("verify" in lower_url),
        "account_word": int("account" in lower_url),
        "security_word": int("security" in lower_url),
        "password_word": int("password" in lower_url),
        "bank_word": int("bank" in lower_url),
        "payment_word": int("payment" in lower_url),
        "update_word": int("update" in lower_url),

        # Suspicious domain structure
        "long_subdomain": int(len(subdomain) > 15),
        "multiple_subdomains": int(subdomain.count(".") >= 2),

        # Punycode
        "has_punycode": int("xn--" in lower_url),
    }

    return features


# ------------------------------------------
# Load dataset
# ------------------------------------------

print("\nLoading dataset...")

df = pd.read_csv(DATASET_PATH)

print("Dataset loaded successfully!")
print("Dataset shape:", df.shape)

print("\nLabel distribution:")
print(df["label"].value_counts())


# ------------------------------------------
# Extract structured features
# ------------------------------------------

print("\nExtracting domain-aware features...")

feature_rows = []

for url in df["URL"]:
    feature_rows.append(extract_features(url))

features_df = pd.DataFrame(feature_rows)

print("Feature extraction complete!")
print("Structured feature shape:", features_df.shape)


# ------------------------------------------
# Prepare text for TF-IDF
# ------------------------------------------

print("\nCreating hostname + URL text...")

text_data = []

for url in df["URL"]:
    url = str(url).lower()

    parsed = tldextract.extract(url)

    # Focus on domain structure rather than only path length
    domain_text = " ".join([
        parsed.subdomain,
        parsed.domain,
        parsed.suffix
    ])

    text_data.append(domain_text + " " + url)


# ------------------------------------------
# TF-IDF
# ------------------------------------------

print("\nTraining TF-IDF...")

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(2, 5),
    min_df=2,
    max_features=80000,
    sublinear_tf=True
)

X_text = vectorizer.fit_transform(text_data)

print("TF-IDF shape:", X_text.shape)


# ------------------------------------------
# Combine structured + TF-IDF features
# ------------------------------------------

X_structured = features_df.drop(columns=["url"]).values

from scipy.sparse import csr_matrix, hstack

X_structured_sparse = csr_matrix(X_structured)

X = hstack([
    X_text,
    X_structured_sparse
])

y = df["label"]


# ------------------------------------------
# Train/Test split
# ------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", X_train.shape[0])
print("Testing samples:", X_test.shape[0])


# ------------------------------------------
# Random Forest
# ------------------------------------------

print("\nTraining PhishGuard AI V5...")

model = RandomForestClassifier(
    n_estimators=250,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

model.fit(X_train, y_train)


# ------------------------------------------
# Evaluation
# ------------------------------------------

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\n===================================")
print("       PHISHGUARD AI V5 RESULTS")
print("===================================")

print(f"\nAccuracy: {accuracy * 100:.2f} %")

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        target_names=["Phishing", "Legitimate"]
    )
)

print("Confusion Matrix:")

print(confusion_matrix(y_test, predictions))


# ------------------------------------------
# Save model
# ------------------------------------------

joblib.dump(
    {
        "model": model,
        "vectorizer": vectorizer
    },
    MODEL_PATH
)

print("\nModel saved:")
print(MODEL_PATH)

print("\n===================================")
print("       V5 TRAINING COMPLETE")
print("===================================")