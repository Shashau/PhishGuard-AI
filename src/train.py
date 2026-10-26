import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib


# ==========================================
# PHISHGUARD AI V3 — FEATURE EXTRACTION
# ==========================================

SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "confirm",
    "password",
    "credential",
    "bank",
    "wallet",
    "payment",
    "unlock",
    "suspended",
    "recover"
]


def extract_features(url):

    # Add protocol if missing
    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)

    # Extract domain
    domain = parsed.netloc.split("@")[-1].split(":")[0]

    path = parsed.path.lower()
    full_url = url.lower()

    # ==========================================
    # FEATURE SET
    # ==========================================

    features = {

        # --------------------------------------
        # DOMAIN FEATURES
        # --------------------------------------

        "domain_length": len(domain),

        "is_ip": int(bool(
            re.fullmatch(
                r"\d{1,3}(\.\d{1,3}){3}",
                domain
            )
        )),

        "subdomain_count": max(
            0,
            len(domain.split(".")) - 2
        ),

        # --------------------------------------
        # SECURITY
        # --------------------------------------

        "https": int(
            parsed.scheme.lower() == "https"
        ),

        # --------------------------------------
        # CHARACTER / STRUCTURE FEATURES
        # --------------------------------------

        "digit_count": sum(
            c.isdigit()
            for c in url
        ),

        "dot_count": url.count("."),

        "hyphen_count": url.count("-"),

        "at_count": url.count("@"),

        "question_count": url.count("?"),

        "equals_count": url.count("="),

        "ampersand_count": url.count("&"),

        "percent_count": url.count("%"),

        "query_length": len(parsed.query),

        # --------------------------------------
        # SUSPICIOUS WORD FEATURES
        # --------------------------------------

        "suspicious_word_count": sum(
            word in full_url
            for word in SUSPICIOUS_WORDS
        ),

        "login_word": int(
            "login" in full_url
            or "signin" in full_url
        ),

        "verify_word": int(
            "verify" in full_url
            or "verification" in full_url
        ),

        "account_word": int(
            "account" in full_url
        ),

        "security_word": int(
            "security" in full_url
            or "secure" in full_url
        ),

        "password_word": int(
            "password" in full_url
            or "credential" in full_url
        ),

        "bank_word": int(
            "bank" in full_url
        ),

        "payment_word": int(
            "payment" in full_url
            or "wallet" in full_url
        ),

        # --------------------------------------
        # PATH FEATURES
        # --------------------------------------

        "suspicious_path": int(
            any(
                word in path
                for word in SUSPICIOUS_WORDS
            )
        ),

        "double_slash_path": int(
            "//" in parsed.path
        ),

        # --------------------------------------
        # ENCODING / OBFUSCATION
        # --------------------------------------

        "has_punycode": int(
            "xn--" in domain.lower()
        )
    }

    return features


# ==========================================
# LOAD DATASET
# ==========================================

print("Loading dataset...")

df = pd.read_csv(
    "dataset/PhiUSIIL_Phishing_URL_Dataset.csv"
)

print("Dataset shape:", df.shape)


# ==========================================
# CREATE FEATURES
# ==========================================

print("\nExtracting URL features...")

X = pd.DataFrame(
    [
        extract_features(url)
        for url in df["URL"]
    ]
)

y = df["label"]


print("\nFeatures used:")

print(
    list(X.columns)
)

print(
    "\nTotal features:",
    len(X.columns)
)


# ==========================================
# TRAIN / TEST SPLIT
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# ==========================================
# TRAIN RANDOM FOREST
# ==========================================

print("\nTraining PhishGuard AI v3...")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(
    X_train,
    y_train
)


# ==========================================
# EVALUATION
# ==========================================

y_pred = model.predict(
    X_test
)

accuracy = accuracy_score(
    y_test,
    y_pred
)


print("\n=============================================")
print("        PHISHGUARD AI V3 MODEL")
print("=============================================")

print(
    f"Accuracy: {accuracy * 100:.2f}%"
)


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred
    )
)


print("\nConfusion Matrix:")

print(
    confusion_matrix(
        y_test,
        y_pred
    )
)


# ==========================================
# FEATURE IMPORTANCE
# ==========================================

importance = pd.Series(
    model.feature_importances_,
    index=X.columns
).sort_values(
    ascending=False
)


print("\nTop Feature Importances:")

print(
    importance.head(10)
)


# ==========================================
# SAVE MODEL
# ==========================================

model_data = {
    "model": model,
    "features": list(X.columns)
}


joblib.dump(
    model_data,
    "models/phishguard_model.pkl"
)


print("\n=============================================")
print("PhishGuard AI v3 saved successfully!")
print("models/phishguard_model.pkl")
print("=============================================")