import re
import joblib
from urllib.parse import urlparse
import pandas as pd


# ==========================================
# LOAD PHISHGUARD AI V2 MODEL
# ==========================================

saved_model = joblib.load(
    "models/phishguard_model.pkl"
)

model = saved_model["model"]
features = saved_model["features"]


# ==========================================
# SUSPICIOUS WORDS
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


# ==========================================
# FEATURE EXTRACTION
# ==========================================

def extract_features(url):

    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)

    domain = parsed.netloc.split("@")[-1].split(":")[0]

    path = parsed.path.lower()
    full_url = url.lower()

    data = {

        "url_length": len(url),

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

        "https": int(
            parsed.scheme.lower() == "https"
        ),

        "digit_count": sum(
            c.isdigit() for c in url
        ),

        "special_char_count": sum(
            not c.isalnum() for c in url
        ),

        "dot_count": url.count("."),

        "hyphen_count": url.count("-"),

        "at_count": url.count("@"),

        "question_count": url.count("?"),

        "equals_count": url.count("="),

        "ampersand_count": url.count("&"),

        "percent_count": url.count("%"),

        "path_length": len(parsed.path),

        "query_length": len(parsed.query),

        # ==================================
        # PHISHING FEATURES
        # ==================================

        "suspicious_word_count": sum(
            word in full_url
            for word in SUSPICIOUS_WORDS
        ),

        "login_word": int(
            "login" in full_url or
            "signin" in full_url
        ),

        "verify_word": int(
            "verify" in full_url or
            "verification" in full_url
        ),

        "account_word": int(
            "account" in full_url
        ),

        "security_word": int(
            "security" in full_url or
            "secure" in full_url
        ),

        "password_word": int(
            "password" in full_url or
            "credential" in full_url
        ),

        "bank_word": int(
            "bank" in full_url
        ),

        "payment_word": int(
            "payment" in full_url or
            "wallet" in full_url
        ),

        "suspicious_path": int(
            any(
                word in path
                for word in SUSPICIOUS_WORDS
            )
        ),

        "double_slash_path": int(
            "//" in parsed.path
        ),

        "has_punycode": int(
            "xn--" in domain.lower()
        )
    }

    return pd.DataFrame([data])[features]


# ==========================================
# MAIN PROGRAM
# ==========================================

if __name__ == "__main__":

    url = input(
        "Enter a URL to check: "
    ).strip()

    X = extract_features(url)

    prediction = model.predict(X)[0]

    probabilities = model.predict_proba(X)[0]

    print("\n" + "=" * 45)
    print("          PHISHGUARD AI V2")
    print("=" * 45)

    if prediction == 0:

        confidence = probabilities[0] * 100

        print("🔴 RESULT: PHISHING")

    else:

        confidence = probabilities[1] * 100

        print("🟢 RESULT: LEGITIMATE")

    print(
        f"Confidence: {confidence:.2f}%"
    )

    print("=" * 45)