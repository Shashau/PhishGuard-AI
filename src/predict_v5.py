import joblib
import pandas as pd
import tldextract
import re
from scipy.sparse import csr_matrix, hstack


MODEL_PATH = "models/phishguard_v5_model.pkl"


# ==========================================
# Feature extraction
# ==========================================

def extract_features(url):
    url = str(url).strip()
    lower_url = url.lower()

    parsed = tldextract.extract(url)

    subdomain = parsed.subdomain
    domain = parsed.domain
    suffix = parsed.suffix

    features = {
        "url": lower_url,
        "domain_length": len(domain),
        "subdomain_length": len(subdomain),
        "subdomain_count": subdomain.count(".") + (1 if subdomain else 0),
        "suffix_length": len(suffix),
        "domain_digit_count": sum(c.isdigit() for c in domain),
        "domain_hyphen_count": domain.count("-"),
        "domain_dot_count": domain.count("."),
        "digit_count": sum(c.isdigit() for c in lower_url),
        "dot_count": lower_url.count("."),
        "hyphen_count": lower_url.count("-"),
        "at_count": lower_url.count("@"),
        "question_count": lower_url.count("?"),
        "equals_count": lower_url.count("="),
        "ampersand_count": lower_url.count("&"),
        "percent_count": lower_url.count("%"),
        "https": int(lower_url.startswith("https://")),
        "is_ip": int(
            re.match(
                r"^https?://(\d{1,3}\.){3}\d{1,3}",
                lower_url
            ) is not None
        ),
        "login_word": int("login" in lower_url),
        "signin_word": int("signin" in lower_url),
        "verify_word": int("verify" in lower_url),
        "account_word": int("account" in lower_url),
        "security_word": int("security" in lower_url),
        "password_word": int("password" in lower_url),
        "bank_word": int("bank" in lower_url),
        "payment_word": int("payment" in lower_url),
        "update_word": int("update" in lower_url),
        "long_subdomain": int(len(subdomain) > 15),
        "multiple_subdomains": int(subdomain.count(".") >= 2),
        "has_punycode": int("xn--" in lower_url),
    }

    return features


# ==========================================
# Load model
# ==========================================

model_data = joblib.load(MODEL_PATH)

model = model_data["model"]
vectorizer = model_data["vectorizer"]


# ==========================================
# Prediction
# ==========================================

def predict_url(url):

    url = url.strip().lower()

    features = extract_features(url)

    features_df = pd.DataFrame([features])

    structured = features_df.drop(columns=["url"]).values
    structured_sparse = csr_matrix(structured)

    parsed = tldextract.extract(url)

    domain_text = " ".join([
        parsed.subdomain,
        parsed.domain,
        parsed.suffix
    ])

    text_data = [domain_text + " " + url]

    url_tfidf = vectorizer.transform(text_data)

    final_features = hstack([
        url_tfidf,
        structured_sparse
    ])

    prediction = model.predict(final_features)[0]

    probabilities = model.predict_proba(final_features)[0]

    confidence = max(probabilities) * 100

    if prediction == 0:
        result = "PHISHING"
        emoji = "🔴"
    else:
        result = "LEGITIMATE"
        emoji = "🟢"

    print("\n===================================")
    print("        PHISHGUARD AI V5")
    print("===================================")
    print(f"URL: {url}")
    print(f"{emoji} RESULT: {result}")
    print(f"Confidence: {confidence:.2f}%")
    print("===================================")


# ==========================================
# Main
# ==========================================

if __name__ == "__main__":

    url = input("Enter a URL to check: ")

    predict_url(url)