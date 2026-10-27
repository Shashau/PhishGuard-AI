import joblib
import pandas as pd
import tldextract
import re

from urllib.parse import urlparse
from scipy.sparse import csr_matrix, hstack


# ==========================================
# PHISHGUARD AI V6
# Hybrid Domain + ML Detection
# ==========================================


MODEL_PATH = "models/phishguard_v5_model.pkl"


# ==========================================
# Trusted registered domains
# ==========================================

TRUSTED_DOMAINS = {
    "amazon.in",
    "amazon.com",
    "amazon.co.uk",
    "amazon.ca",
    "amazon.de",
    "amazon.fr",
    "amazon.it",
    "amazon.es",
    "amazon.nl",

    "microsoft.com",
    "microsoftonline.com",

    "google.com",
    "google.co.in",

    "paypal.com",

    "apple.com",

    "facebook.com",
    "instagram.com",

    "linkedin.com",

    "github.com",

    "youtube.com",

    "netflix.com",

    "adobe.com",

    "cloudflare.com"
}


# ==========================================
# Load V5 model
# ==========================================

model_data = joblib.load(MODEL_PATH)

model = model_data["model"]
vectorizer = model_data["vectorizer"]


# ==========================================
# URL feature extraction
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

        "domain_length":
            len(domain),

        "subdomain_length":
            len(subdomain),

        "subdomain_count":
            subdomain.count(".") + (1 if subdomain else 0),

        "suffix_length":
            len(suffix),

        "domain_digit_count":
            sum(c.isdigit() for c in domain),

        "domain_hyphen_count":
            domain.count("-"),

        "domain_dot_count":
            domain.count("."),

        "digit_count":
            sum(c.isdigit() for c in lower_url),

        "dot_count":
            lower_url.count("."),

        "hyphen_count":
            lower_url.count("-"),

        "at_count":
            lower_url.count("@"),

        "question_count":
            lower_url.count("?"),

        "equals_count":
            lower_url.count("="),

        "ampersand_count":
            lower_url.count("&"),

        "percent_count":
            lower_url.count("%"),

        "https":
            int(lower_url.startswith("https://")),

        "is_ip":
            int(
                re.match(
                    r"^https?://(\d{1,3}\.){3}\d{1,3}",
                    lower_url
                ) is not None
            ),

        "login_word":
            int("login" in lower_url),

        "signin_word":
            int("signin" in lower_url),

        "verify_word":
            int("verify" in lower_url),

        "account_word":
            int("account" in lower_url),

        "security_word":
            int("security" in lower_url),

        "password_word":
            int("password" in lower_url),

        "bank_word":
            int("bank" in lower_url),

        "payment_word":
            int("payment" in lower_url),

        "update_word":
            int("update" in lower_url),

        "long_subdomain":
            int(len(subdomain) > 15),

        "multiple_subdomains":
            int(subdomain.count(".") >= 2),

        "has_punycode":
            int("xn--" in lower_url),
    }

    return features


# ==========================================
# Get registered domain
# ==========================================

def get_registered_domain(url):

    extracted = tldextract.extract(url)

    if not extracted.domain or not extracted.suffix:
        return ""

    return f"{extracted.domain}.{extracted.suffix}".lower()


# ==========================================
# Check trusted domain
# ==========================================

def is_trusted_domain(url):

    registered_domain = get_registered_domain(url)

    return registered_domain in TRUSTED_DOMAINS


# ==========================================
# Brand impersonation
# ==========================================

BRAND_DOMAINS = {

    "amazon": {
        "amazon.in",
        "amazon.com",
        "amazon.co.uk",
        "amazon.ca",
        "amazon.de",
        "amazon.fr",
        "amazon.it",
        "amazon.es",
        "amazon.nl"
    },

    "microsoft": {
        "microsoft.com",
        "microsoftonline.com"
    },

    "google": {
        "google.com",
        "google.co.in"
    },

    "paypal": {
        "paypal.com"
    },

    "apple": {
        "apple.com"
    },

    "facebook": {
        "facebook.com"
    },

    "instagram": {
        "instagram.com"
    },

    "linkedin": {
        "linkedin.com"
    },

    "github": {
        "github.com"
    }
}


def detect_brand_impersonation(hostname, registered_domain):

    hostname = hostname.lower()
    registered_domain = registered_domain.lower()

    for brand, official_domains in BRAND_DOMAINS.items():

        if brand in hostname and registered_domain not in official_domains:

            return brand

    return None


# ==========================================
# Detect suspicious domain structure
# ==========================================

def suspicious_domain(url):

    extracted = tldextract.extract(url)

    subdomain = extracted.subdomain.lower()
    domain = extracted.domain.lower()
    suffix = extracted.suffix.lower()

    score = 0
    reasons = []

    # --------------------------------------
    # Very long subdomain
    # --------------------------------------

    if len(subdomain) > 20:

        score += 2

        reasons.append(
            "very long subdomain"
        )

    # --------------------------------------
    # Multiple nested subdomains
    # --------------------------------------

    if subdomain.count(".") >= 2:

        score += 2

        reasons.append(
            "multiple nested subdomains"
        )

    # --------------------------------------
    # Punycode
    # --------------------------------------

    if "xn--" in url.lower():

        score += 3

        reasons.append(
            "punycode domain"
        )

    # --------------------------------------
    # Suspicious hyphens
    # --------------------------------------

    if domain.count("-") >= 2:

        score += 1

        reasons.append(
            "multiple hyphens in domain"
        )

    # --------------------------------------
    # Many digits
    # --------------------------------------

    if sum(c.isdigit() for c in domain) >= 3:

        score += 1

        reasons.append(
            "many digits in domain"
        )

    # --------------------------------------
    # Suspicious words inside domain
    # --------------------------------------

    suspicious_words = [
        "login",
        "signin",
        "verify",
        "secure",
        "security",
        "account",
        "update",
        "payment",
        "confirm",
        "support"
    ]

    found_words = [
        word
        for word in suspicious_words
        if word in domain
    ]

    if found_words:

        score += 2

        reasons.append(
            "suspicious domain word: "
            + ", ".join(found_words)
        )

    return score, reasons


# ==========================================
# ML prediction
# ==========================================

def ml_prediction(url):

    features = extract_features(url)

    features_df = pd.DataFrame([features])

    structured = features_df.drop(
        columns=["url"]
    ).values

    structured_sparse = csr_matrix(structured)

    extracted = tldextract.extract(url)

    domain_text = " ".join([
        extracted.subdomain,
        extracted.domain,
        extracted.suffix
    ])

    text_data = [
        domain_text + " " + url.lower()
    ]

    url_tfidf = vectorizer.transform(text_data)

    final_features = hstack([
        url_tfidf,
        structured_sparse
    ])

    prediction = model.predict(final_features)[0]

    probabilities = model.predict_proba(
        final_features
    )[0]

    confidence = max(probabilities) * 100

    return prediction, confidence


# ==========================================
# Main prediction engine
# ==========================================

def predict_url(url):

    url = url.strip()

    if not url:

        print("Please enter a URL.")

        return None

    # ======================================
    # Add protocol if missing
    # ======================================

    if not url.startswith(("http://", "https://")):

        url = "https://" + url

    registered_domain = get_registered_domain(url)


    # ======================================
    # Layer 1: Trusted domain verification
    # ======================================

    if is_trusted_domain(url):

        result = "LEGITIMATE"

        confidence = 99.99

        method = "Trusted registered-domain verification"

        reasons = [
            f"Verified registered domain: {registered_domain}"
        ]


    else:

        # ==================================
        # Layer 2: Brand impersonation check
        # ==================================

        parsed_url = urlparse(url)

        hostname = parsed_url.hostname or ""

        brand = detect_brand_impersonation(
            hostname,
            registered_domain
        )


        if brand:

            result = "PHISHING"

            confidence = 99.0

            method = "Brand impersonation detection"

            reasons = [
                f"Possible {brand.title()} brand impersonation",
                f"Registered domain is not an official {brand.title()} domain"
            ]


        else:

            # ==================================
            # Layer 3: Domain structure analysis
            # ==================================

            suspicious_score, reasons = suspicious_domain(url)


            # ==================================
            # Layer 4: V5 ML model
            # ==================================

            prediction, ml_confidence = ml_prediction(url)


            # ==================================
            # Strong suspicious domain
            # ==================================

            if suspicious_score >= 3:

                result = "PHISHING"

                confidence = max(
                    ml_confidence,
                    90 + min(
                        suspicious_score * 2,
                        8
                    )
                )

                method = "Domain structure + ML"


            # ==================================
            # ML says phishing
            # ==================================

            elif prediction == 0:

                result = "PHISHING"

                confidence = ml_confidence

                method = "V5 ML model"


            # ==================================
            # ML says legitimate
            # ==================================

            else:

                result = "LEGITIMATE"

                confidence = ml_confidence

                method = "V5 ML model"


    # ======================================
    # Display result
    # ======================================

    print("\n===================================")

    print("        PHISHGUARD AI V6")

    print("===================================")

    print(f"URL: {url}")

    print(
        f"Registered Domain: {registered_domain}"
    )


    if result == "PHISHING":

        print("\n🔴 RESULT: PHISHING")

    else:

        print("\n🟢 RESULT: LEGITIMATE")


    print(
        f"Confidence: {confidence:.2f}%"
    )

    print(
        f"Detection Method: {method}"
    )


    if reasons:

        print("\nAnalysis:")

        for reason in reasons:

            print(f"  • {reason}")


    print("===================================")


    # ======================================
    # Return result for Flask
    # ======================================

    return {
        "url": url,
        "registered_domain": registered_domain,
        "result": result,
        "confidence": round(confidence, 2),
        "method": method,
        "reasons": reasons
    }


# ==========================================
# Run
# ==========================================

if __name__ == "__main__":

    url = input(
        "Enter a URL to check: "
    )

    predict_url(url)