import joblib


# =========================
# Load V4 Model
# =========================

MODEL_PATH = "models/phishguard_v4_model.pkl"

model_data = joblib.load(MODEL_PATH)

vectorizer = model_data["vectorizer"]
model = model_data["model"]


# =========================
# Prediction Function
# =========================

def predict_url(url):

    url_tfidf = vectorizer.transform([url])

    prediction = model.predict(url_tfidf)[0]

    probabilities = model.predict_proba(url_tfidf)[0]

    confidence = max(probabilities) * 100

    if prediction == 0:
        result = "PHISHING"
        emoji = "🔴"
    else:
        result = "LEGITIMATE"
        emoji = "🟢"

    print("\n===================================")
    print("        PHISHGUARD AI V4")
    print("===================================")
    print(f"{emoji} RESULT: {result}")
    print(f"Confidence: {confidence:.2f}%")
    print("===================================")


# =========================
# Main Program
# =========================

if __name__ == "__main__":

    url = input("Enter a URL to check: ")

    predict_url(url)