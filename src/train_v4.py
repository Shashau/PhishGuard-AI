import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# =========================
# 1. Load Dataset
# =========================

DATASET_PATH = "dataset/PhiUSIIL_Phishing_URL_Dataset.csv"

df = pd.read_csv(DATASET_PATH)

print("Dataset loaded successfully!")
print("Dataset shape:", df.shape)


# =========================
# 2. Prepare Data
# =========================

X = df["URL"].astype(str)
y = df["label"]

print("\nLabel distribution:")
print(y.value_counts())

# Dataset meaning:
# 0 = Phishing
# 1 = Legitimate


# =========================
# 3. Train-Test Split
# =========================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# =========================
# 4. Character-Level TF-IDF
# =========================

print("\nCreating character-level TF-IDF features...")

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    min_df=2,
    max_features=100000,
    sublinear_tf=True,
    lowercase=True
)

X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

print("TF-IDF training shape:", X_train_tfidf.shape)
print("TF-IDF testing shape:", X_test_tfidf.shape)


# =========================
# 5. Train Logistic Regression
# =========================

print("\nTraining Logistic Regression model...")

model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced"
)

model.fit(X_train_tfidf, y_train)


# =========================
# 6. Evaluate Model
# =========================

y_pred = model.predict(X_test_tfidf)

accuracy = accuracy_score(y_test, y_pred)

print("\n==============================")
print("PHISHGUARD AI V4 RESULTS")
print("==============================")

print("\nAccuracy:", round(accuracy * 100, 2), "%")

print("\nClassification Report:")
print(classification_report(
    y_test,
    y_pred,
    target_names=["Phishing", "Legitimate"]
))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))


# =========================
# 7. Save Model + Vectorizer
# =========================

model_data = {
    "vectorizer": vectorizer,
    "model": model
}

MODEL_PATH = "models/phishguard_v4_model.pkl"

joblib.dump(model_data, MODEL_PATH)

print("\nModel saved successfully!")
print("Saved to:", MODEL_PATH)

print("\nV4 training completed! 🚀")