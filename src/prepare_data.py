import pandas as pd

# Load dataset
df = pd.read_csv(
    "dataset/PhiUSIIL_Phishing_URL_Dataset.csv"
)

# Features selected for the first PhishGuard model
features = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "URLSimilarityIndex",
    "NoOfSubDomain",
    "HasObfuscation",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "NoOfDegitsInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
    "NoOfURLRedirect",
    "NoOfSelfRedirect",
    "HasExternalFormSubmit",
    "HasPasswordField",
    "Bank",
    "Pay",
    "Crypto"
]

# Create feature dataset
X = df[features]

# Target
y = df["label"]

print("Feature dataset shape:", X.shape)
print("Target shape:", y.shape)

print("\nSelected features:")
print(X.columns.tolist())

print("\nLabel distribution:")
print(y.value_counts())