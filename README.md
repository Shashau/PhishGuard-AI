# PhishGuard AI 🛡️

PhishGuard AI is a standalone Python-based phishing URL detection system that combines machine learning with domain-aware security rules and brand impersonation detection.

# 🛡️ PhishGuard AI

### AI-Powered Phishing URL Detection System

PhishGuard AI is a standalone Python-based cybersecurity project that detects potentially malicious URLs using a **hybrid approach combining machine learning, domain verification, domain-structure analysis, and brand impersonation detection**.

The project was developed as a practical cybersecurity and machine-learning learning project.

---

## 🎯 Objective

The goal of PhishGuard AI is to identify whether a URL is:

- 🟢 **Legitimate**
- 🔴 **Phishing**

The system is designed to detect both common phishing patterns and URLs that attempt to impersonate trusted brands.

---

## 🧠 Detection Architecture

PhishGuard AI V6 uses multiple detection layers:

### 1. 🌐 Trusted Registered-Domain Verification

Known legitimate domains are verified using their registered domain.

Examples:

```text
amazon.in
microsoft.com
paypal.com
google.com
```

This allows legitimate long URLs such as:

```text
https://www.amazon.in/gp/help/customer/display.html
```

to be recognized as legitimate when their registered domain is trusted.

### 2. 🎭 Brand Impersonation Detection

The system detects cases where a trusted brand name appears inside an unofficial registered domain.

Example:

```text
https://amazon.co.jp.amaznos.cc/login
```

Registered domain:

```text
amaznos.cc
```

The system identifies this as a possible Amazon impersonation attempt.

### 3. 🔍 Domain Structure Analysis

The detector analyzes suspicious domain characteristics including:

- Multiple subdomains
- Multiple hyphens
- Excessive digits
- Punycode
- Suspicious security-related words
- Domain structure

### 4. 🤖 Machine Learning

The ML engine is based on the **PhishGuard V5 model**, trained using the PhiUSIIL Phishing URL Dataset.

The V5 model achieved:

**99.76% holdout accuracy**

Confusion matrix:

```text
[[20096, 93],
 [   22, 26948]]
```

---

## 🧪 V6 Validation

The final V6 detector was tested using genuine and phishing-style URLs.

| Test | Expected | Result |
|---|---|---|
| Amazon genuine URL | Legitimate | ✅ PASS |
| Microsoft genuine URL | Legitimate | ✅ PASS |
| Microsoft impersonation | Phishing | ✅ PASS |
| Amazon impersonation | Phishing | ✅ PASS |
| PayPal impersonation | Phishing | ✅ PASS |
| PayPal genuine URL | Legitimate | ✅ PASS |

### Example

**Legitimate Amazon URL**

```text
https://www.amazon.in/gp/help/customer/display.html
```

```text
RESULT: LEGITIMATE
Confidence: 99.99%
Detection: Trusted registered-domain verification
```

**Amazon impersonation**

```text
https://amazon.co.jp.amaznos.cc/login
```

```text
RESULT: PHISHING
Confidence: 99.00%
Detection: Brand impersonation detection
```

**PayPal impersonation**

```text
http://paypal-login-security.com/verify-account
```

```text
RESULT: PHISHING
Confidence: 99.00%
Detection: Brand impersonation detection
```

---

## 📊 Dataset

PhishGuard AI was trained using the:

**PhiUSIIL Phishing URL Dataset**

Dataset characteristics:

- Records: **235,795**
- Features: **56**
- Legitimate URLs: **134,850**
- Phishing URLs: **100,945**

Labels:

```text
1 = Legitimate
0 = Phishing
```

The original dataset is **not included in this GitHub repository** because of its size.

---

## 📁 Project Structure

```text
PhishGuard-AI/
│
├── models/
│   └── phishguard_v5_model.pkl
│
├── src/
│   ├── predict.py
│   ├── predict_v4.py
│   ├── predict_v5.py
│   ├── predict_v6.py
│   ├── prepare_data.py
│   ├── train.py
│   ├── train_v4.py
│   └── train_v5.py
│
├── .gitignore
├── .gitattributes
├── README.md
└── requirements.txt
```

---

## ⚙️ Technologies Used

- Python
- Pandas
- NumPy
- Scikit-learn
- Matplotlib
- Seaborn
- tldextract
- Joblib
- Git
- Git LFS

---

## 🚀 Running PhishGuard AI

Clone the repository:

```bash
git clone https://github.com/Shashau/PhishGuard-AI.git
cd PhishGuard-AI
```

Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the V6 detector:

```bash
python src/predict_v6.py
```

Enter a URL when prompted.

Example:

```text
Enter a URL to check:
https://www.paypal.com
```

---

## ⚠️ Limitations

PhishGuard AI is a learning and research prototype.

Detection performance depends on:

- Training data quality
- Domain knowledge
- Trusted-domain coverage
- Evolving phishing techniques

A legitimate domain that is not included in the trusted-domain list may require additional analysis.

The system should not be considered a replacement for commercial phishing protection or enterprise security infrastructure.

---

## 🔮 Future Improvements

Possible future improvements include:

- Real-time URL reputation checks
- Larger and more diverse training datasets
- WHOIS and DNS-based analysis
- SSL/TLS certificate analysis
- External threat-intelligence integration
- More advanced brand impersonation detection
- Continuous model evaluation
- Browser security integration

---

## 📌 Project Status

**Current Version:** V6

**Status:** Working cybersecurity prototype ✅

**Validation:** 6/6 test cases passed

---

## 👨‍💻 Author

**Shashank H C**

BCA – Data Science

Cybersecurity & Digital Forensics Enthusiast

---

⭐ If you find this project useful, consider giving the repository a star.## 🎯 Objective

Detect whether a URL is:

- 🟢 Legitimate
- 🔴 Phishing

The system is designed to detect both common phishing patterns and URLs that attempt to impersonate trusted brands.

## 🧠 Detection Approach

PhishGuard AI V6 uses a hybrid detection approach:

1. **Trusted Registered-Domain Verification**
   - Verifies known legitimate domains such as:
     - amazon.in
     - amazon.com
     - microsoft.com
     - paypal.com
     - google.com

2. **Brand Impersonation Detection**
   - Detects trusted brand names appearing in unofficial domains.
   - Example:
     - `microsoft-login-security.com`
     - `paypal-login-security.com`

3. **Domain Structure Analysis**
   - Checks suspicious domain characteristics such as:
     - Multiple subdomains
     - Multiple hyphens
     - Excessive digits
     - Punycode
     - Suspicious security-related words

4. **Machine Learning**
   - Uses the trained PhishGuard V5 model as the ML detection engine.
   - The model was trained using the PhiUSIIL Phishing URL Dataset.

## 📊 Dataset

Dataset: PhiUSIIL Phishing URL Dataset

Records: 235,795

Features: 56

Labels:

- `1` = Legitimate
- `0` = Phishing

## 🧪 V6 Testing

| Test | Expected | Result |
|---|---|---|
| Amazon genuine URL | Legitimate | ✅ PASS |
| Microsoft genuine URL | Legitimate | ✅ PASS |
| Microsoft impersonation | Phishing | ✅ PASS |
| Amazon impersonation | Phishing | ✅ PASS |
| PayPal impersonation | Phishing | ✅ PASS |
| PayPal genuine URL | Legitimate | ✅ PASS |

### Example Results

**Legitimate:**
```text
https://www.amazon.in/gp/help/customer/display.html
→ LEGITIMATE
→ 99.99%
