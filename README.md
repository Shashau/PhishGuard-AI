# PhishGuard AI 🛡️

PhishGuard AI is a standalone Python-based phishing URL detection system that combines machine learning with domain-aware security rules and brand impersonation detection.

## 🎯 Objective

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
