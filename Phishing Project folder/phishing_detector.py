from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import re
from sklearn.linear_model import LogisticRegression

# --------------------
# Flask setup
# --------------------
app = Flask(__name__)
CORS(app)

# --------------------
# Rule-based indicators
# --------------------
keywords = ["login", "secure", "account", "update", "verify", "bank"]
tlds = [".tk", ".ml", ".ga", ".cf"]
subdomains = ["node", "svc", "api", "gate", "hub"]
textfile = [".sh", ".exe", ".zip", ".vbs"]

# --------------------
# Load dataset
# --------------------
urls_df = pd.read_csv("urls.csv")
urls_df = urls_df.rename(columns={"URL's": "url", "Label": "label"})

# --------------------
# Feature extraction
# --------------------
def extract_features(url):
    url = url.lower()

    return [
        int(any(k in url for k in keywords)),
        int(any(t in url for t in tlds)),
        int("@" in url),
        int(url.startswith("http://")),
        int(len(url) > 75),
        url.count('.'),
        url.count('-'),
        url.count('/'),
        int(bool(re.search(r"http[s]?://\d+\.\d+\.\d+\.\d+", url))),
        sum(c.isdigit() for c in url),
        url.count('?'),
        url.count('&'),
        url.count('='),
        int(any(s in url for s in subdomains)),
        int(any(ext in url for ext in textfile))
    ]

# --------------------
# Train model
# --------------------
X = pd.DataFrame([extract_features(u) for u in urls_df["url"]])
y = urls_df["label"]

model = LogisticRegression()
model.fit(X, y)

# --------------------
# API endpoint
# --------------------
@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url", "").lower()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    reasons = []

    # --------------------
    # Rule checks
    # --------------------
    if any(k in url for k in keywords):
        reasons.append("Contains suspicious keywords")
    if any(t in url for t in tlds):
        reasons.append("Suspicious TLD detected")
    if "@" in url:
        reasons.append("Contains @ symbol")
    if url.startswith("http://"):
        reasons.append("Uses insecure HTTP")
    if len(url) > 75:
        reasons.append("Very long URL")

    # --------------------
    # ML prediction
    # --------------------
    features = pd.DataFrame([extract_features(url)])

    prob_malicious = model.predict_proba(features)[0][1]
    prob_safe = 1 - prob_malicious

    # --------------------
    # Final label
    # --------------------
    if prob_malicious > 0.7:
        label = "Malicious"
    elif prob_malicious > 0.4:
        label = "Suspicious"
    else:
        label = "Safe"

    # --------------------
    # Response
    # --------------------
    return jsonify({
        "url": url,
        "label": label,
        "safe_percent": round(prob_safe * 100, 2),
        "malicious_percent": round(prob_malicious * 100, 2),
        "reasons": reasons
    })

# --------------------
# Run server
# --------------------
if __name__ == "__main__":
    app.run(debug=True)