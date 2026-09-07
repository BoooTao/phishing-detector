import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt
import re
from urllib.parse import urlparse

from sklearn.metrics import classification_report
import math
from collections import Counter
import requests
import joblib

#feature list for model
FEATURE_COLS = [
    "url_length", "domain_length", "num_dots", "num_hyphens", "num_digits",
    "num_special_chars", "has_ip", "has_at_symbol", "is_https",
    "num_subdomains", "path_depth", "has_shortener", "has_suspicious_word",
    "has_wp_path", "brand_edit_dist", "domain_entropy",
]


SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "update", "confirm", "bank", "signin"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]
WP_PATHS = ["wp-content", "wp-admin", "wp-includes"]
#prob lots of false positives

#typosquat list
BRANDS = ["paypal", "amazon", "apple", "google", "microsoft", "facebook",
          "netflix", "bankofamerica", "wellsfargo", "chase", "instagram"]

#since www exists
def get_domain_label(domain):
    parts = domain.split(".")
    return parts[-2] if len(parts) >= 2 else domain

#amount of change needed to get to a diff string, for typosquat.
def levenshtein(a, b):
    if len(a) < len(b):
        return levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            current_row.append(min(
                previous_row[j + 1] + 1,        # deletion
                current_row[j] + 1,             # insertion
                previous_row[j] + (ca != cb),   # substitution
            ))
        previous_row = current_row
    return previous_row[-1]

#random keyboard mash, malware primarily basically
def entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)

    return -sum((c/length ) * math.log2(c/length) for c in counts.values())


def extract(url):
    if not isinstance(url, str):
        url = ""

    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        domain = parsed.netloc
        path = parsed.path
    except ValueError:
        domain = ""
        path = ""

    domain_label = get_domain_label(domain)
    brand_dist = min((levenshtein(domain_label, b) for b in BRANDS), default=99)
    domain_entropy = entropy(domain_label)

    return {
        "url_length": len(url),
        "domain_length": len(domain),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": sum(url.count(c) for c in "@%=&?"),
        "has_ip": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain)),
        "has_at_symbol": "@" in url,
        "is_https": url.startswith("https://"),
        "num_subdomains": max(domain.count(".") - 1, 0),
        "path_depth": path.count("/"),
        "has_shortener": any(s in domain for s in SHORTENERS),
        "has_suspicious_word": any(w in url.lower() for w in SUSPICIOUS_WORDS),
        "has_wp_path": any(p in path.lower() for p in WP_PATHS),
        "brand_edit_dist": brand_dist,
        "domain_entropy": domain_entropy,
    }

def fetch_openphish():
    resp = requests.get("https://openphish.com/feed.txt")
    resp.raise_for_status()
    return [line.strip() for line in resp.text.splitlines() if line.strip()]

def main():
    df = pd.read_csv("data/malicious_phish.csv")
    print(df.columns)
    print(df.head())
    print(df["type"].value_counts())

    label_map = {
        "benign": "normal",
        "defacement": "normal",
        "phishing": "phishing",
        "malware": "malware",
    }

    df["label"] = df["type"].map(label_map)

    feature_df = df["url"].apply(extract).apply(pd.Series)
    df = pd.concat([df, feature_df], axis = 1)

    print(df.head())

    # explore whtv
    print(df["label"].value_counts())
    print(df.isna().sum())

    feature_cols = ["url_length", "num_dots", "num_hyphens", "has_ip",
                    "has_suspicious_word", "num_subdomains"]

    class_means = df.groupby("label")[feature_cols].mean()
    print(class_means.to_string())


    #actual classifying

    X = df[FEATURE_COLS].astype(float)
    y= df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )




    model = RandomForestClassifier(random_state=42, n_jobs=-1,
                                   class_weight={"normal": 1, "phishing": 12, "malware": 1},

                                   )

    model.fit(X_train, y_train)
    importances = pd.Series(model.feature_importances_, index=FEATURE_COLS)
    print(f"feature importances")
    print(importances.sort_values(ascending=False).to_string())
    predictions = model.predict(X_test)
    #report = classification_report(y_test, predictions, output_dict=True)
    print(f"start of report")
    print(classification_report(y_test, predictions))


    # opehphish check
    live_urls = fetch_openphish()
    live_features = pd.DataFrame([extract(u) for u in live_urls])
    X_live = live_features[FEATURE_COLS].astype(float)


    live_predictions = model.predict(X_live)
    caught = (live_predictions == "phishing").sum()
    print(f"live OpenPhish recall: {caught}/{len(live_predictions)} = {caught / len(live_predictions):.3f}")
   # end of check

    joblib.dump(model, "models/phishing_rf_model.joblib", compress=3)
    print("random forest model exported successfully")

    print("fin")

if __name__ == "__main__":
    main()


