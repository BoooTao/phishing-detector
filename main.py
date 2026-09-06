import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt
import re
from urllib.parse import urlparse


SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "update", "confirm", "bank", "signin"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]

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

    return {
        "url_length": len(url),
        "domain_length": len(domain),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": sum(url.count(c) for c in "@%=&?"),
        "has_ip": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain)),
        "has_at_symbol": "@" in url,
        "is_https": url.startswith("https"),
        "num_subdomains": max(domain.count(".") - 1, 0),
        "path_depth": path.count("/"),
        "has_shortener": any(s in domain for s in SHORTENERS),
        "has_suspicious_word": any(w in url.lower() for w in SUSPICIOUS_WORDS),
    }


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

    normalized = (class_means - class_means.mean()) / class_means.std()
    normalized.plot(kind="bar", figsize=(10, 6))
    plt.title("Relative feature differences by class (z-scored)")
    plt.ylabel("standard deviations from average")
    plt.tight_layout()
    plt.savefig("feature_comparison_normalized.png")
    plt.show()

    #actual classifying




    print("fin")

if __name__ == "__main__":
    main()


