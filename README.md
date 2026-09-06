# Phishing Detector (STILL WIP!)

A ml project that classifies URLs as **phishing**, **malware**, or **normal** based on structural and lexical features extracted directly from the URL string. no live requests to url to fetch n stuff

## Overview

- Trained on ~651k labeled URLs from the [Malicious URLs Dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) (Kaggle).
- Model: Random Forest classifier (scikit-learn), with class weighting to boost phishing recall since that was an issue
- Validated against a live OpenPhish feed for out-of-training testing with more recent links, as the kaggle database IS dated from around 2016.

## Features

16 features engineered from the URL string:

- **Structural**: URL length, domain length, path depth, subdomain count
- **Lexical**: dot/hyphen/digit/special-character counts, suspicious keywords (`login`, `verify`, `secure`, etc.)
- **Security heuristics**: IP-address-as-domain detection, URL shortener detection, WordPress admin-path detection (catches compromised legitimate sites), brand-name typosquat distance (Levenshtein), domain entropy (flags randomly-generated domains)

## Results

On held-out test data (20% split, stratified by class):

| Class    | Precision | Recall | F1   |
|----------|-----------|--------|------|
| malware  | 0.99      | 0.91   | 0.95 |
| normal   | 0.98      | 0.95   | 0.97 |
| phishing | 0.76      | 0.89   | 0.82 |

Overall accuracy: **0.94**

**Live validation**: 89.7% recall (269/300) against a sample of currently-active phishing URLs from the OpenPhish feed — confirms the model generalizes beyond its training data, which is several years old.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install pandas numpy scikit-learn matplotlib requests
```

Download the dataset from Kaggle and place it at `data/malicious_phish.csv` (this path is gitignored).

## running

```bash
python main.py


```
or just the run button on your IDE like pycharm or vscode


This will:
1. Load and label the dataset (benign + defacement → `normal`, plus `phishing` and `malware`)
2. Extract all 16 features from every URL
3. Explore class-level feature differences and save a comparison chart
4. Train the Random Forest classifier
5. Print a full classification report and feature importance ranking
6. Check live recall against the current OpenPhish feed

## structure

```
phishing-detector/
├── main.py
├── data/                                  # gitignored — dataset lives here
├── .venv/                                 # gitignored
└── README.md
```

## some issues
- Training data is a few years old, live validation currently checks phishing recall only, not precision, against live known phishing links
- no homograph attack stuff since false positives and too little appeared in databases to be worth it for now
- maybe a whois lookup after everything is wrapped up into a nice frontend webapp, not really useful for now though would greately increase detection rates of homograph and phishing links i believe

## stuff that still needs to be implemented

- Save the trained model and scaler to disk (`joblib`) for instant single-URL predictions instead of retraining every run
- website for it