# Phishing Detector (STILL WIP!) LOTS OF BUGS

A ml project that classifies URLs as **phishing**, **malware**, or **normal** based on structural and lexical features extracted directly from the URL string. no live requests to url to fetch n stuff

## Overview

- Trained on ~651k labeled URLs from the [Malicious URLs Dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) (Kaggle).
- Model: Random Forest classifier (scikit-learn), with class weighting to boost phishing recall since that was an issue
- Validated against a live OpenPhish feed for out-of-training testing with more recent links, as the kaggle database IS dated from around 2016.
- VERY MUCH IN PROGRESS!!!!! false positives WILL happen!! (for example)



## some issues
- Training data is a few years old, live validation currently checks phishing recall only, not precision, against live known phishing links
- no homograph attack stuff since false positives and too little appeared in databases to be worth it for now
- maybe a whois lookup after everything is wrapped up into a nice frontend webapp, not really useful for now though would greately increase detection rates of homograph and phishing links i believe

## stuff that still needs to be implemented

- Save the trained model and scaler to disk (`joblib`) for instant single-URL predictions instead of retraining every run
- website for it
- MORE ADVERSARIAL TESTING!!! 