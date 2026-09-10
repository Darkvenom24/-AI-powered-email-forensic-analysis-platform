"""
SIH26106 - AI-Powered Email Threat Detection Model Training Pipeline
====================================================================
Reproducible, leakage-free training script for the primary email threat classifier.

Architecture:
  - Text Normalization (preserves security indicators: URLs, IPs, finance, urgency)
  - Stratified 70% Train / 15% Validation / 15% Test Split
  - TF-IDF Feature Extraction + Logistic Regression Classifier in a single scikit-learn Pipeline
  - Full evaluation on unseen Test set (Accuracy, Precision, Recall, F1, ROC-AUC, Confusion Matrix)
  - Saves:
      1. models/email_threat_model.pkl
      2. data/model_metrics.json
      3. data/model_report.txt
"""

import os
import re
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)

# ============================================================
# CONFIGURATION & HYPERPARAMETERS
# ============================================================

RANDOM_SEED = 42
DATASET_PATH = "data/final_emails.csv"
MODEL_OUTPUT_PATH = "models/email_threat_model.pkl"
METRICS_JSON_PATH = "data/model_metrics.json"
METRICS_TXT_PATH = "data/model_report.txt"

# Ensure output directories exist
os.makedirs("models", exist_ok=True)
os.makedirs("data", exist_ok=True)

# ============================================================
# 1. TEXT CLEANING & NORMALIZATION
# ============================================================

def clean_email_text(text: str) -> str:
    """
    Carefully normalize email text while preserving critical security indicators:
    - Preserves URLs, domains, and IP patterns
    - Preserves urgency, credential, and financial terms
    - Removes unreadable control chars and normalizes whitespace
    """
    if not isinstance(text, str):
        return ""
    
    # Replace non-breaking spaces and excessive whitespace
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", " ", text)
    
    # Normalize excessive tabs/spaces while keeping structure
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    
    return text.strip()

# ============================================================
# 2. LOAD & AUDIT DATASET
# ============================================================

def load_data(filepath: str):
    print("=" * 60)
    print(f"Loading dataset: {filepath}")
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset not found at {filepath}")

    df = pd.read_csv(filepath)
    print(f"Raw rows: {len(df)}")
    print(f"Columns: {df.columns.tolist()}")

    # Check for missing values
    df = df.dropna(subset=["email_text", "label"]).copy()
    
    # Clean text
    df["email_text"] = df["email_text"].apply(clean_email_text)
    df = df[df["email_text"].str.len() > 10].copy()

    # Deduplicate text
    initial_count = len(df)
    df = df.drop_duplicates(subset=["email_text"]).reset_index(drop=True)
    dups_removed = initial_count - len(df)
    if dups_removed > 0:
        print(f"Removed {dups_removed} duplicate email texts.")

    # Normalize labels
    df["label"] = df["label"].astype(str).str.lower().str.strip()
    print("\nClass distribution:")
    print(df["label"].value_counts())
    print("=" * 60)

    return df

# ============================================================
# 3. STRATIFIED TRAIN / VALIDATION / TEST SPLIT
# ============================================================

def split_data(df: pd.DataFrame):
    X = df["email_text"]
    y = df["label"]

    # 70% Train, 30% Temp (Val + Test)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y,
        test_size=0.30,
        random_state=RANDOM_SEED,
        stratify=y
    )

    # Split 30% temp equally into 15% Validation and 15% Test
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp,
        test_size=0.50,
        random_state=RANDOM_SEED,
        stratify=y_temp
    )

    print(f"Dataset Split (70/15/15):")
    print(f"  - Training samples:   {len(X_train)} ({len(X_train)/len(df):.1%})")
    print(f"  - Validation samples: {len(X_val)} ({len(X_val)/len(df):.1%})")
    print(f"  - Testing samples:    {len(X_test)} ({len(X_test)/len(df):.1%})")
    print("=" * 60)

    return X_train, X_val, X_test, y_train, y_val, y_test

# ============================================================
# 4. MODEL PIPELINE CREATION & VALIDATION TUNING
# ============================================================

def build_and_tune_pipeline(X_train, y_train, X_val, y_val):
    print("Evaluating TF-IDF + Logistic Regression hyperparameter configurations on Validation set...")

    candidate_params = [
        {"max_features": 15000, "ngram_range": (1, 2), "min_df": 2, "C": 1.0, "class_weight": "balanced"},
        {"max_features": 20000, "ngram_range": (1, 2), "min_df": 2, "C": 2.0, "class_weight": "balanced"},
        {"max_features": 25000, "ngram_range": (1, 2), "min_df": 2, "C": 5.0, "class_weight": "balanced"},
        {"max_features": 20000, "ngram_range": (1, 2), "min_df": 2, "C": 2.0, "class_weight": None},
    ]

    best_pipeline = None
    best_f1_phish = -1.0
    best_config = None

    for i, p in enumerate(candidate_params):
        pipe = Pipeline([
            ("tfidf", TfidfVectorizer(
                max_features=p["max_features"],
                ngram_range=p["ngram_range"],
                min_df=p["min_df"],
                sublinear_tf=True,
                lowercase=True,
                strip_accents="unicode"
            )),
            ("classifier", LogisticRegression(
                C=p["C"],
                max_iter=1000,
                class_weight=p["class_weight"],
                random_state=RANDOM_SEED,
                solver="lbfgs"
            ))
        ])

        # Fit ONLY on training data (no leakage)
        pipe.fit(X_train, y_train)

        # Evaluate on validation data
        val_preds = pipe.predict(X_val)
        val_acc = accuracy_score(y_val, val_preds)
        val_rec_phish = recall_score(y_val, val_preds, labels=["phishing"], average=None)[0]
        val_prec_phish = precision_score(y_val, val_preds, labels=["phishing"], average=None)[0]
        val_f1_phish = f1_score(y_val, val_preds, labels=["phishing"], average=None)[0]

        print(f"Config {i+1}: max_feat={p['max_features']}, C={p['C']}, class_weight={p['class_weight']} "
              f"-> Val Acc: {val_acc:.4f}, Phishing Prec: {val_prec_phish:.4f}, Recall: {val_rec_phish:.4f}, F1: {val_f1_phish:.4f}")

        # Prioritize high phishing recall and high F1 score
        if val_f1_phish > best_f1_phish:
            best_f1_phish = val_f1_phish
            best_pipeline = pipe
            best_config = p

    print("\nSelected Best Configuration based on Validation Phishing F1:")
    print(best_config)
    print("=" * 60)

    return best_pipeline, best_config

# ============================================================
# 5. FINAL TEST EVALUATION & METRIC GENERATION
# ============================================================

def evaluate_on_test_set(pipeline, X_test, y_test, best_config, total_samples, n_train, n_val, n_test):
    print("Evaluating Selected Pipeline on Held-Out Test Set (Unseen Data)...")

    test_preds = pipeline.predict(X_test)
    test_probs = pipeline.predict_proba(X_test)

    classes = list(pipeline.classes_)
    phishing_idx = classes.index("phishing")
    safe_idx = classes.index("safe")
    spam_idx = classes.index("spam")

    # Overall Metrics
    acc = accuracy_score(y_test, test_preds)
    prec_macro = precision_score(y_test, test_preds, average="macro")
    rec_macro = recall_score(y_test, test_preds, average="macro")
    f1_macro = f1_score(y_test, test_preds, average="macro")

    prec_weighted = precision_score(y_test, test_preds, average="weighted")
    rec_weighted = recall_score(y_test, test_preds, average="weighted")
    f1_weighted = f1_score(y_test, test_preds, average="weighted")

    # Multiclass ROC-AUC (One-vs-Rest)
    y_test_bin = pd.get_dummies(y_test)[classes].values
    try:
        roc_auc_ovr = roc_auc_score(y_test_bin, test_probs, multi_class="ovr", average="macro")
    except Exception:
        roc_auc_ovr = None

    # Binary ROC-AUC specifically for Phishing vs Non-Phishing
    y_test_phish_bin = (y_test == "phishing").astype(int)
    phishing_probs = test_probs[:, phishing_idx]
    try:
        roc_auc_phishing = roc_auc_score(y_test_phish_bin, phishing_probs)
    except Exception:
        roc_auc_phishing = None

    # Per-class metrics
    class_report = classification_report(y_test, test_preds, output_dict=True)
    conf_mat = confusion_matrix(y_test, test_preds, labels=["safe", "spam", "phishing"]).tolist()

    # Specific phishing metrics
    phishing_prec = precision_score(y_test, test_preds, labels=["phishing"], average=None)[0]
    phishing_rec = recall_score(y_test, test_preds, labels=["phishing"], average=None)[0]
    phishing_f1 = f1_score(y_test, test_preds, labels=["phishing"], average=None)[0]

    # Confusion breakdown for phishing
    # In order ['safe', 'spam', 'phishing']:
    # True safe row: conf_mat[0] -> [safe, spam, phishing]
    # True spam row: conf_mat[1] -> [safe, spam, phishing]
    # True phish row: conf_mat[2] -> [safe, spam, phishing]
    true_phishing_count = sum(conf_mat[2])
    phishing_correct = conf_mat[2][2]
    phishing_false_negatives = conf_mat[2][0] + conf_mat[2][1]
    phishing_false_positives = conf_mat[0][2] + conf_mat[1][2]

    print("\n" + "=" * 60)
    print("FINAL TEST SET PERFORMANCE METRICS")
    print("=" * 60)
    print(f"Overall Accuracy:           {acc * 100:.2f}%")
    print(f"Macro F1 Score:             {f1_macro * 100:.2f}%")
    print(f"Weighted F1 Score:          {f1_weighted * 100:.2f}%")
    if roc_auc_ovr:
        print(f"Multiclass ROC-AUC (OvR):   {roc_auc_ovr:.4f}")
    if roc_auc_phishing:
        print(f"Phishing Specific ROC-AUC:  {roc_auc_phishing:.4f}")
    print("-" * 60)
    print(f"Phishing Precision:         {phishing_prec * 100:.2f}%")
    print(f"Phishing Recall:            {phishing_rec * 100:.2f}% (False Negatives: {phishing_false_negatives}/{true_phishing_count})")
    print(f"Phishing F1-Score:          {phishing_f1 * 100:.2f}%")
    print("-" * 60)
    print("Confusion Matrix [Rows: Actual (Safe, Spam, Phishing), Cols: Predicted (Safe, Spam, Phishing)]:")
    print(np.array(conf_mat))
    print("=" * 60)

    # Format metrics JSON matching existing app.py and templates/index.html requirements
    metrics_data = {
        "dataset_used": DATASET_PATH,
        "total_samples": total_samples,
        "train_samples": n_train,
        "val_samples": n_val,
        "test_samples": n_test,
        "random_seed": RANDOM_SEED,
        "training_timestamp": datetime.now().isoformat(),
        "model_name": "TF-IDF + Logistic Regression",
        "tfidf_parameters": {
            "max_features": best_config["max_features"],
            "ngram_range": list(best_config["ngram_range"]),
            "min_df": best_config["min_df"],
            "sublinear_tf": True,
            "lowercase": True
        },
        "classifier_parameters": {
            "algorithm": "LogisticRegression",
            "C": best_config["C"],
            "class_weight": best_config["class_weight"],
            "solver": "lbfgs",
            "max_iter": 1000
        },
        "accuracy": round(acc * 100, 2),
        "precision": round(prec_weighted * 100, 2),
        "recall": round(rec_weighted * 100, 2),
        "f1_score": round(f1_weighted * 100, 2),
        "macro_f1": round(f1_macro * 100, 2),
        "roc_auc_ovr": round(roc_auc_ovr, 4) if roc_auc_ovr else None,
        "roc_auc_phishing": round(roc_auc_phishing, 4) if roc_auc_phishing else None,
        "phishing_precision": round(phishing_prec * 100, 2),
        "phishing_recall": round(phishing_rec * 100, 2),
        "phishing_f1": round(phishing_f1 * 100, 2),
        "phishing_false_negatives": int(phishing_false_negatives),
        "phishing_false_positives": int(phishing_false_positives),
        "classes": {
            "safe": {
                "precision": round(class_report["safe"]["precision"] * 100, 2),
                "recall": round(class_report["safe"]["recall"] * 100, 2),
                "f1_score": round(class_report["safe"]["f1-score"] * 100, 2),
                "support": int(class_report["safe"]["support"])
            },
            "spam": {
                "precision": round(class_report["spam"]["precision"] * 100, 2),
                "recall": round(class_report["spam"]["recall"] * 100, 2),
                "f1_score": round(class_report["spam"]["f1-score"] * 100, 2),
                "support": int(class_report["spam"]["support"])
            },
            "phishing": {
                "precision": round(class_report["phishing"]["precision"] * 100, 2),
                "recall": round(class_report["phishing"]["recall"] * 100, 2),
                "f1_score": round(class_report["phishing"]["f1-score"] * 100, 2),
                "support": int(class_report["phishing"]["support"])
            }
        },
        "confusion_matrix": conf_mat
    }

    # Save JSON
    with open(METRICS_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics_data, f, indent=2)
    print(f"Saved metrics JSON to: {METRICS_JSON_PATH}")

    # Also save models/model_metrics.pkl for backwards compatibility
    try:
        joblib.dump(metrics_data, "models/model_metrics.pkl")
    except Exception as e:
        print(f"Warning saving model_metrics.pkl: {e}")

    # Save human-readable report
    with open(METRICS_TXT_PATH, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("SIH26106 EMAIL THREAT DETECTION MODEL AUDIT & EVALUATION REPORT\n")
        f.write("=" * 70 + "\n")
        f.write(f"Generated at: {metrics_data['training_timestamp']}\n")
        f.write(f"Dataset Used: {DATASET_PATH}\n")
        f.write(f"Random Seed:  {RANDOM_SEED}\n")
        f.write(f"Total Samples: {total_samples} (Train: {n_train}, Val: {n_val}, Test: {n_test})\n\n")
        f.write("Model Architecture:\n")
        f.write(f"  Pipeline: TfidfVectorizer -> LogisticRegression\n")
        f.write(f"  TF-IDF: max_features={best_config['max_features']}, ngram_range={best_config['ngram_range']}, min_df={best_config['min_df']}, sublinear_tf=True\n")
        f.write(f"  Classifier: C={best_config['C']}, class_weight={best_config['class_weight']}, solver=lbfgs\n\n")
        f.write("Overall Test Evaluation Metrics (Held-Out Unseen Data):\n")
        f.write(f"  Accuracy:                  {metrics_data['accuracy']}%\n")
        f.write(f"  Weighted Precision:        {metrics_data['precision']}%\n")
        f.write(f"  Weighted Recall:           {metrics_data['recall']}%\n")
        f.write(f"  Weighted F1-Score:         {metrics_data['f1_score']}%\n")
        f.write(f"  Macro F1-Score:            {metrics_data['macro_f1']}%\n")
        f.write(f"  ROC-AUC (One-vs-Rest):     {metrics_data['roc_auc_ovr']}\n")
        f.write(f"  Phishing ROC-AUC:          {metrics_data['roc_auc_phishing']}\n\n")
        f.write("Phishing Detection Specialization:\n")
        f.write(f"  Phishing Recall:           {metrics_data['phishing_recall']}%\n")
        f.write(f"  Phishing Precision:        {metrics_data['phishing_precision']}%\n")
        f.write(f"  Phishing F1-Score:         {metrics_data['phishing_f1']}%\n")
        f.write(f"  False Negatives:           {metrics_data['phishing_false_negatives']} out of {true_phishing_count} phishing emails\n")
        f.write(f"  False Positives:           {metrics_data['phishing_false_positives']}\n\n")
        f.write("Per-Class Breakdown:\n")
        for cls_name, cls_vals in metrics_data["classes"].items():
            f.write(f"  {cls_name.upper():<10}: Precision={cls_vals['precision']}%, Recall={cls_vals['recall']}%, F1={cls_vals['f1_score']}%, Support={cls_vals['support']}\n")
        f.write("\nConfusion Matrix (Rows=Actual, Columns=Predicted [Safe, Spam, Phishing]):\n")
        f.write(f"  Safe:     {conf_mat[0]}\n")
        f.write(f"  Spam:     {conf_mat[1]}\n")
        f.write(f"  Phishing: {conf_mat[2]}\n")
        f.write("=" * 70 + "\n")
    print(f"Saved human-readable report to: {METRICS_TXT_PATH}")

    return metrics_data

# ============================================================
# MAIN EXECUTION
# ============================================================

def main():
    print("Starting SIH26106 Model Training Pipeline...\n")

    # 1. Load data
    df = load_data(DATASET_PATH)

    # 2. Train/Val/Test Split
    X_train, X_val, X_test, y_train, y_val, y_test = split_data(df)

    # 3. Build & Tune Pipeline on Train/Val
    pipeline, best_config = build_and_tune_pipeline(X_train, y_train, X_val, y_val)

    # 4. Evaluate on Held-Out Test Set
    metrics = evaluate_on_test_set(
        pipeline, X_test, y_test, best_config,
        total_samples=len(df),
        n_train=len(X_train),
        n_val=len(X_val),
        n_test=len(X_test)
    )

    # 5. Save the Complete Pipeline
    print("\nSaving complete pipeline to disk...")
    joblib.dump(pipeline, MODEL_OUTPUT_PATH)
    print(f"SUCCESS: Model pipeline successfully saved to: {MODEL_OUTPUT_PATH}")

    # Verify reload
    reloaded = joblib.load(MODEL_OUTPUT_PATH)
    test_sample = ["URGENT: Your bank account is locked! Click http://evil-bank.com/login immediately to verify."]
    pred = reloaded.predict(test_sample)[0]
    prob = reloaded.predict_proba(test_sample)[0]
    phish_idx = list(reloaded.classes_).index("phishing")
    print(f"Verification test sample prediction: '{pred}' (Phishing probability: {prob[phish_idx]*100:.2f}%)")

if __name__ == "__main__":
    main()
