import pandas as pd
import joblib
import json
import os

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# ==========================================
# PATHS
# ==========================================

DATASET = "data/final_emails.csv"
MODEL_PATH = "models/email_threat_model.pkl"
METRICS_PATH = "data/model_metrics.json"
METRICS_MODEL_PATH = "models/model_metrics.pkl"


# ==========================================
# LOAD DATASET
# ==========================================

print("Loading final dataset...")

df = pd.read_csv(DATASET)

df = df.dropna(
    subset=["email_text", "label"]
)

print()
print("Total emails:", len(df))

print()
print("Class distribution:")
print(df["label"].value_counts())


# ==========================================
# FEATURES AND LABELS
# ==========================================

X = df["email_text"]
y = df["label"]


# ==========================================
# TRAIN / TEST SPLIT
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print()
print("Training emails:", len(X_train))
print("Testing emails:", len(X_test))


# ==========================================
# TF-IDF + LOGISTIC REGRESSION
# ==========================================

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            max_features=50000,
            ngram_range=(1, 2)
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced"
        )
    )
])


# ==========================================
# MODEL TRAINING
# ==========================================

print()
print("Training 3-class model...")
print()

model.fit(
    X_train,
    y_train
)

print("Model training completed!")


# ==========================================
# PREDICTIONS
# ==========================================

y_pred = model.predict(X_test)


# ==========================================
# ACCURACY
# ==========================================

accuracy = accuracy_score(
    y_test,
    y_pred
)


# ==========================================
# MODEL EVALUATION
# ==========================================

print()
print("===================================")
print("MODEL EVALUATION")
print("===================================")

print()
print(f"Accuracy: {accuracy * 100:.2f}%")

print()
print("Classification Report:")

report = classification_report(
    y_test,
    y_pred,
    output_dict=True
)

print(
    classification_report(
        y_test,
        y_pred
    )
)


# ==========================================
# CONFUSION MATRIX
# ==========================================

labels = [
    "safe",
    "spam",
    "phishing"
]

cm = confusion_matrix(
    y_test,
    y_pred,
    labels=labels
)

print("Confusion Matrix:")

print()
print("              safe  spam  phishing")
print("safe       ", cm[0])
print("spam       ", cm[1])
print("phishing   ", cm[2])


# ==========================================
# CREATE COMPLETE METRICS
# ==========================================

metrics = {

    # Overall performance
    "accuracy": round(
        accuracy * 100,
        2
    ),

    # Class performance
    "classes": {

        "safe": {
            "precision": round(
                report["safe"]["precision"] * 100,
                2
            ),
            "recall": round(
                report["safe"]["recall"] * 100,
                2
            ),
            "f1_score": round(
                report["safe"]["f1-score"] * 100,
                2
            ),
            "support": int(
                report["safe"]["support"]
            )
        },

        "spam": {
            "precision": round(
                report["spam"]["precision"] * 100,
                2
            ),
            "recall": round(
                report["spam"]["recall"] * 100,
                2
            ),
            "f1_score": round(
                report["spam"]["f1-score"] * 100,
                2
            ),
            "support": int(
                report["spam"]["support"]
            )
        },

        "phishing": {
            "precision": round(
                report["phishing"]["precision"] * 100,
                2
            ),
            "recall": round(
                report["phishing"]["recall"] * 100,
                2
            ),
            "f1_score": round(
                report["phishing"]["f1-score"] * 100,
                2
            ),
            "support": int(
                report["phishing"]["support"]
            )
        }
    },

    # Confusion Matrix
    "confusion_matrix": cm.tolist(),

    # Order of confusion matrix classes
    "confusion_matrix_labels": labels
}


# ==========================================
# CREATE REQUIRED DIRECTORIES
# ==========================================

os.makedirs(
    "models",
    exist_ok=True
)

os.makedirs(
    "data",
    exist_ok=True
)


# ==========================================
# SAVE ML MODEL
# ==========================================

joblib.dump(
    model,
    MODEL_PATH
)

print()
print("Model saved successfully!")


# ==========================================
# SAVE METRICS AS JSON
# ==========================================

with open(
    METRICS_PATH,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        metrics,
        f,
        indent=4
    )


# ==========================================
# SAVE METRICS AS PICKLE
# ==========================================

joblib.dump(
    metrics,
    METRICS_MODEL_PATH
)


# ==========================================
# FINAL OUTPUT
# ==========================================

print()
print("===================================")
print("MODEL SAVED SUCCESSFULLY")
print("===================================")

print()
print("Model Location:")
print(MODEL_PATH)

print()
print("Metrics JSON Location:")
print(METRICS_PATH)

print()
print("Metrics Pickle Location:")
print(METRICS_MODEL_PATH)

print()
print("Metrics saved successfully!")