import pandas as pd
import joblib
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

DATASET = "data/final_emails.csv"
MODEL_PATH = "models/email_threat_model.pkl"

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

X = df["email_text"]
y = df["label"]

# Train / Test split
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

# TF-IDF + Logistic Regression
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

print()
print("Training 3-class model...")
print()

model.fit(
    X_train,
    y_train
)

print("Model training completed!")

# Predictions
y_pred = model.predict(X_test)

# Accuracy
accuracy = accuracy_score(
    y_test,
    y_pred
)

print()
print("===================================")
print("MODEL EVALUATION")
print("===================================")

print()
print(f"Accuracy: {accuracy * 100:.2f}%")

print()
print("Classification Report:")

print(
    classification_report(
        y_test,
        y_pred
    )
)

print("Confusion Matrix:")

labels = ["safe", "spam", "phishing"]

cm = confusion_matrix(
    y_test,
    y_pred,
    labels=labels
)

print()
print("              safe  spam  phishing")
print("safe       ", cm[0])
print("spam       ", cm[1])
print("phishing   ", cm[2])

# Save model
os.makedirs(
    "models",
    exist_ok=True
)

joblib.dump(
    model,
    MODEL_PATH
)
metrics = {
    "accuracy": round(accuracy * 100, 2),
    "phishing_precision": round(
        classification_report(
            y_test,
            y_pred,
            output_dict=True
        )["phishing"]["precision"] * 100,
        2
    ),
    "phishing_recall": round(
        classification_report(
            y_test,
            y_pred,
            output_dict=True
        )["phishing"]["recall"] * 100,
        2
    ),
    "phishing_f1": round(
        classification_report(
            y_test,
            y_pred,
            output_dict=True
        )["phishing"]["f1-score"] * 100,
        2
    ),
    "safe_f1": round(
        classification_report(
            y_test,
            y_pred,
            output_dict=True
        )["safe"]["f1-score"] * 100,
        2
    ),
    "spam_f1": round(
        classification_report(
            y_test,
            y_pred,
            output_dict=True
        )["spam"]["f1-score"] * 100,
        2
    )
}

joblib.dump(
    metrics,
    "models/model_metrics.pkl"
)

print("Metrics saved successfully!")

print()
print("===================================")
print("MODEL SAVED SUCCESSFULLY")
print("===================================")

print()
print("Location:", MODEL_PATH)