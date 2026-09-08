import pandas as pd

INPUT_FILE = "data/Balanced_Dataset.csv"
OUTPUT_FILE = "data/phishing_clean.csv"

print("Loading phishing dataset...")

df = pd.read_csv(INPUT_FILE)

print("Original dataset:", len(df))
print("Original labels:")
print(df["label"].value_counts())

# Remove empty emails
df = df.dropna(subset=["body", "label"])

# Convert labels
df["label"] = df["label"].map({
    0: "safe",
    1: "phishing"
})

# Remove invalid labels
df = df.dropna(subset=["label"])

# Rename body column
df = df.rename(columns={
    "body": "email_text"
})

# Balance dataset
safe = df[df["label"] == "safe"]
phishing = df[df["label"] == "phishing"]

sample_size = min(
    len(safe),
    len(phishing),
    3000
)

safe_sample = safe.sample(
    n=sample_size,
    random_state=42
)

phishing_sample = phishing.sample(
    n=sample_size,
    random_state=42
)

final_df = pd.concat(
    [safe_sample, phishing_sample],
    ignore_index=True
)

# Shuffle
final_df = final_df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

# Keep only required columns
final_df = final_df[
    ["email_text", "label"]
]

# Save
final_df.to_csv(
    OUTPUT_FILE,
    index=False,
    encoding="utf-8"
)

print()
print("===================================")
print("PHISHING DATASET READY")
print("===================================")

print()
print("Total emails:", len(final_df))

print()
print("Class distribution:")
print(final_df["label"].value_counts())

print()
print("Saved to:")
print(OUTPUT_FILE)