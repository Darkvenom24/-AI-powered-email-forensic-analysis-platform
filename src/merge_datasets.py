import pandas as pd

SPAM_DATASET = "data/large_emails.csv"
PHISHING_DATASET = "data/phishing_clean.csv"
OUTPUT_DATASET = "data/final_emails.csv"

print("Loading datasets...")

original_df = pd.read_csv(SPAM_DATASET)
phishing_df = pd.read_csv(PHISHING_DATASET)

# Keep required columns
original_df = original_df[["email_text", "label"]]
phishing_df = phishing_df[["email_text", "label"]]

# Separate original classes
safe_df = original_df[original_df["label"] == "safe"]
spam_df = original_df[original_df["label"] == "spam"]

# Phishing dataset already contains safe + phishing
phishing_safe_df = phishing_df[
    phishing_df["label"] == "safe"
]

phishing_df_only = phishing_df[
    phishing_df["label"] == "phishing"
]

# Combine all safe emails
all_safe = pd.concat(
    [safe_df, phishing_safe_df],
    ignore_index=True
)

# Remove duplicates
all_safe = all_safe.drop_duplicates(
    subset=["email_text"]
)

phishing_df_only = phishing_df_only.drop_duplicates(
    subset=["email_text"]
)

spam_df = spam_df.drop_duplicates(
    subset=["email_text"]
)

# Limit safe class to avoid huge imbalance
safe_sample = all_safe.sample(
    n=min(5000, len(all_safe)),
    random_state=42
)

# Combine
final_df = pd.concat(
    [
        safe_sample,
        spam_df,
        phishing_df_only
    ],
    ignore_index=True
)

# Remove empty emails
final_df = final_df.dropna(
    subset=["email_text", "label"]
)

# Shuffle
final_df = final_df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

# Save
final_df.to_csv(
    OUTPUT_DATASET,
    index=False,
    encoding="utf-8"
)

print()
print("===================================")
print("FINAL 3-CLASS DATASET")
print("===================================")

print()
print("Total emails:", len(final_df))

print()
print("Class distribution:")
print(final_df["label"].value_counts())

print()
print("Labels:")
print(final_df["label"].unique())

print()
print("Saved to:")
print(OUTPUT_DATASET)