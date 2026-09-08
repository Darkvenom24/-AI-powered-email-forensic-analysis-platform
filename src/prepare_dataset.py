import os
import csv
from email import policy
from email.parser import BytesParser

DATA_DIR = r"C:\Hackathon\data"
OUTPUT_FILE = os.path.join(DATA_DIR, "large_emails.csv")

def extract_text(message):
    parts = []

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()

            if content_type == "text/plain":
                try:
                    content = part.get_content()
                    if content:
                        parts.append(content)
                except Exception:
                    pass
    else:
        try:
            content = message.get_content()
            if content:
                parts.append(content)
        except Exception:
            pass

    return "\n".join(parts)

def get_label(file_path):
    path = file_path.lower()

    if "spam" in path:
        return "spam"

    if "ham" in path:
        return "safe"

    return None

rows = []
total_files = 0
failed_files = 0

print("Scanning email dataset...")
print()

for root, dirs, files in os.walk(DATA_DIR):

    for filename in files:

        # CSV aur archive files ko ignore karo
        if filename.endswith((".csv", ".tar.bz2", ".eml")):
            continue

        file_path = os.path.join(root, filename)

        label = get_label(file_path)

        if label is None:
            continue

        total_files += 1

        try:
            with open(file_path, "rb") as f:
                message = BytesParser(
                    policy=policy.default
                ).parse(f)

            subject = message.get("Subject", "")
            body = extract_text(message)

            text = f"{subject}\n{body}".strip()

            if len(text) < 10:
                continue

            rows.append({
                "email_text": text,
                "label": label
            })

        except Exception:
            failed_files += 1

print("Total email files found:", total_files)
print("Emails successfully processed:", len(rows))
print("Failed files:", failed_files)

with open(
    OUTPUT_FILE,
    "w",
    newline="",
    encoding="utf-8"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=["email_text", "label"]
    )

    writer.writeheader()
    writer.writerows(rows)

print()
print("Dataset created successfully!")
print("Output:", OUTPUT_FILE)