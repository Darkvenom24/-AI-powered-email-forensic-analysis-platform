import os
import json
import pandas as pd

def run_audit():
    data_dir = "data"
    audit_list = []

    # 1. final_emails.csv
    p = os.path.join(data_dir, "final_emails.csv")
    df = pd.read_csv(p)
    audit_list.append({
        "dataset_name": "final_emails.csv",
        "category": "Email Text (NLP)",
        "rows": len(df),
        "columns": df.columns.tolist(),
        "target_column": "label",
        "class_distribution": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        "missing_values": int(df.isna().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "duplicate_texts": int(df["email_text"].duplicated().sum()),
        "leakage_concerns": "None. Cleaned Enron/SpamAssassin/Kaggle emails with balanced multi-class distribution and 0 duplicates.",
        "quality_status": "High Quality",
        "used_for_training": True,
        "reason_for_decision": "Primary multi-class training dataset containing 5,000 safe, 3,000 phishing, and 481 spam emails. Zero text duplicates."
    })

    # 2. phishing_clean.csv
    p = os.path.join(data_dir, "phishing_clean.csv")
    df = pd.read_csv(p)
    audit_list.append({
        "dataset_name": "phishing_clean.csv",
        "category": "Email Text (NLP)",
        "rows": len(df),
        "columns": df.columns.tolist(),
        "target_column": "label",
        "class_distribution": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        "missing_values": int(df.isna().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "duplicate_texts": int(df["email_text"].duplicated().sum()),
        "leakage_concerns": "Minor: 4 duplicate texts. Subsumed inside final_emails.csv with safe emails.",
        "quality_status": "Good",
        "used_for_training": False,
        "reason_for_decision": "Excluded because its samples are already deduplicated and incorporated into final_emails.csv. Training on both would cause train/test duplication."
    })

    # 3. large_emails.csv
    p = os.path.join(data_dir, "large_emails.csv")
    df = pd.read_csv(p)
    audit_list.append({
        "dataset_name": "large_emails.csv",
        "category": "Email Text (NLP)",
        "rows": len(df),
        "columns": df.columns.tolist(),
        "target_column": "label",
        "class_distribution": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        "missing_values": int(df.isna().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "duplicate_texts": int(df["email_text"].duplicated().sum()),
        "leakage_concerns": "Contains 159 duplicates. Contains 0 phishing emails (only safe and spam).",
        "quality_status": "Imbalanced / Incomplete",
        "used_for_training": False,
        "reason_for_decision": "Excluded because it has 0 phishing emails, contains duplicate rows, and its unique samples are already integrated into final_emails.csv."
    })

    # 4. Phishing_validation_emails.csv
    p = os.path.join(data_dir, "Phishing_validation_emails.csv")
    df = pd.read_csv(p)
    audit_list.append({
        "dataset_name": "Phishing_validation_emails.csv",
        "category": "Email Text (Synthetic Validation)",
        "rows": len(df),
        "columns": df.columns.tolist(),
        "target_column": "Email Type",
        "class_distribution": {str(k): int(v) for k, v in df["Email Type"].value_counts().items()},
        "missing_values": int(df.isna().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "duplicate_texts": int(df["Email Text"].duplicated().sum()),
        "leakage_concerns": "CRITICAL: 1,900 out of 2,000 rows (95%) are duplicates! Only 100 unique templates repeated 20 times each.",
        "quality_status": "Severely Duplicated / Synthetic",
        "used_for_training": False,
        "reason_for_decision": "Excluded from training due to massive text duplication (95% duplicate rate) which would cause catastrophic evaluation leakage."
    })

    # 5. emails.csv
    p = os.path.join(data_dir, "emails.csv")
    df = pd.read_csv(p)
    audit_list.append({
        "dataset_name": "emails.csv",
        "category": "Email Text (Toy Dataset)",
        "rows": len(df),
        "columns": df.columns.tolist(),
        "target_column": "label",
        "class_distribution": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        "missing_values": int(df.isna().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "duplicate_texts": int(df["text"].duplicated().sum()),
        "leakage_concerns": "Only 15 sample rows.",
        "quality_status": "Toy / Demo Only",
        "used_for_training": False,
        "reason_for_decision": "Excluded due to tiny sample size (15 rows). Intended only as initial development stub."
    })

    # 6. A_Email_ML_Dataset.csv
    p = os.path.join(data_dir, "A_Email_ML_Dataset.csv")
    df = pd.read_csv(p)
    audit_list.append({
        "dataset_name": "A_Email_ML_Dataset.csv",
        "category": "Tabular Feature Dataset",
        "rows": len(df),
        "columns": df.columns.tolist(),
        "target_column": "label",
        "class_distribution": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        "missing_values": int(df.isna().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "duplicate_texts": None,
        "leakage_concerns": "Contains engineered numerical features (urgency, url_count, html_ratio), no raw email text. Not usable for TF-IDF NLP pipeline.",
        "quality_status": "Tabular Only",
        "used_for_training": False,
        "reason_for_decision": "Excluded from text ML training because it lacks raw email text. Feature definitions (urgency_keyword_count, credential_request_flag) are utilized in the rule-based Threat Scoring Engine."
    })

    # 7. F_Authentication_Forensic_Dataset.csv
    p = os.path.join(data_dir, "F_Authentication_Forensic_Dataset.csv")
    df = pd.read_csv(p)
    audit_list.append({
        "dataset_name": "F_Authentication_Forensic_Dataset.csv",
        "category": "Forensic / Auth Metadata",
        "rows": len(df),
        "columns": df.columns.tolist(),
        "target_column": "label",
        "class_distribution": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        "missing_values": int(df.isna().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "duplicate_texts": None,
        "leakage_concerns": "Contains header metadata (SPF, DKIM, DMARC, hops). No email text.",
        "quality_status": "Tabular Metadata",
        "used_for_training": False,
        "reason_for_decision": "Excluded from text ML training because it lacks email body text. Authentication and header logic is implemented directly in the Forensic Parser and Threat Scorer."
    })

    # 8. M6_Attachmen_Dataset.csv
    p = os.path.join(data_dir, "M6_Attachmen_Dataset.csv")
    df = pd.read_csv(p)
    audit_list.append({
        "dataset_name": "M6_Attachmen_Dataset.csv",
        "category": "Attachment Threat Intelligence",
        "rows": len(df),
        "columns": df.columns.tolist(),
        "target_column": "label",
        "class_distribution": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        "missing_values": int(df.isna().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "duplicate_texts": None,
        "leakage_concerns": "Entropy score is artificially correlated with label (7.45 for label 1 vs 3.2 for label 0). Not suitable for statistical ML training.",
        "quality_status": "Threat Intel / IOC Signatures",
        "used_for_training": False,
        "reason_for_decision": "Excluded from ML training due to artificial entropy distribution. Retained as reference threat intelligence for SHA-256 malware hash and Emotet signature exact lookups."
    })

    # 9. M6_Attachment_Final.csv
    p = os.path.join(data_dir, "M6_Attachment_Final.csv")
    df = pd.read_csv(p)
    audit_list.append({
        "dataset_name": "M6_Attachment_Final.csv",
        "category": "Attachment Metrics",
        "rows": len(df),
        "columns": df.columns.tolist(),
        "target_column": "label",
        "class_distribution": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        "missing_values": int(df.isna().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "duplicate_texts": None,
        "leakage_concerns": "Multiple columns are completely NaN (number_of_dots, double_extension, extension_mime_mismatch). Entropy has perfect correlation (r=1.0) with label.",
        "quality_status": "Unsuitable for ML / Incomplete",
        "used_for_training": False,
        "reason_for_decision": "Excluded due to perfect label leakage on entropy and entirely missing columns."
    })

    # 10. M6_Domain_DNS_Final.csv
    p = os.path.join(data_dir, "M6_Domain_DNS_Final.csv")
    df = pd.read_csv(p)
    audit_list.append({
        "dataset_name": "M6_Domain_DNS_Final.csv",
        "category": "Domain & DNS Intelligence",
        "rows": len(df),
        "columns": df.columns.tolist(),
        "target_column": "label",
        "class_distribution": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        "missing_values": int(df.isna().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "duplicate_texts": None,
        "leakage_concerns": "10 empty/NaN columns at end. High correlation with domain_length and hyphen_count. No email text.",
        "quality_status": "IOC Reference Data",
        "used_for_training": False,
        "reason_for_decision": "Excluded from text ML training (no email text). Retained as a 10,000-domain IOC reference dataset for checking suspicious domains, MX record counts, and DNS authentication."
    })

    # 11. M6_Domain_DNS_Phishing_Dataset.csv
    p = os.path.join(data_dir, "M6_Domain_DNS_Phishing_Dataset.csv")
    df = pd.read_csv(p)
    audit_list.append({
        "dataset_name": "M6_Domain_DNS_Phishing_Dataset.csv",
        "category": "Domain & DNS Intelligence",
        "rows": len(df),
        "columns": df.columns.tolist(),
        "target_column": "label",
        "class_distribution": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        "missing_values": int(df.isna().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "duplicate_texts": None,
        "leakage_concerns": "Domain features only, no email text.",
        "quality_status": "IOC Reference Data",
        "used_for_training": False,
        "reason_for_decision": "Subsumed by M6_Domain_DNS_Final.csv."
    })

    # 12. M6_URL.csv
    p = os.path.join(data_dir, "M6_URL.csv")
    df = pd.read_csv(p)
    audit_list.append({
        "dataset_name": "M6_URL.csv",
        "category": "URL Threat Intelligence",
        "rows": len(df),
        "columns": df.columns.tolist(),
        "target_column": "label",
        "class_distribution": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        "missing_values": int(df.isna().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "duplicate_texts": None,
        "leakage_concerns": "URL-only dataset, not email body text.",
        "quality_status": "High Quality IOC Feed",
        "used_for_training": False,
        "reason_for_decision": "Excluded from email text NLP training because it consists only of URLs. Utilized as an active IOC threat database for fast exact-match URL reputation checking."
    })

    # 13. M6_IP_URL_Threat_Intelligence_Dataset.xlsx
    p = os.path.join(data_dir, "M6_IP_URL_Threat_Intelligence_Dataset.xlsx")
    xl = pd.ExcelFile(p)
    ip_df = pd.read_excel(p, sheet_name="IP_Detection")
    url_df = pd.read_excel(p, sheet_name="Phishing_URL_Detection")
    audit_list.append({
        "dataset_name": "M6_IP_URL_Threat_Intelligence_Dataset.xlsx",
        "category": "Threat Intelligence Feeds (IP & URL)",
        "rows": len(ip_df) + len(url_df),
        "columns": {"IP_Detection": ip_df.columns.tolist(), "Phishing_URL_Detection": url_df.columns.tolist()},
        "target_column": "label",
        "class_distribution": {
            "IP_Detection_label_1": int((ip_df["label"] == 1).sum()),
            "URL_Detection_label_1": int((url_df["label"] == 1).sum())
        },
        "missing_values": int(ip_df.isna().sum().sum()) + int(url_df.isna().sum().sum()),
        "duplicate_rows": int(ip_df.duplicated().sum()) + int(url_df.duplicated().sum()),
        "duplicate_texts": None,
        "leakage_concerns": "External threat feed indicators (MISP / IPsum Level 6 & OpenPhish feeds).",
        "quality_status": "High Quality External Threat Intel",
        "used_for_training": False,
        "reason_for_decision": "Excluded from email text NLP training. Utilized as authoritative threat intelligence IOC feeds for runtime IP and URL reputation queries."
    })

    # Save to JSON
    json_path = os.path.join(data_dir, "dataset_audit.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(audit_list, f, indent=2)

    # Save to CSV
    csv_path = os.path.join(data_dir, "dataset_audit.csv")
    csv_rows = []
    for item in audit_list:
        csv_rows.append({
            "dataset_name": item["dataset_name"],
            "category": item["category"],
            "rows": item["rows"],
            "target_column": str(item["target_column"]),
            "class_distribution": str(item["class_distribution"]),
            "missing_values": item["missing_values"],
            "duplicate_rows": item["duplicate_rows"],
            "leakage_concerns": item["leakage_concerns"],
            "quality_status": item["quality_status"],
            "used_for_training": item["used_for_training"],
            "reason_for_decision": item["reason_for_decision"]
        })
    pd.DataFrame(csv_rows).to_csv(csv_path, index=False, encoding="utf-8")

    print(f"Dataset audit complete! Saved {len(audit_list)} datasets to:")
    print(" -", json_path)
    print(" -", csv_path)

if __name__ == "__main__":
    run_audit()
