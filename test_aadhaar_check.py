import sys
from src.file_validator import validate_email_upload, validate_email_text_payload

# 1. aadhaar.pdf
pdf_bytes = b"%PDF-1.4\n%some aadhaar card pdf data"
ok, err, meta = validate_email_upload(pdf_bytes, "aadhaar.pdf")
print("1. aadhaar.pdf:", ok, "| Error:", err)

# 2. aadhaar.jpg
jpg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"image_bytes" * 10
ok, err, meta = validate_email_upload(jpg_bytes, "aadhaar.jpg")
print("2. aadhaar.jpg:", ok, "| Error:", err)

# 3. aadhaar.png
png_bytes = b"\x89PNG\r\n\x1a\n" + b"png_bytes" * 10
ok, err, meta = validate_email_upload(png_bytes, "aadhaar.png")
print("3. aadhaar.png:", ok, "| Error:", err)

# 4. aadhaar.xml (Offline e-KYC)
xml_bytes = b'<?xml version="1.0"?><OfflinePaperlessKyc referenceId="123456">Some data</OfflinePaperlessKyc>'
ok, err, meta = validate_email_upload(xml_bytes, "aadhaar.xml")
print("4. aadhaar.xml:", ok, "| Error:", err)

# 5. aadhaar disguised pdf as .eml
ok, err, meta = validate_email_upload(pdf_bytes, "aadhaar_card.eml")
print("5. aadhaar disguised pdf as .eml:", ok, "| Error:", err)

# 6. aadhaar disguised jpg as .eml
ok, err, meta = validate_email_upload(jpg_bytes, "aadhaar_card.eml")
print("6. aadhaar disguised jpg as .eml:", ok, "| Error:", err)

# 7. Aadhaar text with UIDAI email help@uidai.gov.in renamed to .eml
aadhaar_text_with_email = b"""GOVERNMENT OF INDIA
Unique Identification Authority of India
Enrollment No: 1234/56789/01234
To: Vaibhav Senjaliya
Address: Surat, Gujarat, India - 395006
Email: help@uidai.gov.in
Phone: 1947
Mera Aadhaar, Meri Pehchan
"""
ok, err, meta = validate_email_upload(aadhaar_text_with_email, "aadhaar.eml")
print("7. aadhaar text with help@uidai.gov.in renamed to .eml:", ok, "| Error:", err)

# 8. Aadhaar text pasted into textarea
aadhaar_text = """GOVERNMENT OF INDIA
Unique Identification Authority of India
Aadhaar Number: 1234 5678 9012
Name: Vaibhav Senjaliya
DOB: 15/08/2000
Gender: Male
Address: 123 Green City, Surat, Gujarat 395006
help@uidai.gov.in
"""
ok, err, meta = validate_email_text_payload(aadhaar_text)
print("8. aadhaar text in textarea:", ok, "| Error:", err)

# 9. Real valid EML
with open("data/test_email.eml", "rb") as f:
    valid_bytes = f.read()
ok, err, meta = validate_email_upload(valid_bytes, "invoice.eml")
print("9. legitimate .eml:", ok, "| Error:", err)
