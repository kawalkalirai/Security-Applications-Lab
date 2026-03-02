import os
import time
import base64
from PIL import Image

def decode_base64(text):
    # Attempts to decode a string from base64.
    try:
        decoded = base64.b64decode(text).decode('utf-8')
        return decoded
    except Exception:
        return None

print("Starting Part 5: Automation & Risk Scoring...")

# Finds all PNG and JPG images in the current folder
image_files = []
for f in os.listdir('.'):
    if f.lower().endswith('.png') or f.lower().endswith('.jpg'):
        image_files.append(f)

for img_file in image_files:
    print(f"\n{'='*40}")
    print(f"Scanning Image: {img_file}")

    risk_score = 0

    # Get Filesystem MAC time (Modified)
    mac_time = time.ctime(os.path.getmtime(img_file))
    print(f"Filesystem Modified Time: {mac_time}")

    try:
        img = Image.open(img_file)
        metadata = img.info

        if not metadata:
            print("Result: No metadata found in this image.")
            print(f">>> Final Risk Score: {risk_score}")
            continue

        # Extracts and log all metadata fields
        print("\n--- Extracted Metadata ---")
        for key, value in metadata.items():
            print(f"{key}: {str(value)[:60]}...")

        print("\n--- Risk Analysis ---")

        # Convert keys to lowercase to make searching easier
        meta_str_dict = {}
        for k, v in metadata.items():
            meta_str_dict[str(k).lower()] = str(v)

        # Hidden Secret Check (10 Points)
        secret_found = False
        target_fields = ['software', 'usercomment', 'gpsdestdistance', 'makernote', 'imagedescription', 'copyright']

        for field in target_fields:
            if field in meta_str_dict:
                val = meta_str_dict[field]
                decoded = decode_base64(val)

                # Check for base64
                if decoded and len(decoded) > 5 and decoded.isprintable():
                    print(f"[!] FLAG: Covert channel secret found in '{field}' tag!")
                    secret_found = True
                # Check for plain-text anomaly (like the RECON command we found)
                elif "RECON:" in val or "EXFIL:" in val:
                    print(f"[!] FLAG: Plain-text covert secret found in '{field}' tag!")
                    secret_found = True

        if secret_found:
            risk_score += 10

        # GPS / Privacy Leak Check (5 Points)
        if 'gpslatitude' in meta_str_dict or 'gpslongitude' in meta_str_dict:
            print("[!] FLAG: GPS Location data present.")
            risk_score += 5

        # Editing / Compression Check (5 Points)
        software_used = meta_str_dict.get('software', None)
        # If it has a software tag and it's not our RECON hacker command
        if software_used and "RECON" not in software_used:
            print(f"[!] FLAG: Software tag indicates editing ({software_used}).")
            risk_score += 5

        # Timestamp Anomaly Check (5 Points)
        create_date = meta_str_dict.get('create-date', None)
        # If the image has an original create date but was edited in external software, the MAC times are broken
        if create_date and software_used and "RECON" not in software_used:
            print("[!] FLAG: EXIF timestamp does not match filesystem MAC time.")
            risk_score += 5

        print(f"\n>>> Final Risk Score for {img_file}: {risk_score} points")

    except Exception as e:
        print(f"Error reading {img_file}: {e}")

print(f"\n{'='*40}")
print("Automated scanning complete.")
