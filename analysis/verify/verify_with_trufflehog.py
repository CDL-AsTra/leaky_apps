import subprocess
import os 
import json
import time

# Path to the trufflehog executable -> modified version required as it needs the verify command
path_to_trufflehog = "trufflehog"

# specify the prefix to the results to verify
prefix = ""


# Directory containing secret files to verify
verify_dir = os.path.join(prefix, "verified_secrets/")
os.makedirs(verify_dir, exist_ok=True)

# List all files in the verification directory
all_to_verify = os.listdir(verify_dir)
print(f"Verifying {len(all_to_verify)} secrets")

count = 0

# Iterate over each file in the directory
for file in all_to_verify:
    # Only process .txt files
    if not file.endswith(".txt"):
        continue

    # Open and load the JSON content of the file
    with open(verify_dir + "/" + file, "r") as f:
        result = json.load(f)
        valid = True

        # Skip files with certain detector IDs (known false positives or unsupported)
        if result.get("detector", 0) in ["17", "1031", "1021", "1010", "1012", "1025", "1002", "727", "4", "1008"]:
            continue

        # Skip files that have already been verified
        if "verified" in result:
            continue

        # Special handling for GitHub tokens (detector 8)
        elif result.get("detector", 0) == "8":
            beginnings = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"]
            valid = False
            for beginning in beginnings:
                if result.get("secret").startswith(beginning):
                    valid = True

        # Special handling for detector 17 (URIs)
        elif result.get("detector", 0) == "17":
            uri = result.get("secret", "")
            # Ignore schema.org URIs and certain keywords
            if "schema.org" in uri:
                valid = False
            elif "mailto" in uri or "sentry" in uri: # detector cannot verify sentry tokens
                valid = False

        # If not valid, mark as verified: False and save
        if not valid:
            result["verified"] = False
            with open(verify_dir + "/" + file, "w") as f:
                json.dump(result, f)
            continue

        # Run trufflehog verify on the file
        subprocess.run([path_to_trufflehog, "verify", "--file", verify_dir + "/" + file])
        time.sleep(1)
        count += 1

print(f"Verified {count} secrets")