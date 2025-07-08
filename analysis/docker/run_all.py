import os
import subprocess


for app in os.listdir("/apps/"):
    if (app.endswith(".apk") and not ".split." in app) or app.endswith(".ipa"):
        subprocess.run(["python3", "analysis.py", "--appPath", f"/apps/{app}", "--deleteAfter", "--database-file", "/results/database.db", "--unzipDir", "/tmp/"])


os.makedirs("/results/verified_secrets/", exist_ok=True)
# Run verification with trufflehog
subprocess.run(["python3", "verify/preprocess.py", "--database", "/results/database.db", "--output_folder", "/results/verified_secrets/"])
subprocess.run(["python3", "verify/verify_with_trufflehog.py"])