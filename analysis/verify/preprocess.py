import json
import sqlite3
import argparse
import logging
import os
import hashlib
import shutil


def setup_logging():
    """
    Set up logging configuration for the script.
    """
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def prepare_gitleaks(secret):
    """
    Prepare a gitleaks secret for processing.

    Args:
        secret (dict): Secret dictionary.

    Returns:
        str: The stripped match string.
    """
    return secret["Match"].strip()

def prepare_trufflehog(secret):
    """
    Prepare a trufflehog secret for processing.

    Args:
        secret (dict): Secret dictionary.

    Returns:
        str: The processed raw secret string.
    """
    raw = secret["Raw"].strip()
    # If RawV2 exists and DetectorType is not 17, process further
    if secret.get("RawV2", "") != "" and secret.get("DetectorType", -1) != 17:
        raw2 = secret["RawV2"].strip()
        if ";-|" in raw2:
            return raw2
        else:
            part2 = raw2.replace(raw, "")
            new_raw =  raw + ";-|"  + part2
            if new_raw.endswith(";-|"):
                new_raw = new_raw[:-3]
            return new_raw
    return raw

def fetch_all_secrets(database):
    """
    Fetch all secrets from the given SQLite database.

    Args:
        database (str): Path to the SQLite database.

    Returns:
        list: List of tuples containing secret, detection_rule, file_path, app_id.
    """
    logging.info(f"Connecting to database: {database}")
    with sqlite3.connect(database) as conn:
        c = conn.cursor()
        c.execute("SELECT secret, detection_rule, file_path,app_id from secrets join files on secrets.file_id = files.id;") 
        secrets = c.fetchall()
        logging.info(f"Fetched {len(secrets)} secrets from the database.")
        return secrets

def parse_arguments():
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(description='Check secrets in the database.')
    parser.add_argument('--database', type=str, help='Path to the SQLite database file')
    parser.add_argument('--database_2', type=str, help='Path to the SQLite database file', default=None)
    parser.add_argument('--old-results', default="", type=str, help='Path to a saved JSON file with previous results')
    parser.add_argument('--output_folder', required=True, type=str, help='Path to a saved JSON file with previous results')
    return parser.parse_args()

def get_unique_secrets(all_secrets):
    """
    Extract unique secrets from the list of all secrets.

    Args:
        all_secrets (list): List of secrets from the database.

    Returns:
        tuple: (results_secrets, rule_ids, unique_per_file)
    """
    results_secrets = {}
    rule_ids = {}
    unique_per_file = {}
    for secret, detection_rule, file_path, appid in all_secrets:
        json_secret = json.loads(secret)
        # Process gitleaks secrets
        if detection_rule == "trufflehog":
            secret = prepare_trufflehog(json_secret)
        else:
            continue

        detector_type = json_secret.get("DetectorType", "")
        # Filter out secrets with specific descriptions or detector types
        if (json_secret.get("DetectorDescription","") == "Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data." or 
            json_secret.get("DetectorType", -1) in [1031, 1021, 1010, 1012, 1025, 1002, 727, 15] or  str(detector_type) in ["1002", "727", "1021", "1025", "1012", "1021", "1031", "1010", "4", "1008"] or
            json_secret.get("DetectorDescription", "") == "Identified an Email address." ):
            continue

        rule_ids[secret] = detector_type
        tmp = results_secrets.get(secret, set())
        tmp.add(appid)
        results_secrets[secret] = tmp
        
        findings = unique_per_file.get(file_path, {})
        tmp_findings = findings.get(detector_type, set())
        tmp_findings.add(secret)
        findings[detector_type] = tmp_findings
        unique_per_file[file_path] = findings

    return results_secrets, rule_ids, unique_per_file

def load_previous_results(path):
    """
    Load previous verification results from a folder.

    Args:
        path (str): Path to the folder containing previous results.

    Returns:
        dict: Mapping of secret to verification status.
    """
    result = {}
    if not os.path.exists(path):
        return result
    for file in os.listdir(path):
        with open(path + "/" + file, "r") as f:
            current = json.load(f)
            if "verified" in current:
                result[current["secret"]] = current["verified"]
    return result

def filter_secrets(secrets, previous_results, rule_ids, max_apps=100000):
    """
    Filter secrets based on previous results, rule IDs, and app count.

    Args:
        secrets (dict): Mapping of secret to set of app IDs.
        previous_results (dict): Mapping of secret to verification status.
        rule_ids (dict): Mapping of secret to detector type.
        max_apps (int): Maximum number of apps a secret can appear in.

    Returns:
        dict: Filtered secrets.
    """
    filtered = {}
    for secret, appids in secrets.items():
        if len(appids) > max_apps:
            continue

        if secret in previous_results:
            continue
        # Special handling for GitHub tokens (detector type 8)
        elif rule_ids[secret] == 8:
            beginnings = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"]
            valid = False
            for beginning in beginnings:
                if secret.startswith(beginning):
                    valid = True
            if not valid:
                continue
        
        filtered[secret] = rule_ids[secret]
    return filtered

def filter_secrets_per_file(filtered_secrets, file_info, max_secrets_per_file=14):
    """
    Further filter secrets based on the number of secrets per file.

    Args:
        filtered_secrets (dict): Filtered secrets.
        file_info (dict): Mapping of file path to detector info.
        max_secrets_per_file (int): Maximum secrets allowed per file.

    Returns:
        dict: Further filtered secrets.
    """
    filtered = {}
    for file_path, detectorinfo in file_info.items():
        for detector, secrets in detectorinfo.items():
            if len(secrets) > max_secrets_per_file:
                continue
            for secret in secrets:
                if secret in filtered_secrets:
                    filtered[secret] = filtered_secrets[secret]
    return filtered

def save_for_trufflehog_verify(secrets, output= "./to_verify/"):
    """
    Save secrets for trufflehog verification as JSON files.

    Args:
        secrets (dict): Mapping of secret to detector type.
        output (str): Output folder path.
    """
    for secret, detector in secrets.items():
        result = {"secret": secret, "detector": str(detector)}
        md5_hash = hashlib.md5((secret+str(detector)).encode()).hexdigest()
        if os.path.exists(output + md5_hash + ".txt"):
            continue
        with open(output + md5_hash + ".txt", "w") as f:
            print(f"Saving {md5_hash}")
            json.dump(result, f)
    return

def copy_secrets(secrect, path):
    """
    Copy or save secrets to the specified path, using test files if available.

    Args:
        secrect (dict): Mapping of secret to detector type.
        path (str): Destination folder path.
    """
    for secret, detector in secrect.items():
        md5_hash = hashlib.md5((secret+str(detector)).encode()).hexdigest()
        result = {"secret": secret, "detector": str(detector)}
        if os.path.exists(path + md5_hash + ".txt"):
            continue

        if os.path.exists("./test/" + md5_hash + ".txt"):
            shutil.copy("./test/" + md5_hash + ".txt", path + md5_hash + ".txt")
            continue

        with open(path + md5_hash + ".txt", "w") as f:
            print(f"Saving {md5_hash}")
            json.dump(result, f)

def main():
    setup_logging()
    args = parse_arguments()
    secrets = fetch_all_secrets(args.database)
    if args.database_2:
        secrets += fetch_all_secrets(args.database_2)

    logging.info(f"Found {len(secrets)} secrets.")
    previous_results = load_previous_results(args.old_results)
    logging.info(f"Loaded {len(previous_results)} previous results.")

    secrect_map, rule_ids, secrets_per_file = get_unique_secrets(secrets)
    logging.info(f"Found {len(secrect_map)} unique secrets.")
    filtered_secrets = filter_secrets(secrect_map, previous_results, rule_ids)

    logging.info(f"Filtered {len(filtered_secrets)} secrets.")
    filtered_secrets = filter_secrets_per_file(filtered_secrets, secrets_per_file)

    logging.info(f"Further filtered {len(filtered_secrets)} secrets.")

    save_for_trufflehog_verify(filtered_secrets, output=args.output_folder)

if __name__ == "__main__":
    main()
