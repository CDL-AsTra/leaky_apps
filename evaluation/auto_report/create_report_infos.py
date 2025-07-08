import os
import json
import sqlite3
import argparse

# Parse command line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Create report infos")
    parser.add_argument(
        "--input_path", type=str, required=True, help="Path to the report"
    )
    parser.add_argument(
        "--database_path", type=str, required=True, help="Path to the database"
    )
    parser.add_argument(
        "--category", type=str, required=False, default=None, help="Category of the report"
    )
    parser.add_argument('--code', action='store_true', help='A binary flag for code')
    parser.add_argument("--output", type=str, required=True, help="Path to the output")
    return parser.parse_args()

# Query app info from the database based on secret and detector
def get_app_infos(secret, detector, database_path):
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    query = """
    SELECT DISTINCT apps.app_name, apps.platform FROM apps JOIN files on apps.id = files.app_id JOIN secrets on secrets.file_id = files.id where secrets.secret like ? and secrets.secret like ?;
    """
    cursor.execute(query, ("%" + secret + "%", '%"DetectorType": '+ detector  +',%', ))
    results = cursor.fetchall()
    if len(results) == 0:
        # Try again with a modified secret if no results
        cursor.execute(query, ("%" + secret.replace(";-|", "") + "%", '%"DetectorType": '+ detector  +',%', ))
        results = cursor.fetchall()
    conn.close()
    return results

# Query file info from the database based on secret and detector
def get_file_infos(secret, detector, database_path):
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    query = """
    SELECT DISTINCT files.file_name FROM apps JOIN files on apps.id = files.app_id JOIN secrets on secrets.file_id = files.id where secrets.secret like ? and secrets.secret like ?;
    """
    cursor.execute(query, ("%" + secret + "%", '%"DetectorType": '+ detector  +',%', ))
    results = cursor.fetchall()
    if len(results) == 0:
        cursor.execute(query, ("%" + secret.replace(";-|", "") + "%", '%"DetectorType": '+ detector  +',%', ))
        results = cursor.fetchall()
    conn.close()
    return results

# Query secret info from the database based on secret and detector
def get_secret_infos(secret, detector, database_path):
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    query = """
    SELECT DISTINCT secrets.secret FROM apps JOIN files on apps.id = files.app_id JOIN secrets on secrets.file_id = files.id where secrets.secret like ? and secrets.secret like ?;
    """
    cursor.execute(query, ("%" + secret + "%", '%"DetectorType": '+ detector  +',%', ))
    results = cursor.fetchall()
    if len(results) == 0:
        cursor.execute(query, ("%" + secret.replace(";-|", "") + "%", '%"DetectorType": '+ detector  +',%', ))
        results = cursor.fetchall()
    conn.close()

    if len(results) == 0:
        return None
    
    return json.loads(results[0][0])

# Get app info by app id
def get_app_infos_id(id, database_path):
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    query = """
    SELECT DISTINCT app_name, platform FROM apps where id = ?;
    """
    cursor.execute(query, (id,))
    results = cursor.fetchall()
    conn.close()

    if len(results) == 0:
        return None
    
    return results[0][0], results[0][1]

# Load verified findings from JSON files in a directory
def load_verified_findings(file_path, id= None):
    results = []
    for file in os.listdir(file_path):
        with open(os.path.join(file_path, file), "r") as f:
            result = json.load(f)

            if result.get("verified", False):
                if result.get("detector", 0) == str(id) or id is None or id == "None":
                    results.append(result)

    return results

# Map detector id to category name
def map_findings_to_category(id):
    mapping = {
        "-1": "Source Code",
        "8": "Repositories",
        "9": "Repositories",
        "2": "AWS",
        "6": "Google Cloud",
        "17": "URI"
    }

    return mapping.get(id, "General Hardcoded Credentials")

# Load a JSON file
def load_json_file(file_path):
    with open(file_path, "r") as f:
        return json.load(f)

# Check if both Android and iOS versions exist for an app
def is_android_and_ios(app_infos, current_id, mapping_file="../dataset/apps/matching.json"):
    mapping = load_json_file(mapping_file)
    ids = []
    for app in app_infos:
        ids.append(app[0]+"_"+app[1])

    if current_id[1] == "ios":
        if mapping.get(current_id[0]) + "_android" in ids:
            return mapping.get(current_id[0])
    return None

# Get the mapped app id for iOS apps
def get_mapping_app_id(app_info, mapping_file="../dataset/apps/matching.json"):
    mapping = load_json_file(mapping_file)
    if app_info[1] == "ios":
        return mapping.get(app_info[0])
    return app_info[0]

# Save the report as a JSON file, merging findings if the file exists
def save_report(output_path, result, android_id):
    platform = result.get("platform", "").replace(" ", "_")
    print("saving id " + android_id)
    output_path = os.path.join(
        os.path.join(output_path, android_id) + "_" + platform + ".json"
    )
    if os.path.exists(output_path):
        old_result = load_json_file(output_path)
        not_in = True
        for finding in old_result["findings"]:
            if finding == result["findings"][0]:
                not_in = False
                break
        if not_in:
            old_result["findings"].append(result["findings"][0])
        
        result = old_result

    with open(output_path, "w") as f:
        json.dump(result, f)

# Create the report info file for a finding
def creat_report_info_file(finding, database_path, json_report_templates, output_path):
    app_infos = get_app_infos(finding.get("secret"),  finding.get("detector"),database_path)
    file_infos = get_file_infos(finding.get("secret"),  finding.get("detector"), database_path)
    secret_infos = get_secret_infos(finding.get("secret"), finding.get("detector"), database_path)
    if secret_infos is None:
        print(f"Secret not found for {finding.get('secret')}")
        return
    detector_name = secret_infos["DetectorName"]
    detector_description = secret_infos["DetectorDescription"]
    if len(detector_description) == 0:
        print(f"Detector description not found for {detector_name}")

    text = json_report_templates.get(
        map_findings_to_category(finding.get("detector", "-1")), ""
    )
    # Mask the secret for the report
    secret_text = finding.get("secret").replace(";-|", " ")
    secret_text = secret_text.split(" ")
    new_secret_text = ""
    for part in secret_text:
        new_secret_text = new_secret_text + " " + part[0 : len(part) - 3] + "***"
    text = text.replace("%CREDENTIALS%", new_secret_text)
    text = text.replace(
        "%FILES%", "(" + ", ".join([file[0] for file in file_infos]) + ")"
    )
    text = text.replace("%TYPE%", detector_name)
    text = text.replace("%FROM_TRUFFLEHOG%", detector_description)
    detector_id = finding.get("detector", "-2")
    # Choose output subdirectory based on detector id
    if detector_id == "2":
        output_path = os.path.join(output_path, "aws")
    elif detector_id == "8" or detector_id == "9":
        output_path = os.path.join(output_path, "repositories")
    elif detector_id == "6":
        output_path = os.path.join(output_path, "google_cloud")
    elif detector_id == "-1":
        output_path = os.path.join(output_path, "code")
    elif detector_id == "17":
        output_path = os.path.join(output_path, "uri")
    else:
        output_path = os.path.join(output_path, "other")

    to_skip = []

    # Handle Android/iOS mapping and skip duplicates
    for app in app_infos:
        if app[1] == "android":
            continue
        android_id = is_android_and_ios(app_infos, app)
        if android_id is not None:
            to_skip.append(android_id + "_android")
            to_skip.append(app[0] +  "_ios")
            report_info_content(output_path, True, app, text)
        else:
            to_skip.append(app[0] + "_" + app[1])
            report_info_content(output_path, False, app, text)

    for app in app_infos:
        if app[0] + "_" + app[1] in to_skip:
            continue
        report_info_content(output_path, False, app, text)

# Generate the content for the report info and save it
def report_info_content(output_path, both, id, text):
    android_id = get_mapping_app_id(id)

    if both:
        text = text.replace("%PLATFORM%", "Android and iOS")
        result = {"id": android_id, "platform": "Android and iOS", "findings": [text]}
        save_report(output_path, result, android_id)
        return

    app_id = id[0]
    app_platform = id[1]
    if app_platform == "ios":
        app_platform = "iOS"
    else:
        app_platform = "Android"
    text = text.replace("%PLATFORM%", app_platform)
    text = text.replace("%APP%", app_id)
    result = {"id": app_id, "platform": app_platform, "findings": [text]}
    save_report(output_path, result, android_id)

# Create code report entries for code findings
def create_code_report(data, database_path, json_report_templates, category_name, files = False):
    results = []
    for app in data:
        info = get_app_infos_id(app[0], database_path=database_path)
        text = json_report_templates.get(category_name, "")
        text = text.replace("%APP%", info[0])
        text = text.replace("%PLATFORM%", info[1])
        if files:
            tmp = ""
            for file in app[1]:
                tmp = tmp + f"* {file}\n"
            text = text.replace("%FILES%", tmp)
        results.append({"id": info[0], "platform": info[1], "findings": [text]})
    return results

# Process dependency management findings
def process_dependency_file():
    result = {}
    with open("./report_infos_dm.json", "r") as f:
        loaded = json.load(f)
        for key, value in loaded.items():
            for item in value:
                current_key = item[0]
                if current_key not in result:
                    result[current_key] = []
                result[current_key].append(item[2])

    to_return = []
    for key, value in result.items():
        to_return.append((key, list(set(value))))

    return to_return

# Process code findings and generate reports
def process_code_findings(file_path, database_path, json_report_templates, mapping_file, output_path):
    tmp_results = []
    results = []

    all_ids = set()
    with open(file_path, "r") as f:
        loaded = json.load(f)
        all_code = loaded.get(".java") +  loaded.get(".kt") + loaded.get(".swift")
        code = set()
        for c in all_code:
            code.add(tuple(c))

        swiftpm = loaded.get("swiftpm")
        spm_version = loaded.get("spm_versions")
        tmp_results.extend(create_code_report(swiftpm, database_path, json_report_templates, "Source Code"))
        tmp_results.extend(create_code_report(spm_version, database_path, json_report_templates, "spm_versions"))
        tmp_results.extend(create_code_report(process_dependency_file(), database_path, json_report_templates, "Dependency Management File", files=True))
        tmp_results.extend(create_code_report(code, database_path, json_report_templates, "Source Code"))

        # Remove duplicates by id+platform
        for tmp_result in tmp_results:
            if tmp_result.get("id") + "_" + tmp_result.get("platform") in all_ids:
                continue
            all_ids.add(tmp_result.get("id") + "_" + tmp_result.get("platform"))
            results.append(tmp_result)
        
        id_results = {}
        # Group results by mapped app id
        for result in results:
            android_id = get_mapping_app_id([result.get("id"), result.get("platform")], mapping_file= mapping_file)
            tmp = id_results.get(android_id, [])
            tmp.append(result)
            id_results[android_id] = tmp
        
        # Save reports, merging findings for Android/iOS pairs
        for key, value in id_results.items():
            if len(value) == 1:
                if value[0].get("platform") == "ios":
                    value[0]["platform"] = "iOS"
                else:
                    value[0]["platform"] = "Android"
                save_report(output_path, value[0], key)
            else:
                current = value[0]
                current["platform"] = "Android and iOS"
                current["id"] = key
                current["findings"] = current["findings"] + value[1]["findings"]
                save_report(output_path, value[0], key)

    return


def main():
    args = parse_args()
    if not args.code:
        verified_findings = load_verified_findings(args.input_path, str(args.category))
    else:
        process_code_findings(args.input_path, args.database_path, load_json_file("./mail_infos/all.json"), "../dataset/apps/matching.json", args.output)
        return

    json_report_templates = load_json_file("./mail_infos/all.json")
    print(len(verified_findings))
    for finding in verified_findings:
        creat_report_info_file(
            finding, args.database_path, json_report_templates, args.output
        )

if __name__ == "__main__":
    main()
