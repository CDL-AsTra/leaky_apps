"""
analysis.py

This script analyzes mobile app packages (APK for Android, IPA for iOS) to extract metadata, search for secrets, and store results in a SQLite database.
It detects secrets using Trufflehog (optional also Gitleaks).

Usage:
    python analysis.py --appPath <path_to_app> [--unzipDir <dir>] [--deleteAfter] [--database-file <db>] [--gitleaks-config <config>]
"""

import zipfile
import os
import shutil
import argparse
import exiftool
import pathlib
import sqlite3
import logging
import subprocess
import json
import glob
import magic

# Import utility functions for filtering and reference analysis
from references.util import not_intersting, not_intersting_magic, is_interesting
from references.create_config.create_config import select_files_for_references
from references.android.main import decompile_apk, analyze_apk_library
from references.ios.main import analyze_ipa_lib

# Prepare lists of file suffixes and magic types to ignore during analysis
not_intersting_search = not_intersting
not_intersting_magic_search = not_intersting_magic
not_intersting_search.remove('.dex')
not_intersting_search.remove('.so')
not_intersting_search.remove('.dylib')
not_intersting_magic_search.remove('x-mach-binary')

# Set up logging to file
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', filename='app_analysis.log', filemode='a')
logger = logging.getLogger(__name__)

class ExifData:
    """Class for storing EXIF metadata."""
    def __init__(self, name, value):
        self.name = name
        self.value = value

class FileInfo:
    """Class for storing file metadata."""
    def __init__(self, app_name, file_name, file_path, metadata):
        self.app_name = app_name
        self.file_name = file_name
        self.file_path = file_path
        self.metadata = metadata

def get_metadata(path):
    """
    Extract metadata from a file using exiftool.
    Returns a dictionary of metadata.
    """
    result = []
    try:
        with exiftool.ExifToolHelper() as et:
            metadata = et.get_metadata(path)
            for d in metadata:
                return d
    except Exception as e:
        logger.error(f"Error getting metadata: {e}")
    return result

def get_ios_appid(basename):
    """
    Extract iOS app ID from file basename.
    """
    return basename.split("_")[0]

def get_base_file_name(path):
    """
    Get the base file name (without extension) from a path.
    """
    base_name = os.path.basename(path)
    file_name_without_ext = os.path.splitext(base_name)[0]
    return file_name_without_ext

def get_base_path(path):
    """
    Get the directory name from a path.
    """
    return os.path.dirname(path)

def extract_app(app_path, output_dir):
    """
    Extract a ZIP archive (APK/IPA) to the specified output directory.
    Returns True on success, False on failure.
    """
    try:
        with zipfile.ZipFile(app_path, 'r') as zip_ref:
            zip_ref.extractall(output_dir)
        return True
    except Exception as e:
        logger.error(f"Error extracting app file: {e}")
        return False

# Initialize magic for MIME type detection
mime = magic.Magic(mime=True)
def get_mime_type(file_path):
    """
    Get the MIME type of a file using python-magic.
    """
    try:
        return mime.from_file(file_path) 
    except FileNotFoundError as e:
        logger.error(f"Error getting mime type: {e}")
        return "file not found"
    except magic.MagicException as e:
        logger.error(f"Error getting mime type: {e}")
        return "magic error"

def is_path_excluded(path):
    """
    Exclude certain resource/media paths from analysis to speed up processing.
    """
    exclued_paths = ["/res/drawable/", "/res/anim/", "/res/animator/", "/res/color/", "/res/drawable-/", "/res/layout/", "/res/layout-", "/res/mipmap-"]
    for p in exclued_paths:
        if p in path:
            return True
    return False

def parse_trufflehog_results(results, output_dir):
    """
    Parse Trufflehog JSONL results and group by file path.
    """
    start = ""
    if output_dir.startswith("/"):
        start = "/"
    elif output_dir.startswith("./"):
        start = "./"
    results_per_file = {}
    for result in results:
        file_path = result.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "")
        if file_path.endswith(".ownstrings"):
            file_path = file_path[:-11]
        if not file_path.startswith(start):
            file_path = start + file_path
        tmp = results_per_file.get(file_path, [])
        tmp.append(result)
        results_per_file[file_path] = tmp
    return results_per_file

def parse_gitleaks_results(results, output_dir):
    """
    Parse Gitleaks JSON results and group by file path.
    """
    start = ""
    if output_dir.startswith("/"):
        start = "/"
    elif output_dir.startswith("./"):
        start = "./"
    results_per_file = {}
    for result in results:
        file_path = result.get("File", "")
        if file_path.endswith(".ownstrings"):
            file_path = file_path[:-11]
        if not file_path.startswith(start):
            file_path = start + file_path
        tmp = results_per_file.get(file_path, [])
        tmp.append(result)
        results_per_file[file_path] = tmp
    return results_per_file

def add_secrets_to_results(results, secrets, detection_rule):
    """
    Add detected secrets to the results list for each file.
    """
    for result in results:
        if result["filePath"] in secrets:
            result[f"secrets_{detection_rule}"] = secrets[result["filePath"]]
    return results

def analyze_app(output_dir, gitleaks_config, app_name, platform, skip_secrets = False) -> dict:
    """
    Analyze extracted app files for metadata and secrets.
    Returns a list of file analysis results.
    """
    results = []
    file_names_analyzed = set()
    lproj_file_analyzed = set()

    # Walk through extracted files and analyze each
    for root, dirs, files in os.walk(output_dir):
        for file in files:
            file_path = os.path.join(root, file)
            logger.debug(f"Processing file: {file_path}")
            mime_type = get_mime_type(file_path) 
            try:
                file_size = os.path.getsize(file_path)
            except Exception as e:
                logger.error(f"Error getting file size: {e}")
                file_size = -1
            
            suffix = pathlib.Path(file_path).suffix.lower()
            # Skip uninteresting files and duplicates
            if ( ((file.endswith(".js") or file.endswith(".html")) and file in file_names_analyzed) or
                 is_path_excluded(file_path) or 
                 not is_interesting(mime_type, not_intersting_magic_search) or
                 not is_interesting(suffix, not_intersting_search) or
                 (".lproj" in file_path and file in lproj_file_analyzed)
                 or file.endswith(".dex") 
                 ):
                 pass
            else:
                if ".lproj" in file_path:
                    lproj_file_analyzed.add(file)
                file_names_analyzed.add(file)
                if "text" not in mime_type:
                    create_strings_file(file_path)
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        logger.error(f"Error removing file: {e}", exc_info=True)
                
            results.append({"fileName": file, "filePath": file_path, "fileSize": file_size, "mimeType": mime_type, "suffix": suffix, "secrets_trufflehog": [], "secret_key_value_pairs": [], "secrets_gitleaks": []})
    if skip_secrets:
        return results
    
    # Search for secrets using Trufflehog
    logger.info("Searching for secrets in the extracted files...")
    trufflehog = parse_trufflehog_results(search_for_secrets_trufflehog(output_dir), output_dir)
    logger.info("Trufflehog finished")
    results = add_secrets_to_results(results, trufflehog, "trufflehog")
    return results

def app_analyzed(app_name, platform, con):
    """
    Check if the app has already been analyzed (exists in DB).
    """
    cur = con.execute("SELECT id FROM apps WHERE app_name = ? AND platform = ?", [app_name, platform])
    return len(cur.fetchall())

def find_split_files(app_name, file_path):
    """
    Find Android split APK files matching the app name.
    """
    split_files = glob.glob(file_path + "/" + app_name + ".split.*")
    return split_files

def create_strings_file(file_path):
    """
    Run the 'strings' command on a file and save output to .ownstrings file.
    """
    try:
        if not os.path.exists(f"{file_path}.ownstrings"):
            subprocess.run(["strings", file_path], stdout=open(file_path+".ownstrings", "w"))
        return f"{file_path}.ownstrings"
    except Exception as e:
        logger.error(f"Error creating strings file: {e}")

def remove_strings_file(file_path):
    """
    Remove the .ownstrings file for a given file.
    """
    try:
        os.remove(file_path+".ownstrings")
    except Exception as e:
        logger.error(f"Error removing strings file: {e}")

def search_for_secrets_trufflehog(file_path):
    """
    Run Trufflehog on the given path and return detected secrets.
    """
    secrets = []
    try:
        result = subprocess.run(
            ["trufflehog", "-j", "--no-update",  "--no-debug", "filesystem", file_path, "--no-verification"],
            capture_output=True
        )
        out = result.stdout.decode("utf-8").strip()
        if out == "":
            return secrets
        for line in out.split("\n"):
            if line.strip() == "":
                continue
            result = json.loads(line)
            if "running source" in result.get("msg", "") or "finished" in result.get("msg", ""):
                continue
            secrets.append(result)
            logger.info(f"Secret found: {result}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running trufflehog: {e}")
    except Exception as e:
        logger.error(f"Error running trufflehog: {e}")
    return secrets

def search_for_secrets_gitleaks(file_path, config_path = "./gitleaks/config/gitleaks.toml", id = ""):
    """
    Run Gitleaks on the given path and return detected secrets.
    """
    secrets=[]
    try:
        subprocess.run(
            ["gitleaks", "detect", "-f", "json", "-r", "gitleaks" + id + ".json", "-c", config_path, "--no-banner", "--no-git",  "-s", file_path, "-l", "fatal"],
            capture_output=False
        )
        with open("gitleaks" + id + ".json", "r") as f:
            data = json.load(f)
            for secret in data:
                if "/sources/androidx/" in secret.get("File", ""):
                    continue
                secrets.append(secret)
        os.remove("gitleaks" + id + ".json")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running gitscrets: {e}")
    except Exception as e:
        logger.error(f"Error running gitscrets: {e}")
    return secrets

def setup_tables(con):
    """
    Create necessary tables in the SQLite database if they do not exist.
    """
    con.execute("CREATE TABLE IF NOT EXISTS apps(id INTEGER PRIMARY KEY AUTOINCREMENT, app_name VARCHAR, platform VARCHAR)")
    con.execute("CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY AUTOINCREMENT, app_id INT, file_size BIGINT, file_name VARCHAR, file_path VARCHAR, mime_type TEXT, suffix VARCHAR, reference_files TEXT, FOREIGN KEY (app_id) REFERENCES apps(id))")
    con.execute("CREATE TABLE IF NOT EXISTS secrets(id INTEGER PRIMARY KEY AUTOINCREMENT, file_id INT, secret TEXT, detection_rule TEXT, FOREIGN KEY (file_id) REFERENCES files(id))")

def insert_app_info(app_info, db_file):
    """
    Insert analyzed app and file info (including secrets) into the database.
    """
    app_name = app_info["app"]
    platform = app_info["platform"]
    con = connect_db(db_file)
    cursor = con.cursor()

    cursor.execute("INSERT INTO apps (app_name, platform) VALUES (?, ?)", [app_name, platform])
    app_id = cursor.lastrowid
    for file_info in app_info["files"]:
        file_name = file_info["fileName"]
        file_path = file_info["filePath"]
        file_size = file_info["fileSize"]
        mime_type = file_info["mimeType"]
        reference_files = file_info.get("reference_files", None)
        suffix = file_info["suffix"]
        secrets_trufflehog = file_info["secrets_trufflehog"]
        secrets_key_value = file_info["secret_key_value_pairs"]
        secrets_gitleaks = file_info["secrets_gitleaks"] 
        try:
            cursor.execute("INSERT INTO files(app_id, file_size, file_name, file_path, mime_type, suffix, reference_files) VALUES (?, ?, ?, ?, ?, ?, ?)", [app_id, file_size, file_name, file_path, mime_type, suffix, reference_files])
        except Exception as e:
            logger.error(f"Error inserting file info - try it again without exifdata: {e}")

        try:
            file_id = cursor.lastrowid
            for secret in secrets_trufflehog:
                cursor.execute("INSERT INTO secrets(file_id, secret, detection_rule) VALUES (?, ?, ?)", [file_id, json.dumps(secret), "trufflehog"])
            for secret in secrets_key_value:
                cursor.execute("INSERT INTO secrets(file_id, secret, detection_rule) VALUES (?, ?, ?)", [file_id, json.dumps(secret), "key_value_pairs"])
            for secret in secrets_gitleaks:
                cursor.execute("INSERT INTO secrets(file_id, secret, detection_rule) VALUES (?, ?, ?)", [file_id, json.dumps(secret), "gitleaks"])
        except Exception as e:
            logger.error(f"Error inserting file info: {e}")
    cursor.connection.commit()
    con.close()
    logger.info("Connection to database closed.")

def connect_db(file_name):
    """
    Connect to the SQLite database.
    """
    try:
        con = sqlite3.connect(file_name)
        return con
    except Exception as e:
        logger.error(f"Error connecting to database: {e}")
    logger.error("Error connecting to database")
    exit(1)

def parse_flags():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Process an app file")
    parser.add_argument('--appPath', type=str, required=True, help='Path to the app file')
    parser.add_argument('--unzipDir', type=str, help='Path to directory where the app file will be extracted')
    parser.add_argument('--deleteAfter', action='store_true', help='Delete the app file after extraction')
    parser.add_argument('--database-file', type=str, help='Path to the database file', default='analysis_sqllite.db')
    parser.add_argument('--gitleaks-config', type=str, help='Path to the gitleaks config file', default='./gitleaks/config/gitleaks.toml')
    return parser.parse_args()

def merge_reference_results(file_results, reference_results):
    """
    Merge reference analysis results into file analysis results.
    """
    for file_result in file_results:
        if file_result["fileName"] in reference_results:
            file_result["reference_files"] = json.dumps(reference_results[file_result["fileName"]])
    return file_results

def setup(db_file, app_name, platform):
    """
    Prepare the database and check if the app has already been analyzed.
    """
    con = connect_db(db_file)
    setup_tables(con)
    if app_analyzed(app_name, platform, con) > 0:
        logger.info("App already analyzed, skipping...")
        con.close()
        exit(0)
    con.close()

def add_split_files(app_path, app_name):
    """
    For Android, add split APK files to the analysis list.
    """
    to_analyze = [app_path] 
    if app_path.endswith(".apk"):
        if ".split." in app_path:
            logger.info("Only analyze split files with base APK file")
            exit(0)
        for app in find_split_files(app_name, get_base_path(app_path)):
            to_analyze.append(app)
            logger.debug(to_analyze)
    return to_analyze

def merge_sources(file_path):
    """
    Merge all source files in a directory into a single file for analysis.
    """
    if not os.path.exists(file_path):
        return file_path
    folder = os.path.join(file_path, "all_sources")
    if not os.path.exists(folder):
        os.mkdir(folder)
    output_file = os.path.join(folder, "sources.java")
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for folder_path, _, filenames in os.walk(file_path):
            for filename in filenames:
                current = os.path.join(folder_path, filename)
                with open(current, 'r', encoding='utf-8') as infile:
                    outfile.write(infile.read())
                    outfile.write("\n") 
    return folder

def run_analysis(app_path, app_name, platform, unzip_dir, gitleaks_config, to_analyze, delete_after):
    """
    Main analysis workflow for an app: extraction, analysis, decompilation, and reference analysis.
    Returns a dictionary with app and file analysis results.
    """
    app_info = {}
    app_info["app"] = app_name
    app_info["platform"] = platform
    total_files = []
    for app_path in to_analyze:
        # Extract app file
        logging.info(f"Extracting app file: {app_path}")
        output_dir = os.path.join(unzip_dir, f"{get_base_file_name(app_path)}_{platform}")
        app_extracted = extract_app(app_path, output_dir)
        if not app_extracted:
            logger.error("Error extracting app file")
            continue

        file_infos = analyze_app(output_dir, gitleaks_config, app_name, platform)
        total_files.extend(file_infos)

    references = {}
    if platform == "android":
        # Android: decompile APK and analyze sources
        search_for_references = select_files_for_references(total_files)
        base = to_analyze[0]
        decompile_path = f"{base}_{platform}_decompiled"
        decompile_apk(base, decompile_path)
        sources = os.path.join(decompile_path, "sources")   
        new_sources = merge_sources(sources)
        logger.info("Searching for secrets in the decompiled APK sources...")
        trufflehog = search_for_secrets_trufflehog(new_sources)
        logger.info("Trufflehog finished")
        classes_path = os.path.join(os.path.join(unzip_dir, f"{get_base_file_name(to_analyze[0])}_{platform}"), "classes.dex")
        trufflehog = {classes_path: trufflehog}
        add_secrets_to_results(total_files, trufflehog, "trufflehog")
        references = analyze_apk_library(decompile_path, search_for_references)
        if delete_after:
            shutil.rmtree(decompile_path)
    elif platform == "ios":
        # iOS: analyze IPA libraries for references
        search_for_references = select_files_for_references(total_files, isApple=True)
        references = analyze_ipa_lib(output_dir, search_for_references, total_files)

    total_files = merge_reference_results(total_files, references)
    app_info["files"] = total_files
    return app_info

def main():
    """
    Main entry point: parse arguments, run analysis, and store results.
    """
    args = parse_flags()
    app_path = args.appPath
    unzip_dir = args.unzipDir or get_base_path(app_path)
    delete_after = args.deleteAfter
    db_file = args.database_file
    gitleaks_config = args.gitleaks_config

    if app_path.endswith(".apk"):
        platform = "android"
    else:
        platform = "ios"

    app_name = get_base_file_name(app_path)
    if platform == "ios":
        app_name = get_ios_appid(app_name)

    setup(db_file, app_name, platform)
    to_analyze = add_split_files(app_path, app_name)
    app_info = run_analysis(app_path, app_name, platform, unzip_dir, gitleaks_config, to_analyze, delete_after)
    logging.info("Inserting data into database...")
    insert_app_info(app_info, db_file)
    logger.info("Metadata inserted into database successfully.")

    # Optionally delete extracted files after analysis
    if delete_after:
        for app_path in to_analyze:
            output_dir = os.path.join(unzip_dir, f"{get_base_file_name(app_path)}_{platform}")
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)

if __name__ == "__main__":
    main()
