import sqlite3
import json
import argparse
import os
import logging
from references.util import not_intersting, not_intersting_magic, is_interesting

def setup_logging():
    """
    Set up logging configuration for the script.
    Logs messages with INFO level and above, including timestamps.
    """
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_arguments():
    """
    Parse command line arguments for database path and output directory.
    Returns:
        argparse.Namespace: Parsed arguments with 'database' and 'output' attributes.
    """
    parser = argparse.ArgumentParser(description='Create the database.')
    parser.add_argument('--database', default="/matching_new.db", help='Path to the database file')
    parser.add_argument('--output', default="./config_files/", help='Output directory')
    return parser.parse_args()

def connect_to_database(database_path):
    """
    Connect to the SQLite database.
    Args:
        database_path (str): Path to the SQLite database file.
    Returns:
        tuple: (sqlite3.Connection, sqlite3.Cursor)
    """
    logging.info(f"Connecting to database at {database_path}")
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    return conn, cursor

def fetch_apps(cursor):
    """
    Fetch all apps from the 'apps' table in the database.
    Args:
        cursor (sqlite3.Cursor): Database cursor.
    Returns:
        list: List of app records (tuples).
    """
    logging.info("Fetching apps from the database")
    cursor.execute("SELECT * FROM apps")
    return cursor.fetchall()

def fetch_files_for_app(cursor, app_id):
    """
    Fetch all files for a given app from the 'files' table.
    Args:
        cursor (sqlite3.Cursor): Database cursor.
        app_id (int): ID of the app.
    Returns:
        list: List of file records (tuples).
    """
    logging.info(f"Fetching files for app_id {app_id}")
    cursor.execute("SELECT * FROM files WHERE app_id = ?", (app_id,))
    return cursor.fetchall()

def select_files_to_analyze(files):
    """
    Select files to analyze based on their mime type and name.
    Args:
        files (list): List of file records (tuples).
    Returns:
        set: Set of file names (file[3]) that are interesting.
    """
    logging.info("Selecting files to analyze")
    result = set()
    for file in files:
        # file[5]: mimeType, file[6]: fileName
        if is_interesting(file[5], not_intersting_magic) and is_interesting(file[6], not_intersting):
            result.add(file[3])  # file[3]: fileName
    return result

def save_config(output_dir, platform, app_name, config_data):
    """
    Save the configuration data to a JSON file for the given app.
    Args:
        output_dir (str): Output directory path.
        platform (str): Platform name (e.g., 'android', 'ios').
        app_name (str): Name of the app.
        config_data (list): Data to be saved in the config file.
    """
    logging.info(f"Saving config for {app_name} on platform {platform}")
    os.makedirs(os.path.join(output_dir, platform), exist_ok=True)
    with open(os.path.join(output_dir, platform, f"{app_name}.json"), 'w') as f:
        json.dump(config_data, f, indent=4)

def select_files_for_references(files, isApple=False):
    """
    Select files for reference analysis, filtering out uninteresting files.
    Args:
        files (list): List of file dictionaries.
        isApple (bool): Whether the platform is Apple (iOS/macOS).
    Returns:
        list: List of interesting file names.
    """
    result = set()
    for file in files:
        file_name = file.get("fileName", "")
        # Remove '.ownstrings' suffix if present
        if file_name.endswith(".ownstrings"):
            file_name = file_name[:-11]
        file_path = file.get("filePath", "")
        # Skip Android resource files if not Apple
        if not isApple and ("kotlin" in file_path or "/res/color" in file_path or "/res/drawable" in file_path or "/res/layout" in file_path or "/res/menu" in file_path or "/res/values" in file_path or "/res/xml" in file_path or "res/anim" in file_path):
            continue
        # Skip Apple-specific files
        if isApple and ("mach" in file.get("mimeType", "") or file_name == "Info.plist"):
            continue
        # Check if file is interesting by mimeType and name
        if is_interesting(file.get("mimeType", ""), not_intersting_magic) and is_interesting(file_name, not_intersting):
            result.add(file_name)
    return list(result)

def main():
    setup_logging()
    args = parse_arguments()
    database_path = args.database
    output_dir = args.output

    conn, cursor = connect_to_database(database_path)
    apps = fetch_apps(cursor)

    for app in apps:
        app_id, app_name, platform = app[0], app[1], app[2]
        config_path = os.path.join(output_dir, platform, f"{app_name}.json")
        # Skip if config file already exists
        if os.path.exists(config_path):
            logging.info(f"Config file for {app_name} already exists, skipping")
            continue

        files = fetch_files_for_app(cursor, app_id)
        files_to_analyze = select_files_to_analyze(files)
        files_to_analyze = list(files_to_analyze)

        save_config(output_dir, platform, app_name, files_to_analyze)

    conn.close()
    logging.info("Finished processing all apps")

if __name__ == "__main__":
    main()