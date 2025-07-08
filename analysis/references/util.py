import sqlite3
import json
import os
import logging
import argparse
import exiftool
import pathlib
import subprocess
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# List of file extensions and magic types that are not interesting
not_intersting = [".dex",".supp", ".frag", ".version", ".vert" ,".nib", ".png", ".svg", ".jpg", ".ttf", ".xcf", ".car", ".xml", ".supx", ".supf", ".sinf", ".dylib", ".so", ".material", ".rsa", ".mf", ".sf"]
not_intersting_magic = ["image/", "font/", "audio/", "video/", "x-mach-binary", "opentype"]


def arg_parser():
    parser = argparse.ArgumentParser(description='Process an App file.')
    parser.add_argument('--app', required=True, help='Path containing the app file (apk or ipa)')
    parser.add_argument('--file-names', required=True, help='Path to the JSON file (JSON List) containing file names to search')
    parser.add_argument('--tmp-dir', default="./", help='Path to the temporary directory')
    parser.add_argument('--database', default="~/databases/matching.db", help='Path to the database file')
    parser.add_argument('-p', action='store_true', help='If set, print the results to the console')

    return parser.parse_args()




def extract_data_from_config_path(config_path):
    app_name = os.path.basename(config_path)[:-5]
    platform = os.path.basename(os.path.dirname(config_path))
    return app_name, platform


def get_app_id(cursor, app_name, platform):
    try:
        cursor.execute("""
            SELECT id
            FROM apps
            WHERE app_name = ? AND platform = ?
        """, (app_name, platform))
        app_id = cursor.fetchone()
        if app_id:
            return app_id[0]
        else:
            return None
    except sqlite3.Error as e:
        logger.error(f"Error fetching app_id: {e}", exc_info=True)
        return None



def already_analyzed(database, app_name, platform):
    conn = connect_db(database)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT reference_files
        FROM files join apps on files.app_id = apps.id
        WHERE apps.app_name = ? AND apps.platform = ? AND reference_files IS NOT NULL
    """, (app_name, platform))
    result = len(cursor.fetchall()) > 0
    conn.close()
    return result



def connect_db(file_name):
    for _ in range(500):
        try:
            con = sqlite3.connect(file_name)
            return con
        except Exception as e:
            logger.error(f"Error connecting to database: {e}")

        print("Error connecting to database")
        
        logger.error("Error connecting to database")
        time.sleep(1)


def save_results(results, config_path, database):
    conn = connect_db(database)
    app_name, platform = extract_data_from_config_path(config_path)
    cursor = conn.cursor()
    app_id = get_app_id(cursor, app_name, platform)
    if not app_id:
        logger.warning(f"App {app_name} not found in the database")
        return
    cursor.close()

    for file_name, references in results.items():
        cursor = conn.cursor()
        success = False
        while not success:
            try:
                reference_apps_json = json.dumps(references)
                cursor.execute("""UPDATE files SET reference_files = ? WHERE file_name = ? AND app_id = ?;""", (reference_apps_json, file_name, app_id))
                logger.info(f"Successfully updated reference_files for {file_name} and {app_name}")
                cursor.close()
                success = True
            except sqlite3.Error as e:
                logger.error(f"Error updating reference_files for {file_name} and {app_name}: {e}")
                time.sleep(1)

    conn.close()
    return


def is_ios_binary(file_path):
    try:
        if "CodeSignature" in file_path or file_path.endswith(".plist"):
            return True
        if pathlib.Path(file_path).suffix == "":
            with exiftool.ExifToolHelper() as exif:
                metadata = exif.get_metadata(file_path)
                if "Mach-O executable" in str(metadata):
                    return True
    except Exception as e:
        logging.error(f"Error processing {file_path}: {e}")

    return False

def is_interesting(name, no_intersting_list):
    """
    Check if the name is not in the list of not interesting file types.
    """
    for v in no_intersting_list:
        if v in name:
            return False
    return True


def analyze_binary(binary_path, strings_to_search):
    """
    Analyze Mach-O binary using strings and search for specific strings.
    """
    results = {}
    try:
        path_to_add = binary_path
        if binary_path.endswith(".ownstrings"):
            path_to_add = binary_path[:-11]
            with open(binary_path, 'r') as f:
                output = f.read()
        else:
            # Extract strings from the binary
            output = subprocess.check_output(["strings", binary_path], text=True)

            
        for search_string in strings_to_search:
            if search_string in binary_path:
                continue
            if search_string in output:
                current_results = results.get(search_string, [])
                current_results.append(path_to_add)
                results[search_string] = current_results
    except Exception as e:
        logging.error(f"Error analyzing Mach-O binary {binary_path}: {e}")
    return results


def exit_if_analyzed(args):
    if not args.p:
        app_name, platform = extract_data_from_config_path(args.file_names)

        if already_analyzed(args.database,app_name, platform):
            logging.info(f"App {app_name} on platform {platform} already analyzed, skipping")
            exit()
