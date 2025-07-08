import os
import sys
import logging
import shutil
import json
import plistlib
import zipfile

import references.util as util

# Configure logging for the script
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def extract_ipa(ipa_path, output_dir):
    """
    Extracts the contents of an IPA file to the specified output directory.

    Args:
        ipa_path (str): Path to the IPA file.
        output_dir (str): Directory where the IPA contents will be extracted.

    Returns:
        None
    """
    try:
        if os.path.exists(output_dir):
            # If output directory already exists, skip extraction
            return
        os.makedirs(output_dir, exist_ok=True)
        with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
            zip_ref.extractall(output_dir)
        logging.info(f"IPA extracted successfully to {output_dir}")
    except Exception as e:
        logging.error(f"Error during IPA extraction: {e}")
        sys.exit(1)

def analyze_plist(plist_path, strings_to_search):
    """
    Analyzes a plist file and searches for specific strings.

    Args:
        plist_path (str): Path to the plist file.
        strings_to_search (list): List of strings to search for in the plist.

    Returns:
        dict: Mapping of found strings to the plist file path(s).
    """
    results = {}
    try:
        with open(plist_path, 'rb') as f:
            plist_data = plistlib.load(f)
        # Convert plist data to JSON string for easier searching
        plist_str = json.dumps(plist_data)
        for search_string in strings_to_search:
            if search_string in plist_str:
                current_results = results.get(search_string, [])
                current_results.append(plist_path)
                results[search_string] = current_results
    except Exception as e:
        logging.error(f"Error analyzing plist file {plist_path} - trying to analyze it with strings: {e}")
        # If plist parsing fails, fallback to normal binary analysis
        return util.analyze_binary(plist_path, strings_to_search)

    return results

def search_in_files(base_dir, strings_to_search, is_lib=False, file_info = {}):
    """
    Searches for occurrences of strings in files within a directory.

    Args:
        base_dir (str): Directory to search in.
        strings_to_search (list): Strings to search for.
        is_lib (bool): Whether searching in a library context.
        file_info (dict): Additional file information (e.g., mime types).

    Returns:
        dict: Mapping of found strings to file path(s).
    """
    results = {}
    for root, _, files in os.walk(base_dir):
        for file in files:
            file_path = os.path.join(root, file)
            # Skip certain directories/files
            if "SC_Info" in file_path or "_CodeSignature" in file_path:
                continue
            try:
                if file.endswith('.plist'):
                    # Analyze plist files
                    plist_results = analyze_plist(file_path, strings_to_search)
                    results.update(plist_results)
                elif util.is_ios_binary(file_path):
                    # Analyze iOS binary files
                    binary_results = util.analyze_binary(file_path, strings_to_search)
                    results = merge_results(results, binary_results)
                elif is_lib and file.endswith('.ownstrings'):
                    # Analyze .ownstrings files in library context if they are Mach-O binaries
                    if "mach" in file_info.get(file_path[:-11], ""):
                        binary_results = util.analyze_binary(file_path, strings_to_search)
                        results = merge_results(results, binary_results)
            except Exception as e:
                logging.error(f"Error reading file {file_path}: {e}")
    return results

def merge_results(result_map_1, result_map_2):
    """
    Merges two result dictionaries.

    Args:
        result_map_1 (dict): First result dictionary.
        result_map_2 (dict): Second result dictionary.

    Returns:
        dict: Merged result dictionary.
    """
    for key, value in result_map_2.items():
        current_results = result_map_1.get(key, [])
        current_results.extend(value)
        result_map_1[key] = current_results
    return result_map_1

def cleanup(file_path):
    """
    Deletes a directory and its contents.

    Args:
        file_path (str): Path to the directory to delete.

    Returns:
        None
    """
    try:
        shutil.rmtree(file_path)
    except OSError as e:
        logging.error(f"Error deleting temporary files: {e}")

def read_json(file_path):
    """
    Reads a JSON file and returns its contents.

    Args:
        file_path (str): Path to the JSON file.

    Returns:
        dict or list: Parsed JSON data.
    """
    with open(file_path, 'r') as f:
        return json.load(f)

def get_tmp_directory(tmp_dir, ipa_file_path):
    """
    Constructs a temporary directory path for IPA extraction.

    Args:
        tmp_dir (str): Base temporary directory.
        ipa_file_path (str): Path to the IPA file.

    Returns:
        str: Path to the temporary extraction directory.
    """
    base_name = os.path.basename(ipa_file_path)
    base_name = base_name[:-4] + "_ipa_extracted"
    return os.path.join(tmp_dir, base_name)

def remove_march_o_files_from_search(files_to_search, tmp_dir):
    """
    Removes files from the search list that are not Mach-O binaries.

    Args:
        files_to_search (list): List of file names to search.
        tmp_dir (str): Directory to check for Mach-O binaries.

    Returns:
        list: Filtered list of files to search.
    """
    new_files_to_search = set()
    for root, _, files in os.walk(tmp_dir):
        for file in files:
            if file in files_to_search and not util.is_ios_binary(os.path.join(root,file)):
                new_files_to_search.add(file)
    return list(new_files_to_search)

def create_file_info(files):
    """
    Creates a mapping from file paths to their mime types.

    Args:
        files (list): List of file metadata dictionaries.

    Returns:
        dict: Mapping of file paths to mime types.
    """
    result = {}
    for file in files:
        result[file.get("filePath", "")] = file.get("mimeType", "")
    return result

def analyze_ipa_lib(extracted_ipa, files_to_search, files):
    """
    Analyzes an extracted IPA in a library context.

    Args:
        extracted_ipa (str): Path to the extracted IPA directory.
        files_to_search (list): List of strings to search for.
        files (list): List of file metadata dictionaries.

    Returns:
        dict: Mapping of found strings to file path(s).
    """
    logging.info("Searching for references in resources and plist files...")
    return search_in_files(extracted_ipa, files_to_search, is_lib=True, file_info = create_file_info(files))

def analyze_ipa(ipa_path, files_to_search, tmp_dir):
    """
    Extracts and analyzes an IPA file for specific string references.

    Args:
        ipa_path (str): Path to the IPA file.
        files_to_search (list): List of strings to search for.
        tmp_dir (str): Temporary directory for extraction.

    Returns:
        dict: Mapping of found strings to file path(s).
    """
    tmp_dir = get_tmp_directory(tmp_dir, ipa_path)

    # Extract the IPA
    extract_ipa(ipa_path, tmp_dir)
    app_dir = os.path.join(tmp_dir, "Payload")
    files_to_search = remove_march_o_files_from_search(files_to_search, app_dir)
    # Search in resources and plist files
    logging.info("Searching for references in resources and plist files...")
    matches = search_in_files(app_dir, files_to_search)
    cleanup(tmp_dir)
    return matches

def get_ipa_path(config, app_directory):
    """
    Constructs the path to the IPA file based on configuration.

    Args:
        config (str): Path to the configuration file.
        app_directory (str): Directory containing the IPA.

    Returns:
        str: Path to the IPA file.
    """
    app_name, _ = util.extract_data_from_config_path(config)
    return os.path.join(app_directory, f"{app_name}.ipa")
    
def main():
    args = util.arg_parser()
    ipa_path = get_ipa_path(args.file_names, args.app)
    if not os.path.exists(ipa_path):
        logging.error(f"IPA file {ipa_path} does not exist")
        sys.exit(1)
        
    util.exit_if_analyzed(args)

    files_to_search = read_json(args.file_names)
    tmp_dir = args.tmp_dir
    matches = analyze_ipa(ipa_path, files_to_search, tmp_dir)
    if args.p:
        print(json.dumps(matches, indent=4))
    else:
        util.save_results(matches, args.file_names, args.database)

if __name__ == "__main__":
    main()
