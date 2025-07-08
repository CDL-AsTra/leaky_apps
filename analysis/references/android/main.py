import os
import subprocess
import sys
import logging
import shutil
import json
import mimetypes

import references.util as util

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


def decompile_apk(apk_path, output_dir):
    """
    Decompile an APK file using jadx and store the output in output_dir.

    Args:
        apk_path (str): Path to the APK file.
        output_dir (str): Directory where the decompiled files will be stored.
    """
    try:
        if os.path.exists(output_dir):
            # Skip decompilation if output already exists
            return
        os.makedirs(output_dir, exist_ok=True)
        # Set environment variable to limit RAM usage for jadx
        env = os.environ.copy()
        env["JADX_OPTS"] = "-XX:MaxRAMPercentage=20.0"
        # Run jadx to decompile the APK
        subprocess.run(
            ["jadx", "-d", output_dir, "-m", "simple", "-j", "1", "--show-bad-code", apk_path],
            check=True,
            env=env
        )
        logging.info(f"APK decompiled successfully to {output_dir}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error during APK decompilation: {e}")
        logging.info("Trying to continue")


def search_in_files(base_dir, strings_to_search):
    """
    Search for occurrences of specific strings in files under given directories.

    Args:
        base_dir (list): List of directories to search in.
        strings_to_search (list): List of strings to search for.

    Returns:
        dict: Mapping from search string to list of file paths where found.
    """
    results = {}
    analyzed_binaries = set()

    for dir_to_search in base_dir:
        for root, _, files in os.walk(dir_to_search):
            # Skip common library directories to avoid noise
            if "/androidx/" in root or "/javax/" in root:
                logging.debug(f"Skipping {root}")
                continue
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # Analyze binaries in specific directory only once
                    if "/resources/lib/" in file_path and file not in analyzed_binaries:
                        binary_result = util.analyze_binary(file_path, strings_to_search)
                        results = merge_results(results, binary_result)
                        analyzed_binaries.add(file)
                        continue
                    # Only process text or JSON files
                    mime = str(mimetypes.guess_type(file_path))
                    if "text" not in mime and "json" not in mime:
                        continue
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        for pattern in strings_to_search:
                            if pattern in content:
                                current_results = results.get(pattern, [])
                                current_results.append(file_path)
                                results[pattern] = current_results
                except Exception as e:
                    logging.error(f"Error reading file {file_path}: {e}", exc_info=True)
    return results


def merge_results(result_map_1, result_map_2):
    """
    Merge two result dictionaries, combining lists of file paths for each key.

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
    Remove a directory and all its contents.

    Args:
        file_path (str): Path to the directory to remove.
    """
    try:
        shutil.rmtree(file_path)
    except OSError as e:
        logging.error(f"Error deleting temporary files: {e}")


def read_json(file_path):
    """
    Read a JSON file and return its contents.

    Args:
        file_path (str): Path to the JSON file.

    Returns:
        object: Parsed JSON data.
    """
    data = []
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data


def get_tmp_directory(tmp_dir, apk_file_path):
    """
    Generate a temporary directory path for decompilation output.

    Args:
        tmp_dir (str): Base temporary directory.
        apk_file_path (str): Path to the APK file.

    Returns:
        str: Path to the temporary output directory.
    """
    base_name = os.path.basename(apk_file_path)
    base_name = base_name[:-4] + "_jadx_output"
    tmp_dir = os.path.join(tmp_dir, base_name)
    return tmp_dir


def analyze_apk(apk_path, files_to_search, tmp_dir):
    """
    Decompile an APK and search for specified strings in the decompiled files.

    Args:
        apk_path (str): Path to the APK file.
        files_to_search (list): List of strings to search for.
        tmp_dir (str): Base temporary directory.

    Returns:
        dict: Mapping from search string to list of file paths where found.
    """
    tmp_dir = get_tmp_directory(tmp_dir, apk_path)

    decompile_apk(apk_path, tmp_dir)

    # Search for the strings in the decompiled resources and sources
    logging.info("Searching for references in the decompiled APK...")
    logging.info("searching resources")
    matches_resources = search_in_files([os.path.join(tmp_dir, "resources")], files_to_search)
    logging.info("searching sources")
    matches_sources = search_in_files([os.path.join(tmp_dir, "sources")], files_to_search)
    matches = merge_results(matches_resources, matches_sources)

    # Clean up temporary files
    cleanup(tmp_dir)
    return matches


def analyze_apk_library(decompiled_apk_path, files_to_search):
    """
    Search for specified strings in a previously decompiled APK directory.

    Args:
        decompiled_apk_path (str): Path to the decompiled APK directory.
        files_to_search (list): List of strings to search for.

    Returns:
        dict: Mapping from search string to list of file paths where found.
    """
    logging.info("Searching for references in the decompiled APK...")
    logging.info("searching resources")
    matches_resources = search_in_files([os.path.join(decompiled_apk_path, "resources")], files_to_search)
    logging.info("searching sources")
    source_base = os.path.join(decompiled_apk_path, "sources")
    # If all_sources exists, search there; otherwise, search sources root
    if os.path.exists(os.path.join(source_base, "all_sources")):
        matches_sources = search_in_files([os.path.join(source_base, "all_sources")], files_to_search)
    else:
        matches_sources = search_in_files([source_base], files_to_search)
    matches = merge_results(matches_resources, matches_sources)
    return matches


def get_apk_path(config, app_directory):
    """
    Construct the path to the APK file based on config and app directory.

    Args:
        config (str): Path to the config file.
        app_directory (str): Directory containing the APK.

    Returns:
        str: Path to the APK file.
    """
    app_name, _ = util.extract_data_from_config_path(config)
    return os.path.join(app_directory, f"{app_name}.apk")
    

def main():

    args = util.arg_parser()
    apk_path = get_apk_path(args.file_names, args.app)
    if not os.path.exists(apk_path):
        logging.error(f"APK file {apk_path} does not exist")
        sys.exit(1)
        
    util.exit_if_analyzed(args)
    files = read_json(args.file_names)
    tmp_dir = args.tmp_dir
    matches = analyze_apk(apk_path, files, tmp_dir)
    if args.p:
        print(json.dumps(matches, indent=4))
    else:
        util.save_results(matches, args.file_names, args.database)


if __name__ == "__main__":
    main()
