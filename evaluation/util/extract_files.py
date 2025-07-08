import os
import plistlib
import zipfile
import argparse
import sqlite3
import json

def get_infos_secret(filename, database_path, query_wherepart="file_name "):
    """
    Query the database for app information and file paths matching the given filename.

    Args:
        filename (str): The filename or pattern to search for.
        database_path (str): Path to the SQLite database.
        query_wherepart (str): Additional WHERE clause for the SQL query.

    Returns:
        list: List of tuples containing (app_name, platform, file_path).
    """
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    query = (
        "SELECT app_name, platform, file_path FROM apps "
        "join files on apps.id = files.app_id where " + query_wherepart
    )
    if "*" in filename:
        query += "like ?;"
        filename = filename.replace("*", "%")
    else:
        query += "= ?;"
    print(query + filename)
    cursor.execute(query, (filename,))
    results = cursor.fetchall()
    conn.close()
    return results

def convert_binary_plist_to_xml(plist_path):
    """
    Converts a binary plist file to XML format and overwrites the original file.

    Args:
        plist_path (str): Path to the plist file.
    """
    try:
        with open(plist_path, "rb") as f:
            plist_data = plistlib.load(f)
        with open(plist_path, "wb") as f:
            plistlib.dump(plist_data, f, fmt=plistlib.FMT_XML)
        print(f"Converted and overwritten: {plist_path}")
    except Exception as e:
        print(f"Error converting plist: {e}")

def extract_files_from_zips(app_path, paths, dest_dir, app_name, platform):
    """
    Extracts specified files from a ZIP archive (APK/IPA) and converts plists if needed.

    Args:
        app_path (str): Path to the ZIP archive.
        paths (list): List of file paths to extract.
        dest_dir (str): Destination directory for extracted files.
        app_name (str): Name of the app.
        platform (str): Platform ('android' or 'ios').
    """
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
    try:
        with zipfile.ZipFile(app_path, 'r') as zip_ref:
            for file in paths:
                dest_file_path = f"{dest_dir}/{app_name}_{platform}/{file}"
                # If file already exists, just convert plist if needed
                if os.path.exists(dest_file_path):
                    convert_binary_plist_to_xml(dest_file_path)
                    continue
                zip_ref.extract(file, f"{dest_dir}/{app_name}_{platform}")
                convert_binary_plist_to_xml(dest_file_path)
                print(f"Extracted {file} from {app_path} to {dest_dir}")
    except zipfile.BadZipFile:
        print(f"Skipping invalid ZIP file: {app_path}")
    except FileNotFoundError:
        print(f"Skipping missing file: {app_path}")
    except KeyError:
        print(f"Skipping missing file: {app_path}")

def parse_file_path(file_path):
    """
    Parses the file path to extract the app name and the relative file path.

    Args:
        file_path (str): The full file path.

    Returns:
        tuple: (app_name, remaining_part)
    """
    file_split = file_path.split("/")
    remaining_part = ""
    app_name = ""
    remaining_start = False
    platform_part = ""
    if "_android/" in file_path:
        platform_part = "_android"
    elif "_ios" in file_path:
        platform_part = "_ios"
    for part in file_split:
        if part.endswith(platform_part):
            app_name = part[:-len(platform_part)]
            remaining_start = True
            continue
        if remaining_start:
            if remaining_part != "":
                remaining_part = remaining_part + "/"
            remaining_part += part
    return app_name, remaining_part

def cluster_files(results):
    """
    Groups file paths by app name and platform.

    Args:
        results (list): List of (app_name, platform, file_path) tuples.

    Returns:
        dict: Mapping of "app_name;-|platform" to list of file paths.
    """
    to_return = {}
    for name, platform, file in results:
        app_name, file_path = parse_file_path(file)
        current_app = f"{app_name};-|{platform}"
        current_list = to_return.get(current_app, [])
        current_list.append(file_path)
        to_return[current_app] = current_list
    return to_return

def process(android_dir, ios_dir, filename, database, dst_file, frameworks=False, bundle=False, plugin=False):
    """
    Main processing function to extract files from APK/IPA archives.

    Args:
        android_dir (str): Directory containing APK files.
        ios_dir (str): Directory containing IPA files.
        filename (str): Filename or pattern to extract.
        database (str): Path to the SQLite database.
        dst_file (str): Destination directory for extracted files.
        frameworks (bool): Extract only frameworks if True.
        bundle (bool): Extract only bundles if True.
        plugin (bool): Extract only plugins if True.
    """
    if frameworks:
        to_extract = get_infos_secret(
            filename, database,
            query_wherepart='file_path like "%/Frameworks/%.framework/Info.plist" and file_name'
        )
    elif bundle:
        to_extract = get_infos_secret(
            filename, database,
            query_wherepart='file_path like "%.bundle/Info.plist" and file_name'
        )
    elif plugin:
        to_extract = get_infos_secret(
            filename, database,
            query_wherepart='file_path like "%/PlugIns/%/Info.plist" and file_name'
        )
    else:
        to_extract = get_infos_secret(filename, database)
    print(len(to_extract))
    for name_platform, files in cluster_files(to_extract).items():
        name_split = name_platform.split(";-|")
        name = name_split[0]
        platform = name_split[1]
        if platform == "ios":
            ipa_path = os.path.join(ios_dir, f"{name}.ipa")
            extract_files_from_zips(ipa_path, files, dst_file, name, platform)
        elif platform == "android":
            apk_path = os.path.join(android_dir, f"{name}.apk")
            extract_files_from_zips(apk_path, files, dst_file, name, platform)

if __name__ == "__main__":
    # Argument parser for command-line usage
    parser = argparse.ArgumentParser(description="Extract specific file from ZIP archives.")
    parser.add_argument("--filename", help="Name of the file to extract", default=None)
    parser.add_argument("--database", help="Directory containing the databse")
    parser.add_argument("--android_dir", help="Directory containing ZIP files")
    parser.add_argument("--ios_dir", help="Directory containing ZIP files")
    parser.add_argument("--dst_dir", help="Directory to extract files to")
    parser.add_argument("--frameworks", help="Extract frameworks", action="store_true")
    parser.add_argument("--bundle", help="Extract bundles", action="store_true")
    parser.add_argument("--plugin", help="Extract plugin", action="store_true")
    parser.add_argument("--filename_file", help="File containing the filenames to extract", default=None)

    args = parser.parse_args()
    # Handle extraction modes
    if args.frameworks:
        print("Extracting frameworks")
        process(args.android_dir, args.ios_dir, "Info.plist", args.database, args.dst_dir, frameworks=True)
    elif args.bundle:
        print("Extracting bundles")
        process(args.android_dir, args.ios_dir, "Info.plist", args.database, args.dst_dir, bundle=True)
    elif args.plugin:
        print("Extracting plugins")
        process(args.android_dir, args.ios_dir, "Info.plist", args.database, args.dst_dir, plugin=True)
    # If no filename or filename_file is provided, use a default list of common dependency files
    elif args.filename is None and args.filename_file is None:
        filenames = [
            "Podfile", "Podfile.lock", "*.podspec", "Cartfile", "Cartfile.resolved", "Package.swift", "Package.resolved",
            "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bower.json", ".bower.json",
            "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "poetry.lock", "setup.py", "pom.xml",
            "build.gradle", "build.gradle.kts", "gradle.lockfile", "settings.gradle", "settings.gradle.kts",
            "packages.config", "*.csproj", "global.json", "Directory.Packages.props", "CMakeLists.txt", "*.cmake",
            "vcpkg.json", "conanfile.txt", "conanfile.py", "meson.build", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum",
            "Gopkg.toml", "composer.json", "composer.lock", "Gemfile", "Gemfile.lock", "pubspec.yaml", "pubspec.yaml.dist",
            "pubspec.lock", "stack.yaml", "cabal.project", "cpanfile", "*.gemspec", "Rakefile", "opensslv.h",
            "configure.in", "configure", "configure.ac"
        ]
        for file in filenames:
            process(args.android_dir, args.ios_dir, file, args.database, args.dst_dir)
    # If a file containing filenames is provided, load and process each
    elif args.filename_file is not None:
        with open(args.filename_file, "r") as f:
            files = json.load(f)
            for file in files:
                process(args.android_dir, args.ios_dir, file, args.database, args.dst_dir)
    # Otherwise, process the single filename provided
    else:
        process(args.android_dir, args.ios_dir, args.filename, args.database, args.dst_dir)