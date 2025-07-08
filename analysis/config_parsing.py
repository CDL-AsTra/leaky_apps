import json
import logging
import plistlib
import re
import xmltojson
import yaml
from jproperties import Properties
from androguard.core.bytecodes.axml import AXMLPrinter, ARSCParser

# Configure logging to write debug and error messages to a log file
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename="app_analysis.log",
    filemode="a",
)
logger = logging.getLogger(__name__)

def secret_key_value_pair(key_string):
    """
    Checks if a given key string is likely to represent a secret (e.g., API key, token).
    Returns True if the key matches any of the keywords, otherwise False.
    """
    if type(key_string) is not type(""):
        return False
    key_string = key_string.lower()
    keywords_to_look_for = (
        'api"',
        'key"',
        'secret"',
        'token"',
        "bearer",
        "jwt",
        "credential",
        "client_id"
    )
    return any(keyword in key_string for keyword in keywords_to_look_for)

def parse_plist(file_path):
    """
    Attempts to parse a .plist file. Handles both binary and string-based plist formats.
    Returns a dictionary of key-value pairs.
    """
    try:
        # Try parsing as a binary plist
        with open(file_path, "rb") as f:
            return plistlib.load(f)
    except Exception as e:
        logger.error(f"Error reading plist file: {e}")
    try:
        # Try parsing as a localization strings file (binary)
        with open(file_path, "rb") as fp:
            localization_strings = fp.read()
        # Remove comments from the file
        pattern = rb"\/\*([\s\S]*?)\*\/"
        re.sub(pattern, "", localization_strings)
        plist_localization = {}
        items = localization_strings.splitlines()
        if len(items) <= 1:
            items = localization_strings.split(b";")
        for line in items:
            line = line.decode("utf-8")
            key_value = line.split("=")
            if len(key_value) > 1:
                key = key_value[0].replace('"', "").replace("'", "").strip()
                value = (
                    key_value[1]
                    .replace('"', "")
                    .replace("'", "")
                    .replace(";", "")
                    .strip()
                )
                plist_localization[key] = value
        return plist_localization
    except Exception as e:
        logger.error(f"Error reading plist file: {e}")
    try:
        # Try parsing as a localization strings file (text)
        with open(file_path, "r") as fp:
            localization_strings = fp.read()
        pattern = r"\/\*([\s\S]*?)\*\/"
        re.sub(pattern, "", localization_strings)
        items = localization_strings.splitlines()
        if len(items) <= 1:
            items = localization_strings.split(";")
        plist_localization = {}
        for line in items:
            key_value = line.split("=")
            if len(key_value) > 1:
                key = key_value[0].replace('"', "").replace("'", "").strip()
                value = (
                    key_value[1]
                    .replace('"', "")
                    .replace("'", "")
                    .replace(";", "")
                    .strip()
                )
                plist_localization[key] = value
        return plist_localization
    except Exception as e:
        logger.error(f"Could not parse file {file_path}: {e}")
    return {}

def parse_file(file_path):
    """
    Parses a configuration file based on its extension and returns its contents as a dictionary.
    Supports JSON, plist, XML, YAML, properties, env, and arsc files.
    """
    to_search = {}
    if file_path.endswith(".json"):
        try:
            with open(file_path, "r") as f:
                to_search = json.load(f)
        except Exception as e:
            logger.error(f"Error reading JSON file: {e}")
    elif file_path.endswith(".plist"):
        to_search = parse_plist(file_path)
    elif file_path.endswith(".xml"):
        if "AndroidManifest.xml" in file_path:
            # Special handling for AndroidManifest.xml (binary XML)
            try:
                with open(file_path, "rb") as f:
                    axml = AXMLPrinter(f.read())
                    buf = axml.get_buff()
                    to_search = xmltojson.parse(buf)
            except Exception as e:
                logger.error(f"Error reading AndroidManifest.xml file: {e}")
        else:
            # Try parsing as regular XML (text)
            try:
                with open(file_path, "r") as f:
                    my_xml = f.read()
                    to_search = xmltojson.parse(my_xml)
            except Exception as e:
                logger.error(f"Error reading XML file: {e}")
                # Try reading as binary if text fails
                try:
                    with open(file_path, "rb") as f:
                        my_xml = f.read()
                        to_search = xmltojson.parse(my_xml)
                except Exception as e:
                    logger.error(f"Error reading XML file: {e}")
    elif file_path.endswith(".yaml") or file_path.endswith(".yml"):
        try:
            with open(file_path, "r") as f:
                to_search = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error reading YAML file: {e}")
    elif file_path.endswith(".properties") or file_path.endswith(".env"):
        # Try loading Java properties or .env files
        try:
            configs = Properties()
            with open(file_path, "r") as config_file:
                configs.load(config_file)
        except Exception as e:
            logger.error(f"Error reading properties file: {e}")
            try:
                configs = Properties()
                with open(file_path, "rb") as config_file:
                    configs.load(config_file)
            except Exception as e:
                logger.error(f"Error reading properties file: {e}")
    elif file_path.endswith(".arsc"):
        # Parse Android resources.arsc files
        try:
            arsc_parser = ARSCParser(open(file_path, "rb").read())
            resources = arsc_parser.get_strings_resources()
            to_search = xmltojson.parse(resources)
        except Exception as e:
            logger.error(f"Error reading arsc file: {e}")

    return to_search

def iterate_nested_list(nested_list):
    """
    Recursively iterates through a nested list, searching for secret key-value pairs.
    Returns a list of found secrets.
    """
    result = []
    for item in nested_list:
        if isinstance(item, dict):
            return result + iterate_nested_dict(item)
        elif isinstance(item, list):
            return result + iterate_nested_list(item)
    return result

def iterate_nested_dict(nested_dict):
    """
    Recursively iterates through a nested dictionary, searching for secret key-value pairs.
    Returns a list of found secrets.
    """
    result = []
    if type(nested_dict) is type(""):
        # If the input is a string (e.g., manifest stored as string), try to parse as JSON
        try:
            nested_dict = json.loads(nested_dict)
        except json.JSONDecodeError:
            logger.error("Error parsing JSON")
            return result
    elif isinstance(nested_dict, list):
        return result + iterate_nested_list(nested_dict)
    elif not isinstance(nested_dict, dict):
        return result

    for key, value in nested_dict.items():
        if isinstance(value, dict):
            return result + iterate_nested_dict(value)
        elif isinstance(value, list):
            return result + iterate_nested_list(value)
        else:
            if secret_key_value_pair(key):
                result.append({key: value})
    return result

def search_for_secrets_key_value_pairs(file_path):
    """
    Main entry point: parses the given file and recursively searches for secret key-value pairs.
    Returns a list of found secrets.
    """
    to_search = parse_file(file_path)
    # Recursively search for secrets in the parsed data
    return iterate_nested_dict(to_search)
