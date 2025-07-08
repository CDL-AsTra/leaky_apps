import argparse
import re
import requests
import json
import os

# List of default CocoaPods sources
default_sources = [
    "https://github.com/CocoaPods/Specs.git",
    "https://cdn.cocoapods.org/",
    "https://github.com/CocoaPods/Specs",
    "trunk"
]

def has_non_default_podfile_sources(file_path):
    """
    Checks if the Podfile contains any non-default source declarations.
    Returns True if non-default sources are found, otherwise False.
    """
    sources = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                if line.strip().startswith("#"):
                    continue  # Skip comments
                match = re.match(r'\s*source\s+["\'](.*?)["\']', line)
                if match:
                    sources.append(match.group(1))
        
        if not sources:
            print("No sources found in the file.")
            return
        
        print(f"Found {len(sources)} source declarations:")
        for src in sources:
            print(f" - {src}")
        
        # Warn if multiple sources are declared
        if len(sources) > 1:
            print("Warning: Multiple source declarations found!")
        
        # Identify non-default sources
        non_default_sources = [s for s in sources if s not in default_sources]
        
        if non_default_sources:
            print("Warning: The following sources are not the general CocoaPods repository:")
            for src in non_default_sources:
                print(f" - {src}")
            return True
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"Error: {e}")
    return False

def get_all_pod_names(file_path):
    """
    Extracts all pod names from a Podfile.
    Returns a set of pod names.
    """
    pod_names = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                if line.strip().startswith("#"):
                    continue  # Skip comments
                if ":git" in line:
                    continue  # Skip pods with custom git sources
                match = re.match(r'\s*pod\s+[\'"](.*?)[\'"]', line)
                if match:
                    pod_names.add(match.group(1))
    except Exception as e:
        print(f"Error: {e}")
    return pod_names

def search_pod(pod_name):
    """
    Checks if a pod exists in the CocoaPods trunk repository.
    Returns True if found, False otherwise.
    """
    url = f"https://trunk.cocoapods.org/api/v1/pods/{pod_name}"
    response = requests.get(url)
    if response.status_code == 200:
        pod_info = response.json()
        return True
    elif response.status_code == 404:
        return False
    else:
        print(f"⚠️ Error: Unable to fetch data (Status Code: {response.status_code})")
    return False

def check_pods(pod_names):
    """
    Checks if the given pods are registered in the default CocoaPods repository.
    Returns a set of pods not found in the default repository.
    """
    non_default_registerd_pod = set()
    for pod in pod_names:
        main_pod = pod.split("/")[0]
        sub_pod = pod.split("/")[1] if "/" in pod else None
        if sub_pod:
            # Check both main pod and subpod
            if not search_pod(main_pod) and not search_pod(main_pod+sub_pod):
                print(f"❌ Pod '{pod}' not found in the CocoaPods repository.")
                non_default_registerd_pod.add(pod)
        else:
            print(f"Checking pod '{pod}'... is {search_pod(main_pod)}")
            if not search_pod(main_pod):
                non_default_registerd_pod.add(pod)
    return non_default_registerd_pod

def check_podfile(file_path):
    """
    Checks a Podfile for non-default sources and pods not in the default repository.
    """
    if not has_non_default_podfile_sources(file_path):
        print("Only default sources found. Skipping pod search.")
        return
    pod_names = get_all_pod_names(file_path)
    print(f"Found {len(pod_names)} pods in the Podfile:")
    return check_pods(pod_names)

def get_log_name(file_path):
    """
    Generates a log file name based on the file path.
    """
    for file in file_path.split("/"):
        if file.endswith("_android") or file.endswith("_ios"):
            return file + ".log"
    return "default_file_should_not_happend.log"

def parse_podfile_lock(file_path):
    """
    Parses a Podfile.lock to find pods from non-default sources.
    Returns a set of such pods.
    """
    non_default_pods = set()
    with open(file_path, "r") as f:
        repo_block_started = False
        non_default_started = False
        for line in f.readlines():
            if "SPEC REPOS:" in line:
                repo_block_started = True
                continue
            if repo_block_started and line.strip() == "":
                return check_pods(non_default_pods)
            if not line.strip().startswith("-") and repo_block_started:
                source = line.strip().replace('"', '')
                if source.endswith(":"):
                    source = source[:-1]
                if source not in default_sources:
                    print(f"Non-default source found: {source}")
                    non_default_started = True
                    continue
            if non_default_started and "-" in line:
                pod_name = line.strip().replace("-", "").strip()
                non_default_pods.add(pod_name)
    return check_pods(non_default_pods)

def analyze_podspec(file_path):
    """
    Analyzes a .podspec file to extract the pod name and check its registration.
    """
    with open(file_path, "r") as f:
        for line in f.readlines():
            if ".name" in line:
                podname = line.split("=")[1].strip().replace('"', "").replace("'", "")
                return check_pods([podname])
    return set()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check sources in a Podfile or Podfile.lock")
    parser.add_argument("-file", help="Path to the Podfile or Podfile.lock", default=None)
    parser.add_argument("-logfile", default=None)
    parser.add_argument("-directory", default=None)

    args = parser.parse_args()
    if args.directory:
        # Walk through the directory and process Podfiles, Podfile.locks, and podspecs
        for root, dirs, files in os.walk(args.directory):
            for file in files:
                file_path = os.path.join(root, file)
                logfile = get_log_name(file_path)
                if os.path.exists(logfile) and not file.endswith(".podspec"):
                    continue
                if file == "Podfile":
                    print(f"{file_path} is a Podfile")
                    non_default_pod = check_podfile(file_path)
                    if non_default_pod:
                        with open(logfile, "w") as f:
                            json.dump(list(non_default_pod), f)
                elif file == "Podfile.lock":
                    print(f"{file_path} is a Podfile.lock")
                    non_default_pod = parse_podfile_lock(file_path)
                    if non_default_pod:
                        with open(logfile, "w") as f:
                            json.dump(list(non_default_pod), f)
                elif file.endswith(".podspec"):
                    print(f"{file_path} is a podspec")
                    non_default_pod = analyze_podspec(file_path)
                    if non_default_pod:
                        if os.path.exists(logfile):
                            with open(logfile, "r") as f:
                                all = json.load(f)
                                if non_default_pod not in all:
                                    all = all + list(non_default_pod)
                                    all = list(set(all))
                                    with open(logfile, "w") as f2:
                                        json.dump(list(all), f2)
                        else:
                            with open(logfile, "w") as f:
                                json.dump(list(non_default_pod), f)
    else:
        # Single file mode
        if args.file.endswith("Podfile.lock"):
            non_default_pod = parse_podfile_lock(args.file)
            if len(non_default_pod) > 0:
                with open(args.logfile, "w") as f:
                    json.dump(list(non_default_pod), f)
        else:
            non_default_pod = check_podfile(args.file)
            if len(non_default_pod) > 0:
                with open(args.logfile, "w") as f:
                    json.dump(list(non_default_pod), f)
