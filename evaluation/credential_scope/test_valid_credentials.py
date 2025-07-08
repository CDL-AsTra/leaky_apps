import os
import json
import argparse
import subprocess

# Parse command-line arguments for input and output folders
def parse_arguments():
    parser = argparse.ArgumentParser(description='Process some folders.')
    parser.add_argument('--input_folder', type=str, help='The input folder')
    parser.add_argument('--output_folder', type=str, help='The output folder')
    return parser.parse_args()

# Collect secrets from input_folder that match certain criteria
def get_secrets_to_analyze(input_folder):
    to_analyze = []
    for file in os.listdir(input_folder):
        if file.endswith(".txt"):
            with open(os.path.join(input_folder, file), "r") as f:
                data = json.load(f)
                # Check if secret is verified and detector is in the allowed list
                if data.get("verified", False) and data.get("detector", "-1") in [
                    "8", "12", "201", "968", "13", "26", "125", "126", "926", "16",
                    "9", "20", "118", "41", "34", "14", "928", "902", "875"
                ]:
                    data["hash"] = file[:-4]  
                    to_analyze.append(data)
    return to_analyze

# Run trufflehog on a secret and save the output
def call_trufflehog(secret, output_folder):
    # Skip if log file already exists
    if os.path.exists(os.path.join(output_folder, secret.get("hash") + ".log")):
        return

    # analyze-v2 is only provided by our trufflehog changes -> separated analyze command
    command = [
        "trufflehog", "analyze-v2", secret.get("detector"),
        "--logfile", os.path.join(output_folder, f"{secret.get('hash')}.log"),
        "--secret", secret.get("secret")
    ]
    # Run the command and write output to a .txt file
    with open(os.path.join(output_folder, secret.get("hash") + ".txt"), "w") as output_file:
        subprocess.run(command, stdout=output_file, stderr=subprocess.STDOUT)
    # Prepend the secret's JSON data to the output file
    with open(os.path.join(output_folder, secret.get("hash") + ".txt"), "r+") as output_file:
        content = output_file.read()
        output_file.seek(0, 0)
        output_file.write(json.dumps(secret) + '\n' + content)
    return

def main():
    args = parse_arguments()
    input_folder = args.input_folder
    output_folder = args.output_folder
    secrets = get_secrets_to_analyze(input_folder)
    print(len(secrets))  #
    for secret in secrets:
        call_trufflehog(secret, output_folder)

if __name__ == "__main__":
    main()