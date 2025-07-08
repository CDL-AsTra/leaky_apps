import os
import json
import smtplib
import ssl
from email.message import EmailMessage
import argparse

# Reads a JSON file and returns its contents as a dictionary
def read_json(file_path):
    data = {}
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data

# Loads the mapping file and creates both iOS->Android and Android->iOS mappings
def load_mapping_file(mapping_path):
    with open(mapping_path, 'r') as f:
        ios_to_android = json.load(f)
        android_to_ios = {}
        for key, value in ios_to_android.items():
            android_to_ios[value] = key
        return ios_to_android, android_to_ios

# Reads the email body template from a file
def get_body():
    with open("mail_body.txt", "r") as f:
        body = f.read()
    return body

class Messager:
    # Initializes the Messager with mapping and metadata files
    def __init__(self, mapping_path, ios_metadata_path, android_metadata_path):
        self.ios_to_android, self.android_to_ios = load_mapping_file(mapping_path)
        self.ios_metadata = read_json(ios_metadata_path)
        self.android_metadata = read_json(android_metadata_path)

    # Gets the developer's email address for the given app ID and platform
    def get_developer_mail(self, id, platform):
        android_id, ios_id = None, None
        if platform == "iOS":
            android_id = self.ios_to_android[id]
            ios_id = id
        else:
            ios_id = self.android_to_ios[id]
            android_id = id

        mails = []

        android_mail = self.android_metadata[android_id]["mail"]
        if android_mail:
            mails.append(android_mail)

        return mails

    # Gets the developer's name for the given app ID and platform
    def get_developer_name(self, id, platform):
        if platform == "iOS":
            return self.ios_metadata[id]["seller"]
        else:
            return self.android_metadata[id]["seller"]

    # Gets the app name for the given app ID and platform
    def get_app_name(self, id, platform):
        if platform == "iOS":
            return self.ios_metadata[id]["app_name"]
        else:
            return self.android_metadata[id]["app_name"]

    # Creates an email message for the given app and findings
    def create_message(self, appId, platform, findings):
        # TODO: adjust CC and FROM
        msg = EmailMessage()
        msg["TO"] = self.get_developer_mail(appId, platform)
        msg["CC"] = [""]
        msg["FROM"] = ""
        msg["BCC"] = [""]
        msg["Subject"] = f"Potential Security and Privacy Issue in {platform} App {appId}" #+ self.get_app_name(appId, platform)
        body = get_body()

        # Replace placeholders in the email body
        body = body.replace("{Developer_Name}", self.get_developer_name(appId, platform))
        body = body.replace("{platform}", platform)
        body = body.replace("{app_name}", self.get_app_name(appId, platform))
        findings_text = ""

        # Format findings as a list
        for finding in findings:
            findings_text = "*" + finding + "\n"

        body = body.replace("{List of findings}", findings_text)
        #print(body)

        msg.set_content(body) 
        return msg

# Sends the email using SMTP over SSL
def send_mail(user, password, msg):
    port = 465  # For SSL

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL("", port, context=context) as server:
        server.login(user, password)
        server.send_message(msg)
   
    return

def parse_args():
    parser = argparse.ArgumentParser(description='Send security and privacy issue reports.')
    parser.add_argument('--mapping_path', default="../evaluation/matching.json", type=str, help='Path to the mapping file')
    parser.add_argument('--ios_metadata_path', default="./ios_metadata.json", type=str, help='Path to the iOS metadata file')
    parser.add_argument('--android_metadata_path', default="./android_metadata.json", type=str, help='Path to the Android metadata file')
    parser.add_argument("--report-info", required=True, type=str, help="Path to the report info file")
    parser.add_argument("--user", required=True, type=str, help="Email address of the sender")
    parser.add_argument("--password", required=True, type=str, help="Password of the  sender's email account")
    parser.add_argument("--done-directory" , default="./done", type=str, help="Path to the directory where the report info file is moved to after sending the report")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    mapping_path = args.mapping_path
    ios_metadata_path = args.ios_metadata_path
    android_metadata_path = args.android_metadata_path
    # Create the done directory if it doesn't exist
    if os.path.exists(args.done_directory) is False:
        os.mkdir(args.done_directory)

    messager = Messager(mapping_path, ios_metadata_path, android_metadata_path)
    report_info = read_json(args.report_info)
    platform_path = report_info["platform"].replace(" ", "_")
    # Check if the report has already been sent -> avoid sending it twice
    if os.path.exists(os.path.join(args.done_directory,report_info["id"] + "_Android_and_iOS"  )) or os.path.exists(os.path.join(args.done_directory,report_info["id"] + "_Android")) or os.path.exists(os.path.join(args.done_directory,report_info["id"] + "_iOS")) :
        print("Report already sent")
        exit()

    print(report_info)
    msg = messager.create_message(report_info["id"], report_info["platform"], report_info["findings"])
    print(msg)
    send_mail(args.user, args.password, msg)
    # Save the sent report to the done directory
    with open(os.path.join(args.done_directory,report_info["id"] + "_" + platform_path ), "w") as f:
        f.write(str(msg))
