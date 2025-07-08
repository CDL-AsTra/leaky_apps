import os
import shutil
import zipfile
import argparse
import tempfile

def export_files_from_zip(zip_file, file_with_paths, output_folder):
    """
    Extracts files listed in the input file from a ZIP file and copies them to the output folder.

    Args:
        zip_file (str): Path to the ZIP file containing the application files.
        file_with_paths (str): Path to the file containing relative file paths (one per line).
        output_folder (str): Path to the output folder where files will be copied.
    """
    # Create a temporary directory to extract the ZIP file
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            # Extract ZIP file
            with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            print(f"Extracted ZIP file to: {temp_dir}")

            # Ensure output folder exists
            os.makedirs(output_folder, exist_ok=True)

            # Read the file containing relative paths
            with open(file_with_paths, 'r') as file:
                file_paths = file.readlines()

            for relative_path in file_paths:
                relative_path = relative_path.strip()  # Remove whitespace and newlines
                if not relative_path:
                    continue  # Skip empty lines

                # Construct the absolute source path and target path
                source_path = os.path.join(temp_dir, relative_path)
                target_path = os.path.join(output_folder, relative_path)

                # Check if the source file exists
                if not os.path.isfile(source_path):
                    print(f"Warning: File not found - {relative_path}")
                    continue

                # Ensure target directories exist
                os.makedirs(os.path.dirname(target_path), exist_ok=True)

                # Copy the file to the target path
                shutil.copy2(source_path, target_path)
                print(f"Copied: {relative_path} -> {target_path}")

            print("\nExport completed successfully.")

        except Exception as e:
            print(f"An error occurred: {e}")


if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Export selected files from a ZIP file to an output folder.")
    parser.add_argument("zip_file", help="Path to the ZIP file containing the application files.")
    parser.add_argument("file_with_paths", help="Path to the file containing relative file paths.")
    parser.add_argument("output_folder", help="Path to the output folder where files will be copied.")

    # Parse arguments
    args = parser.parse_args()

    # Run the export function
    export_files_from_zip(args.zip_file, args.file_with_paths, args.output_folder)
