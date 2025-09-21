# Analysis

- [Analysis script (requires `trufflehog`, `exiftool`, and `jadx`)](./analysis.py)  
- [Modified version of Trufflehog with separate verification functionality](./trufflehog/)  
- [Code for verifying discovered credentials](./verify/)  

---

## Docker Setup

To simplify the environment setup, we provide a Docker compose configuration.  

1. Place the files you want to analyze into the `docker/apps/` directory, hit `docker compose up`.  
2. The analysis will produce an sqlite database in the `docker/results/` directory. https://sqlitebrowser.org/ can be used to view the database.
3. Afterward, the verification step will run automatically, creating the directory: `docker/results/verified_secrets/`  



## Without Docker

To run the analysis without Docker:

1. Install the required Python dependencies (requirements.txt).  
2. Install the following external programs: 
   - [`exiftool`](https://exiftool.org/)  
   - [`jadx`](https://github.com/skylot/jadx)  
   - [`trufflehog`](./trufflehog/)  
   - For installation instructions take a look at the [`Dockerfile`](./Dockerfile)
3. Run the main analysis script - `analysis.py`, e.g., `python3 analysis.py --appPath /apps/{app_file} --deleteAfter --database-file /results/database.db --unzipDir /tmp/`


The `analysis.py` is responible for creating a sqlite database, containing the metadata of each file in the app bundle, and secret candidates discovered with trufflehog.

### Verifying Detected Secrets

1. Run the preprocessing step to generate the directory structure and filter detected secrets: `verify/preprocess.py`. To execute it run: `python3 verify/preprocess.py --database {database/path} --output_folder {output/path}`
2. Run the verification step using our modified version of Trufflehog (make sure to adjust file paths if needed) `verify/verify_with_trufflehog.py`