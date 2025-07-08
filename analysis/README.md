# Analysis

- `trufflehog/` contains our modifications to Trufflehog with separate verification functionality.
- `analysis.py` executes our analysis. Requires `trufflehog`, `exiftool`, and `jadx-gui`, expect the binaries in a path directory. 
- `verify/` provides code to verify the results.



## Docker
To simplify the setup we provided a docker compse file. 
1. To run the analysis, place the files to analyze in the `apps` directory.
2. It places the database into `results`
3. Executes the verification, which creates `results/verified_secrets/`