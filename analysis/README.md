# Analysis

- `trufflehog/` contains our modifications to Trufflehog with separate verification functionality.
- `analysis.py` executes our analysis. Requires `trufflehog`, `exiftool`, and `jadx-gui`, expect the binaries in a path directory. 
- `verify/` provides code to verify the results.