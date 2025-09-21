# Leaky Apps: Large-scale Analysis of Secrets Distributed in Android and iOS Apps

![Figure1](misc/pipeline.svg)

We analyzed what secrets are distributed in mobile apps by
* studying what files Android and iOS apps contain;
* investigating what secrets developers include in the distributed files;
* evaluting differences between Android and iOS;
* studied changes between the app versions of 2023 and 2024.



## Folder Structure
* [Analysis to extract file metadata and secrets from the app bundle](./analysis/)
* [Evaluation scripts to produce tables and figure](./evaluation/)
* [Dataset information (app ids and metadata)](./dataset/)
* [Full tables from the paper](./tables/)

The `analysis/` directory contains our code for analyzing apps, the modified Trufflehog version, and the verification scripts. We executed the analysis on a Debian 12 VM with `Python 3.11.2`, 32 cores and 64 GB RAM. We recommend [parallel command line tool](https://www.gnu.org/software/parallel/) to analyze multiple apps.

The results include:  
- a sqlite database with all discovered files and secrets, and  
- a `verified_secrets/` folder.  

These outputs can be further explored using the jupyter notebooks provided in the `evaluation/` directory.



## How to cite:

```
@inproceedings{2025:leaky_apps,
    title     = {{Leaky Apps: Large-scale Analysis of Secrets Distributed in Android and iOS Apps}},
    author    = {Schmidt, David and Schrittwieser, Sebastian and Weippl, Edgar},
    booktitle = {Proceedings of the 32nd ACM SIGSAC Conference on Computer and Communications Security (CCS)},
    year      = {2025},
    doi       = {10.1145/3719027.3765033}
}
```



## Contacts
* David Schmidt:
    * email: d.schmidt@univie.ac.at
    * Bluesky: [@dschm1dt](https://bsky.app/profile/dschm1dt.bsky.social)
* Sebastian Schrittwieser
    * email: sebastian.schrittwieser@univie.ac.at


### Dataset and Analysis Artifacts
We share the app dataset and all artifacts on request. Please get in touch with us and send us your public key.