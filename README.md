# Leaky Apps: Large-scale Analysis of Secrets Distributed in Android and iOS Apps

![Figure1](misc/pipeline.svg)

We analyzed what secrets are distributed in mobile apps by
* studying what files Android and iOS apps contain;
* investigating what secrets developers include in the distributed files;
* evaluting differences between Android and iOS;
* studied changes between the app versions of 2023 and 2024.



## Folder Structure
* [Analysis](./analysis/)
* [Evaluation Scripts](./evaluation/)
* [Dataset Information](./dataset/)
* [Full Tables from the Paper](./tables/)

The `analysis/` directory contains our code for analyzing apps, the modified Trufflehog version, and the verification scripts.  
The results include:  
- a database with all discovered files and secrets, and  
- a `verified_secrets/` folder.  

These outputs can be further explored using the notebooks provided in the `evaluation/` directory.


## How to cite:

```
@inproceedings{2025:leaky_apps,
    title     = {{Leaky Apps: Large-scale Analysis of Secrets Distributed in Android and iOS Apps}},
    author    = {Schmidt, David and Schrittwieser, Sebastian and Weippl, Edgar},
    booktitle = {Proceedings of the 32nd ACM SIGSAC Conference on Computer and Communications Security (CCS)},
    year      = {2025},
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