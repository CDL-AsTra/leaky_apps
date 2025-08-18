# App Dataset & Results

* [IDs of analyzed apps](./apps/)
* [Metadata information](./metadata/)

To also access the app bundles and our results, please provide us with a public SSH key. Once your key has been added, you can transfer files using `rsync`.

## Listing Available Files
Use the following command to list the available files:

```bash
rsync --list-only -e "ssh -i {key_path}" dataset@app-secrets.sec.univie.ac.at:/
```


## Downloading Files
To download specific files, run:

```bash
rsync -az -e "ssh -i {key_path}" dataset@app-secrets.sec.univie.ac.at:{file_path} {destination_path}
```