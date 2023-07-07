# Testing SBOMs Collector

This script aims to fetch metadata files from high-quality GitHub repositories written in various programming languages and generate SBOMs (Software Bill of Materials) in three different formats: spdx-json, spdx, and cyclonedx.

## Workflow

The script follows the following workflow:

1. Downloads the `README.md` file from the appropriate `awesome-XXX` repository for a specific programming language. These repositories are curated collections of high-quality repositories contributed by other users.

2. Extracts the URLs of high-quality repositories from the `awesome-XXX` repository.

3. Searches the corresponding repositories and verifies if they contain the desired metadata files. If the files are found, they are downloaded to the designated folder in the `./metadata/` directory.

4. Utilizes trivy to generate three types of SBOMs (spdx-json, spdx, and cyclonedx) using the downloaded metadata files. The resulting SBOMs are saved in the `./SBOM/` directory.

**Note:** Before executing the script, make sure to replace the `ACCESS_TOKEN` with your own GitHub access token.

## Getting Started

To get started with this script, follow the instructions below:

1. Replace the `ACCESS_TOKEN` in the script with your GitHub access token. Make sure to grant the necessary permissions for accessing repositories and metadata.

2. Run the script using the following command:

```bash
python download_metadata.py
```

3. Sit back and relax while the script downloads the metadata files and generates the SBOMs.

## File Structure

The repository has the following structure:

```
├── download_metadata.py     # Main script file
├── metadata.zip             # ZIP file containing partial results of the ./metadata folder
├── SBOM.zip                 # ZIP file containing partial results of the ./SBOM folder
└── README.md                # Project README file
```

## Contributing

Contributions are welcome! If you have any suggestions, improvements, or bug fixes, please open an issue or submit a pull request.