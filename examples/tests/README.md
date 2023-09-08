# Real-world SBOMs Generator

The Real-world SBOMs Generator is a tool designed to automatically collect top-quality GitHub repositories written in various programming languages and generate Software Bill of Materials (SBOMs) in three different formats: spdx-json, spdx, and cyclonedx. These SBOMS can be used to test the correctness of our protobom translator.

## How it Works

The SBOM Generator follows this workflow to ensure accurate and comprehensive SBOM generation:

1. **Data Collection**: The script starts by automatically downloading the `README.md` file from a curated and suitable `awesome-XXX` repository that corresponds to a specific programming language. These `awesome-XXX` repositories are maintained by the community and serve as collections of high-quality repositories.

2. **Repository Download**: The script extracts the URLs of high-quality repositories from the `awesome-XXX` repository and proceeds to download these repositories into a temporary folder.

3. **SBOM Generation**: The powerful `syft` tool is then employed to generate three types of SBOMs (spdx-json, spdx, and cyclonedx) based on the downloaded repositories. Once the SBOMs are generated, they are automatically saved in the `./SBOM/` directory.

## Getting Started

### Option 1: Quick Start (Using Pre-generated SBOMs)

If you require the SBOM files but wish to skip the entire generation process, you have the option to download the pre-generated SBOMs directly from the following link: [Pre-generated SBOMs](https://drive.google.com/file/d/1LgGlq3g_H02mhzkc94cUd0zzxy0JhFim/view?usp=sharing). These files come in three formats: spdx-json, spdx, and cyclonedx, ready to use.

### Option 2: Run the Script

If you prefer to generate the SBOMs from scratch, follow these simple instructions:

1. **Install syft**: Ensure that the `syft` tool is installed. For more information and installation instructions, refer to [syft's GitHub repository](https://github.com/anchore/syft).

2. **Install Dependencies**: Install the required Python packages using the following command:

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Script**: Execute the script using the following command:

   ```bash
   python crawl_and_generate_SBOM.py
   ```

4. **Sit Back and Relax**: The script will automatically download the metadata files and proceed to generate the SBOMs. The process may take some time, depending on the number and size of the repositories.

## File Structure

The repository is organized as follows:

```
- crawl_and_generate_SBOM.py    # Main script file responsible for SBOM generation
- requirements.txt              # Required Python packages for the script
- README.md                     # Project README file (you are here)
```

## Contributing

Contributions are highly appreciated and welcome! If you have any suggestions, improvements, or bug fixes, please feel free to open an issue or submit a pull request. Together, we can make the SBOM Generator even more powerful and useful for the community!
