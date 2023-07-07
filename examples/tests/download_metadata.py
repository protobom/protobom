import os
import re
import time
import requests
from urllib.parse import urlparse
import random
import re
import subprocess

ACCESS_TOKEN = "<YOUR_ACCESS_TOKEN>"
METADATA_OUTPUT = "./metadata/"
SBOM_OUTPUT = "./SBOM/"

awesome_language_readme_urls = {
    "python": 'https://raw.githubusercontent.com/vinta/awesome-python/master/README.md',
    "javascript": 'https://raw.githubusercontent.com/sorrycc/awesome-javascript/master/README.md',
    "go": 'https://raw.githubusercontent.com/avelino/awesome-go/main/README.md',
    "java": 'https://raw.githubusercontent.com/akullpp/awesome-java/master/README.md',
    "ruby": 'https://raw.githubusercontent.com/markets/awesome-ruby/master/README.md',
    "rust": 'https://raw.githubusercontent.com/rust-unofficial/awesome-rust/main/README.md',
    "php": 'https://raw.githubusercontent.com/ziadoz/awesome-php/master/README.md'
}

search_filenames = {
    "python": ["requirements.txt", "poetry.lock", "Pipfile.lock"],
    "javascript": ["yarn.lock", "package-lock.json", "package.json", "pnpm-lock.yaml"],
    "go": ["go.mod", "go.sum"],
    "java": ["pom.xml", "gradle.lockfile"],
    "ruby": ["Gemfile.lock"],
    "rust": ["Cargo.lock"],
    "php": ["composer.lock"]
}

def scan_downloaded_repos():
    skip_repos = set()

    for language in os.listdir(METADATA_OUTPUT):
        language_folder = os.path.join(METADATA_OUTPUT, language)

        if os.path.isdir(language_folder):
            downloaded_files = os.listdir(language_folder)

            for file_name in downloaded_files:
                owner, repo = file_name.split("_")[:2]
                skip_repos.add((owner, repo))

    return skip_repos

def find_github_urls(url):
    skip_repos = scan_downloaded_repos()
    response = requests.get(url)
    download_urls = []

    if response.status_code == 200:
        content = response.text
        print(f"Downloaded content from {url}")

        urls = re.findall(r'(https?://github\.com/[^\s/()]+/[\w.-]+)', content)
        urls = list(set(urls))

        for url in urls:
            parsed_url = urlparse(url)
            path_segments = parsed_url.path.strip("/").split("/")
            owner = path_segments[0]
            repository = path_segments[1]
            if (owner, repository) not in skip_repos:
                download_urls.append(url)

        random.shuffle(download_urls)
    else:
        print(f"Failed to download content from {url}")

    return download_urls

def download_metadata(language):
    # Set input file path and search_filename based on the language
    awesome_language_readme_url = awesome_language_readme_urls[language]
    search_filename = search_filenames[language]

    # Read the input file and find all GitHub URLs
    urls = find_github_urls(awesome_language_readme_url)
     
    # Create output folder if it doesn't exist
    output_folder = f"metadata/{language}"
    os.makedirs(output_folder, exist_ok=True)

    for url in urls:
        print(f"Downloading metadata for [{language}] {url}")
        parsed_url = urlparse(url)
        path_segments = parsed_url.path.strip("/").split("/")
        owner = path_segments[0]
        repository = path_segments[1]

        for filename in search_filename:
            search_url = f"https://api.github.com/search/code?q=filename:{filename}+repo:{owner}/{repository}"

            # Set access token and headers for GitHub API requests
            headers = {"Authorization": f"Token {ACCESS_TOKEN}"}

            response = requests.get(search_url, headers=headers)
            time.sleep(5)

            if response.status_code == 200:
                data = response.json()
                items = data.get("items", [])

                if items:
                    for item in items:
                        download_url = item["html_url"].replace("/blob/", "/raw/")
                        file_name = f"{owner}_{repository}_{filename}"
                        output_path = os.path.join(output_folder, file_name)

                        file_response = requests.get(download_url)
                        time.sleep(5)

                        if file_response.status_code == 200:
                            with open(output_path, "wb") as file:
                                file.write(file_response.content)
                            print(f"Downloaded {file_name} to {output_path}")
                            
                            sbom_output_folder = f"{SBOM_OUTPUT}/{language}"
                            os.makedirs(sbom_output_folder, exist_ok=True)

                            for format in ["spdx-json", "spdx", "cyclonedx"]:
                                sbom_output_path = f"{sbom_output_folder}/{owner}_{repository}_{filename}_{format}.json"
                                command = f"trivy filesystem --format {format} --output {sbom_output_path} {output_path}"
                                subprocess.run(command, shell=True)
                            break
                        else:
                            print(f"Failed to download {file_name}")
                else:
                    print(f"No matching files found for {filename}")
            else:
                print(f"Request failed with status code {response.status_code}")
                time.sleep(15)


def main():
    for language in ["go", "java", "python", "rust", "ruby", "javascript", "php"]:
        try:
            download_metadata(language)
        except Exception as e:
            print(e)

if __name__ == "__main__":
    main()