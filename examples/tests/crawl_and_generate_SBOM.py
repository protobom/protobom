import os
import re
import requests
from urllib.parse import urlparse
import json
from git import Repo
import subprocess
import tempfile

SBOM_OUTPUT = "./SBOM/"

awesome_language_readme_urls = {
    "python": 'https://raw.githubusercontent.com/vinta/awesome-python/master/README.md',
    "javascript": 'https://raw.githubusercontent.com/sorrycc/awesome-javascript/master/README.md',
    "go": 'https://raw.githubusercontent.com/avelino/awesome-go/main/README.md',
    "java": 'https://raw.githubusercontent.com/akullpp/awesome-java/master/README.md',
    "ruby": 'https://raw.githubusercontent.com/markets/awesome-ruby/master/README.md',
    "rust": 'https://raw.githubusercontent.com/rust-unofficial/awesome-rust/main/README.md',
    "php": 'https://raw.githubusercontent.com/ziadoz/awesome-php/master/README.md',
    "dotnet": 'https://raw.githubusercontent.com/quozd/awesome-dotnet/master/README.md',
    "swift": 'https://raw.githubusercontent.com/matteocrippa/awesome-swift/master/README.md',
}

def find_github_urls(url):
    response = requests.get(url)
    urls = []
    if response.status_code == 200:
        content = response.text
        print(f"Downloaded content from {url}")
        urls = re.findall(r'(https?://github\.com/[^\s/()]+/[\w.-]+)', content)
        urls = list(set(urls))
    return urls

def get_owner_and_repo(url):
    parsed_url = urlparse(url)
    path_parts = parsed_url.path.strip('/').split('/')
    
    if len(path_parts) >= 2:
        owner, repo = path_parts[:2]
        return owner, repo
    
    return None, None

def validate_cyclonedx_sbom(data):
    try:
        sbom = json.loads(data)
        if 'components' in sbom:
            for component in sbom['components']:
                if component['type'] == 'library':
                    return True
    except Exception:
        pass
    return False

def main():
    for language, readme_url in awesome_language_readme_urls.items():
        urls = find_github_urls(readme_url)
        print(len(urls))
        for url in urls:
            try:
                print(f"[{language}] Downloading {url}")
                owner, repo = get_owner_and_repo(url)

                with tempfile.TemporaryDirectory() as tmp_folder:
                    download_folder = os.path.join(tmp_folder, f"{language}/{owner}/{repo}")
                    os.makedirs(download_folder, exist_ok=True)
                    os.makedirs(SBOM_OUTPUT, exist_ok=True)
                    Repo.clone_from(url, download_folder)

                    cyclonedx_json = subprocess.check_output(f'syft packages dir:{download_folder} -o cyclonedx-json', shell=True, text=True)
                    if validate_cyclonedx_sbom(cyclonedx_json):
                        cyclonedx_json_path = f'{SBOM_OUTPUT}/{owner}_{repo}_syft_cyclonedx.json'
                        with open(cyclonedx_json_path, 'w') as file:
                            file.write(cyclonedx_json)

                        spdx_json_path = f'{SBOM_OUTPUT}/{owner}_{repo}_syft_spdx.json'
                        os.system(f'syft packages dir:{download_folder} -o spdx-json > {spdx_json_path}')
                        spdx_path = f'{SBOM_OUTPUT}/{owner}_{repo}_syft_spdx.txt'
                        os.system(f'syft packages dir:{download_folder} -o spdx > {spdx_path}')
            except Exception as e:
                print(e)

if __name__ == "__main__":
    main()