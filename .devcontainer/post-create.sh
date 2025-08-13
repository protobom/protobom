#!/usr/bin/env bash

PYTHON_UTILS=("yamllint" "pre-commit")
GITHUB_UTILS=("")
GOLANG_UTILS=("github.com/google/yamlfmt/cmd/yamlfmt@latest" "google.golang.org/protobuf/cmd/protoc-gen-go@latest")
APT_UTILS=("shellcheck" "vim")

set -e

# Install Python tools
if [[ $(python --version) != "" ]]; then
    echo ====================================================
    echo Installing Python tools...
    export PYTHONUSERBASE=/tmp/pip-tmp
    export PIP_CACHE_DIR=/tmp/pip-tmp/cache
    PIPX_DIR=""
    if ! type pipx >/dev/null 2>&1; then
        pip3 install --disable-pip-version-check --no-cache-dir --user pipx 2>&1
        /tmp/pip-tmp/bin/pipx install --pip-args=--no-cache-dir pipx
        PIPX_DIR="/tmp/pip-tmp/bin/"
    fi
    for util in "${PYTHON_UTILS[@]}"; do
        if ! type "${util}" >/dev/null 2>&1; then
            "${PIPX_DIR}pipx" install --system-site-packages --pip-args '--no-cache-dir --force-reinstall' "${util}"
        else
            echo "${util} already installed. Skipping."
        fi
    done
    rm -rf /tmp/pip-tmp
fi

# Install tools
echo ====================================================
echo "Installing tools from Github..."
for util in "${GITHUB_UTILS[@]}"; do
    if ! type "${util}" >/dev/null 2>&1; then
        curl -s "https://raw.githubusercontent.com/${util}" | bash
        echo ""
    else
        echo "${util} already installed. Skipping."
    fi
done

# Install Golang tools
echo ====================================================
echo Installing Golang tools...
for util in "${GOLANG_UTILS[@]}"; do
    if ! type "${util}" >/dev/null 2>&1; then
        go install "${util}"
    else
        echo "${util} already installed. Skipping."
    fi
done

# Install APT tools
echo ====================================================
echo Installing apt tools...
sudo apt-get update
for util in "${APT_UTILS[@]}"; do
    if ! type "${util}" >/dev/null 2>&1; then
        sudo apt install -y "${util}"
    else
        echo "${util} already installed. Skipping."
    fi
done

# Install Protoctol Buffers
sudo bash .devcontainer/protoc-install.sh

echo >>/home/vscode/.zshrc

# Update .zshrc
echo ====================================================
echo Updating .zshrc ...
{
    printf "export PATH=\$PATH:/usr/local/bin\n"
    printf "setopt appendhistory \nsetopt sharehistory \nsetopt incappendhistory \n"
    printf "export GPG_TTY=%s\n" "$(tty)"
} >>/home/vscode/.zshrc

# Other
echo ====================================================
echo Finallizing ...
pre-commit install
pre-commit run --all-files

# Done
echo ====================================================
