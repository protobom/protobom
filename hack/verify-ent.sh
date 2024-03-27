#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" &> /dev/null && pwd)"
ENT_ROOT_DIR="$(dirname "${SCRIPT_DIR}")/ent"

readonly ENT_ROOT_DIR SCRIPT_DIR
readonly PROTOC_VER="24.4"
readonly PROTOC_URL="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VER}/protoc-${PROTOC_VER}-linux-x86_64.zip"

# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

# Download `protoc`
curl --fail --silent --show-error --location --remote-name --url ${PROTOC_URL}
unzip "$(basename ${PROTOC_URL})" -d "${HOME}/.local"

# Add `$HOME/.local/bin` to PATH if not already present
[[ "$PATH" != *"$HOME/.local/bin"* ]] && export PATH="$HOME/.local/bin:$PATH"

# Install GNU make if not installed
if ! command -v make &> /dev/null; then
  (apt-get update && apt-get install --yes make) &> /dev/null
fi

# Generate ent schemas and code
make generate-ent

git diff --exit-code -- "${ENT_ROOT_DIR}"/**/*.go || {
  exit_with_msg \
    "The ent schemas and database types are not up to date." \
    "Check the docs and run 'make generate-ent'"
}
