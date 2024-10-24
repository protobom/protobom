#!/usr/bin/env bash

set -euxo pipefail

source hack/common.sh

# These are pinned to the versions used in the latest generated code
export PROTOC_GO_VER="v1.34.2"
export BUF_VERSION="v1.45.0"

# Install protoc-gen-go plugin
GOBIN="${PWD}/.bin" go install google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GO_VER}

# Install Buf CLI
mkdir -p .bin
curl --fail --silent --show-error --location \
  --url "https://github.com/bufbuild/buf/releases/download/${BUF_VERSION}/buf-$(uname -s)-$(uname -m)" \
  --output .bin/buf && chmod +x "$_"

# Install jq to parse JSON response
if ! command -v jq &> /dev/null; then
  (apt-get update && apt-get install --yes jq) &> /dev/null
fi

# Get latest tag from GitHub releases API
releases_api=https://api.github.com/repos/protobom/protobom/releases/latest
tag_name="$(curl --fail --silent --show-error --location --url "$releases_api" | jq --raw-output '.tag_name')"

export PATH=${PWD}/.bin:${PATH}

VERSION=$tag_name make buf-format buf-lint proto

git diff --exit-code -- **/{*.pb,value_scanner}.go **/*.proto ||
  exit_with_msg "The protobuf definitions are not up to date. Check the docs and run make proto"
