#!/usr/bin/env bash

set -euxo pipefail

source hack/common.sh

# These are pinned to the versions used in the latest generated code
export PROTOC_GO_VER="v1.34.2"
export BUF_VERSION="v1.45.0"

# Install protoc-gen-go plugin
go install google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GO_VER}

# Install Buf CLI
mkdir -p .bin
curl --fail --silent --show-error --location \
  --url "https://github.com/bufbuild/buf/releases/download/${BUF_VERSION}/buf-$(uname -s)-$(uname -m)" \
  --output .bin/buf && chmod +x "$_"

export PATH="${PWD}/.bin:${PATH}"

make buf-format
make buf-lint
make buf-generate

git diff --exit-code -- **/{*.pb,value_scanner}.go **/*.proto ||
  exit_with_msg "The protobuf definitions are not up to date. Check the docs and run make proto"
