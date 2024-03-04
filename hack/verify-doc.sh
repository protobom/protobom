#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

source hack/common.sh

export PROTOC_VER="24.4"
export PROTOC_GEN_DOC_VER="v1.5.1"

if [ ! -f "protoc-${PROTOC_VER}-linux-x86_64.zip" ]; then
    curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VER}/protoc-${PROTOC_VER}-linux-x86_64.zip
    unzip protoc-${PROTOC_VER}-linux-x86_64.zip -u -d $HOME/.local
fi 
go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@${PROTOC_GEN_DOC_VER}

pushd api
protoc --doc_out=../docs --doc_opt=markdown,protobom-ref.md sbom.proto 
popd

git diff --exit-code || exit_with_msg "The proto documentation are not up to date"
