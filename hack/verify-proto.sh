#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

source hack/common.sh

# These two are pinned to the versions used in the latest generated code
export PROTOC_VER="24.4"
export PROTOC_GO_VER="v1.31.0"

# References main branch as of 11/22/2023 (last tagged release v1.1.2 was August 2022)
export PROTOC_GORM_VER="d3024d4fa7c9ce9d62e2f2cc0b42faf679211846"

curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VER}/protoc-${PROTOC_VER}-linux-x86_64.zip
unzip protoc-${PROTOC_VER}-linux-x86_64.zip -d $HOME/.local
go install google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GO_VER}
go install github.com/infobloxopen/protoc-gen-gorm@${PROTOC_GORM_VER}
curl -LO https://raw.githubusercontent.com/infobloxopen/protoc-gen-gorm/${PROTOC_GORM_VER}/proto/options/gorm.proto

$HOME/.local/bin/protoc --proto_path=$HOME/.local/include --proto_path=. --go_out=pkg --gorm_out=pkg --gorm_opt=Mapi/sbom.proto=sbom/beta api/sbom.proto

mkdir -p beta
cp api/sbom.proto beta
sed -i -E 's/^(package bomsquad\.protobom)/\1\.beta/' beta/sbom.proto

$HOME/.local/bin/protoc --proto_path=$HOME/.local/include --proto_path=. \
	--go_out=pkg --go_opt=M'beta/sbom.proto=sbom/beta;beta' \
	--gorm_out=pkg --gorm_opt=M'beta/sbom.proto=sbom/beta;beta' \
	beta/sbom.proto

rm -r beta

git diff --exit-code -- **/*.pb{,.gorm}.go || exit_with_msg "The protobuf definitions are not up to date. Check the docs and run make proto"
