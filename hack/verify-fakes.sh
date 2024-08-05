#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

set -o xtrace

source hack/common.sh

make fakes
git diff --exit-code || exit_with_msg "Fakes are not up to date. Please run 'make fakes' and commit the result"
