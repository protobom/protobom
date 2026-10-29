#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

set -o xtrace

source hack/common.sh

make licenselist
git diff --exit-code -- pkg/licenselist || exit_with_msg "The SPDX License List data is not up to date with its pinned version. Please run 'make licenselist' and commit the result"
