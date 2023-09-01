#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

make fakes
git diff --exit-code || echo "Fakes are not up to date. Please run 'make fakes' and commit the reusult"

