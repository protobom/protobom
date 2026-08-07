#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
# SPDX-License-Identifier: Apache-2.0
#
# Checks the SPDX documents protobom writes against the SPDX project's own
# tooling: the Verify command of the SPDX Java tools for both SPDX 2.3 and
# SPDX 3.0.1, and the official 3.0.1 JSON schema for SPDX 3.
#
# Every SBOM under examples/ is read and written back out in both versions,
# and each result is put through the checks. Protobom's own tests can say the
# output is what protobom meant to write; only the SPDX tools can say it is
# a document the rest of the world will accept.
#
#   ./hack/verify-spdx.sh [--keep DIR]
#
# Requires java and check-jsonschema on PATH. The tools jar and the schema are
# downloaded into a cache directory unless SPDX_TOOLS_JAR and SPDX_JSON_SCHEMA
# name local copies.

set -euo pipefail

readonly tools_version="2.0.7"
readonly tools_url="https://github.com/spdx/tools-java/releases/download/v${tools_version}/tools-java-${tools_version}.zip"
readonly schema_url="https://spdx.org/schema/3.0.1/spdx-json-schema.json"

# Documents protobom cannot yet write validly, with the reason. An entry here
# is a bug that is known and not yet fixed, not a document that is allowed to
# be wrong: removing the entry is part of fixing it.
#
#   juice-shop/2.3: the CycloneDX reader keeps identifiers that are not valid
#   SPDX 2 element URIs, so Verify rejects the document with
#   "Element object URI does not follow the SPDX V2.X required pattern".
readonly known_bad=(
	"juice-shop-11.1.2.cdx.json:2.3"
)

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache="${SPDX_VERIFY_CACHE:-${TMPDIR:-/tmp}/protobom-spdx-verify}"
keep=""

while [[ $# -gt 0 ]]; do
	case "$1" in
	--keep)
		keep="$2"
		shift 2
		;;
	-h | --help)
		sed -n '3,19p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
		exit 0
		;;
	*)
		echo "unknown argument: $1" >&2
		exit 2
		;;
	esac
done

for tool in java check-jsonschema; do
	if ! command -v "${tool}" >/dev/null; then
		echo "${tool} is required but not on PATH" >&2
		exit 1
	fi
done

mkdir -p "${cache}"

schema="${SPDX_JSON_SCHEMA:-${cache}/spdx-json-schema-3.0.1.json}"
if [[ ! -f "${schema}" ]]; then
	echo "Downloading the SPDX 3.0.1 JSON schema..."
	curl -sSL -o "${schema}" "${schema_url}"
fi

jar="${SPDX_TOOLS_JAR:-${cache}/tools-java-${tools_version}-jar-with-dependencies.jar}"
if [[ ! -f "${jar}" ]]; then
	echo "Downloading the SPDX Java tools ${tools_version}..."
	curl -sSL -o "${cache}/tools-java.zip" "${tools_url}"
	unzip -oq "${cache}/tools-java.zip" -d "${cache}"
fi

if [[ -n "${keep}" ]]; then
	out="${keep}"
	mkdir -p "${out}"
else
	out="$(mktemp -d)"
	trap 'rm -rf "${out}"' EXIT
fi

# convert reads an SBOM and writes it in the named SPDX version.
convert() {
	local source="$1" version="$2" target="$3"
	(cd "${root}" && go run ./hack/spdxconvert -format "${version}" -out "${target}" "${source}")
}

is_known_bad() {
	local entry="$1"
	for bad in "${known_bad[@]}"; do
		[[ "${entry}" == "${bad}" ]] && return 0
	done
	return 1
}

# verify_ok and schema_ok answer whether a document passes. Neither pipes the
# checker's output anywhere: a reader closing the pipe early would send it
# SIGPIPE, which under pipefail reads as the document having failed.
verify_output() {
	java -jar "${jar}" Verify "$1" 2>&1 || true
}

verify_ok() {
	local result
	result="$(verify_output "$1")"
	[[ "${result}" == *"This SPDX Document is valid."* ]]
}

schema_ok() {
	check-jsonschema --schemafile "${schema}" "$1" >/dev/null 2>&1
}

report() {
	local text="$1" lines=()
	mapfile -t lines <<<"${text}"
	printf '    %s\n' "${lines[@]:0:15}"
}

declare -i checked=0 failed=0 skipped=0
printf '\n%-34s %-8s %-8s %-8s %s\n' "DOCUMENT" "VERSION" "VERIFY" "SCHEMA" "CODES"

while read -r source; do
	for version in 2.3 3.0.1; do
		name="$(basename "${source}")"
		target="${out}/${name%.json}-spdx${version}.json"
		checked+=1

		if ! convert "${source}" "${version}" "${target}" >/dev/null 2>&1; then
			printf '%-34s %-8s %s\n' "${name:0:33}" "${version}" "WRITE FAILED"
			failed+=1
			continue
		fi

		# How many packages carry a verification code, which is computed on
		# write and so is worth watching. SPDX 2 names the value, SPDX 3 types
		# the element.
		if [[ "${version}" == "2.3" ]]; then
			codes="$(grep -co "packageVerificationCodeValue" "${target}" || true)"
		else
			codes="$(grep -co '"PackageVerificationCode"' "${target}" || true)"
		fi

		verify_result="ok"
		verify_ok "${target}" || verify_result="FAILED"
		schema_result="-"
		if [[ "${version}" == "3.0.1" ]]; then
			schema_result="ok"
			schema_ok "${target}" || schema_result="FAILED"
		fi

		if [[ "${verify_result}" == "FAILED" || "${schema_result}" == "FAILED" ]]; then
			if is_known_bad "${name}:${version}"; then
				printf '%-34s %-8s %-8s %-8s %s\n' "${name:0:33}" "${version}" "${verify_result}" "${schema_result}" "(known)"
				skipped+=1
				continue
			fi
			failed+=1
			printf '%-34s %-8s %-8s %-8s %s\n' "${name:0:33}" "${version}" "${verify_result}" "${schema_result}" "${codes}"
			[[ "${verify_result}" == "FAILED" ]] && report "$(verify_output "${target}")"
			[[ "${schema_result}" == "FAILED" ]] &&
				report "$(check-jsonschema --schemafile "${schema}" "${target}" 2>&1 || true)"
			continue
		fi

		printf '%-34s %-8s %-8s %-8s %s\n' "${name:0:33}" "${version}" "${verify_result}" "${schema_result}" "${codes}"
	done
done < <(find "${root}/examples" -maxdepth 1 -name '*.json' | sort)

echo
if [[ ${failed} -gt 0 ]]; then
	echo "${checked} documents written, ${failed} the SPDX tools reject."
	exit 1
fi
echo "${checked} documents written, all accepted by the SPDX tools."
if [[ ${skipped} -gt 0 ]]; then
	echo "${skipped} known to be broken and not counted; see known_bad in this script."
fi
