#!/bin/bash

set -eu

SCRIPT_NAME="$(basename "$0")"

echo "${SCRIPT_NAME} is running... "

PROTOC_VERSION=24.2
PROTOC_OS=""
PROTOC_ARCH=""
PROTOC_ZIP=""

buildProtocZIPName() {
  PROTOC_ZIP=protoc-${PROTOC_VERSION}-${PROTOC_OS}-${PROTOC_ARCH}.zip
}

getOSName(){
KERNEL_TYPE=$(uname -s | tr '[:upper:]' '[:lower:]')

  case "${KERNEL_TYPE}" in
      linux)
        PROTOC_OS="linux"
        ;;
      darwin)
        PROTOC_OS="osx"
        ;;
      freebsd)
        PROTOC_OS="freebsd"
        ;;
      msys* | cygwin*)
        PROTOC_OS="win"
        echo "Your Operating System ${KERNEL_TYPE}-> ITS NOT SUPPORTED"
        exit 1
        ;;
      * )
        echo "Your Operating System ${KERNEL_TYPE} -> ITS NOT SUPPORTED"
        exit 1
      ;;
  esac
}

getArch(){
  ARCH=$(uname -m)

  # supported archs
  #  - amd64
  #  - arm64
  #  - 386
  #  - armv7

  case "${ARCH}" in
      x86)
        PROTOC_ARCH="x86_32"
        ;;
      i?86)
        PROTOC_ARCH="x86_32"
        ;;
      amd64)
        PROTOC_ARCH="x86_64"
        ;;
      arm64)
        PROTOC_ARCH="arm64"
        ;;
      x86_64)
        PROTOC_ARCH="x86_64"
        ;;
      aarch64)
        PROTOC_ARCH="aarch_64"
        ;;
      * )
        echo "Your Architecture ${ACRH} -> ITS NOT SUPPORTED."
        ;;
  esac
}

cleanup() {
  trap - EXIT
  rm -rf ./protoc-*
}

downloadProtoc() {
  URL="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/${PROTOC_ZIP}"

  echo "Gonna to download ${PROTOC_ZIP} at ${URL}"

  wget --no-check-certificate -O "${PROTOC_ZIP}" "${URL}"  &&
    unzip -o "${PROTOC_ZIP}" -d /usr/local bin/protoc &&
    unzip -o "${PROTOC_ZIP}" -d /usr/local 'include/*' &&
    chmod +x /usr/local/bin/protoc
}

osxInstall() {
  PROTOC_ARCH="x86_64"
}

linuxInstall() {
  DISTRO_ID=$(grep '^ID=' /etc/os-release | sed "s/ID=//")
}

install() {
  getOSName
  getArch

  case "${PROTOC_OS}" in
  osx*)
    osxInstall
    ;;
  linux*)
    linuxInstall
    ;;
  win*)
    ## TODO(o.balunenko): add windows installation.
    exit 1
    ;;
  *)
    echo "unsupported os: ${PROTOC_OS}"
    exit 1
    ;;
  esac

  buildProtocZIPName

  downloadProtoc

  cleanup


  echo "Protoc version: $(protoc --version)"
}

install

echo "${SCRIPT_NAME} done."
