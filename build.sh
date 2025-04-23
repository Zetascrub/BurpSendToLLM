#!/usr/bin/env bash
# build.sh: compile and create a fat JAR for the Burp "Send to LLM" extension
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 /path/to/burpsuite.jar /path/to/json.jar"
  exit 1
fi

BURP_JAR="$1"
JSON_JAR="$2"
SRC_FILE="BurpExtender.java"
MANIFEST="manifest.txt"
OUTPUT_JAR="SendToLLM.jar"
BUILD_DIR="build_tmp"

echo "Compiling ${SRC_FILE}..."
javac --release 11 -cp "${BURP_JAR}:${JSON_JAR}" "${SRC_FILE}"

echo "Preparing build directory..."
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

echo "Copying classes to build directory..."
cp *.class "${BUILD_DIR}/"

echo "Unpacking JSON library..."
(cd "${BUILD_DIR}" && jar xf "../${JSON_JAR}")

echo "Building fat JAR ${OUTPUT_JAR}..."
jar cfm "${OUTPUT_JAR}" "${MANIFEST}" -C "${BUILD_DIR}" .

echo "Cleaning up..."
rm -rf "${BUILD_DIR}"
rm -f *.class

echo "Build complete: ${OUTPUT_JAR}"
