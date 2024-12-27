#!/bin/bash

DEFAULT_OUTPUT_FILE=""
OUTPUT_FILE=${1:-$DEFAULT_OUTPUT_FILE}


DEFAULT_SCAN_FILE=""
SCAN_FILE=${2:-$DEFAULT_SCAN_FILE}

# Execute trivy sbom script
./scripts/scanner/trivy.sh $OUTPUT_FILE $SCAN_FILE
if [ $? -ne 0 ]; then
  echo "trivy.sh failed!"
  exit 1
fi

# Execute osv script
./scripts/scanner/osv.sh $OUTPUT_FILE $SCAN_FILE
if [ $? -ne 0 ]; then
  echo "osv.sh failed!"
  exit 1
fi

# Execute snyk sbom script
./scripts/scanner/snyk.sh $OUTPUT_FILE $SCAN_FILE
if [ $? -ne 0 ]; then
  echo "snyk.sh failed!"
  exit 1
fi



echo "all scripts were executed successfully!"
