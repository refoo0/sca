#!/bin/bash

DEFAULT_SCAN_FILE=""
SCAN_FILE=${1:-$DEFAULT_SCAN_FILE}

# Execute trivy sbom script
./scripts/scanner/trivy.sh "" $SCAN_FILE
if [ $? -ne 0 ]; then
  echo "trivy.sh failed!"
  exit 1
fi

# Execute snyk sbom script
./scripts/scanner/snyk.sh "" $SCAN_FILE
if [ $? -ne 0 ]; then
  echo "snyk.sh failed!"
  exit 1
fi

# Execute osv script
./scripts/scanner/osv.sh "" $SCAN_FILE
if [ $? -ne 0 ]; then
  echo "osv.sh failed!"
  exit 1
fi



echo "all scripts were executed successfully!"
