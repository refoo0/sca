#!/bin/bash

TIMESTAMP=$(date +"%Y%m%d%H%M%S")

DEFAULT_SCAN_FILE=""
SCAN_FILE=${1:-$DEFAULT_SCAN_FILE}

# Execute trivy sbom script
./scripts/sbom/trivy_sbom.sh $TIMESTAMP "" $SCAN_FILE
if [ $? -ne 0 ]; then
  echo "trivy_sbom.sh failed!"
  exit 1
fi

# Execute snyk sbom script
./scripts/sbom/snyk_sbom.sh $TIMESTAMP "" $SCAN_FILE
if [ $? -ne 0 ]; then
  echo "snyk_sbom.sh failed!"
  exit 1
fi



echo "all scripts were executed successfully!"
