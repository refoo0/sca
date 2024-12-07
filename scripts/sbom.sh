#!/bin/bash

TIMESTAMP=$(date +"%Y%m%d%H%M%S")
SCAN_FILE="app/myapp"

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
