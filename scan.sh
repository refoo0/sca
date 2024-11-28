#!/bin/bash

# Execute trivy sbom script
./scripts/trivy.sh
if [ $? -ne 0 ]; then
  echo "trivy_sbom.sh failed!"
  exit 1
fi

# Execute snyk sbom script
./scripts/snyk.sh
if [ $? -ne 0 ]; then
  echo "snyk_sbom.sh failed!"
  exit 1
fi

# Execute osv script
./scripts/osv.sh
if [ $? -ne 0 ]; then
  echo "osv.sh failed!"
  exit 1
fi



echo "all scripts were executed successfully!"
