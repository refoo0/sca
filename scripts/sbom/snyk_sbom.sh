#!/bin/bash

# Set default values
DEFAULT_OUTPUT_FILE="results/sbom/snyk_sbom.json"
OUTPUT_FILE=${1:-$DEFAULT_OUTPUT_FILE}

DEFAULT_SCAN_FILE="app"
SCAN_FILE=${2:-$DEFAULT_SCAN_FILE}

# Execute the Trivy command
echo "Executing Snyk SBOM scan..."
snyk sbom "$SCAN_FILE" --format cyclonedx1.6+json > "$OUTPUT_FILE" 

# Check if the command was successful
if [ $? -eq 0 ]; then
    echo "Snyk SBOM scan completed successfully. Result saved in $OUTPUT_FILE"
else
    echo "Snyk SBOM scan failed."
    exit 1
fi
