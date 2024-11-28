#!/bin/bash

# Set default values
DEFAULT_OUTPUT_FILE="results/trivy.json"
OUTPUT_FILE=${1:-$DEFAULT_OUTPUT_FILE}

DEFAULT_SCAN_FILE="app"
SCAN_FILE=${2:-$DEFAULT_SCAN_FILE}

# Execute the Trivy command
echo "Executing Trivy scan..."
trivy fs --scanners vuln --format json --output "$OUTPUT_FILE"  "$SCAN_FILE"

# Check if the command was successful
if [ $? -eq 0 ]; then
    echo "Trivy scan completed successfully. Result saved in $OUTPUT_FILE"
else
    echo "Trivy scan failed."
    exit 1
fi
