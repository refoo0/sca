#!/bin/bash

# Set default values
DEFAULT_OUTPUT_FILE="results/scanner/snyk.json"
OUTPUT_FILE=${1:-$DEFAULT_OUTPUT_FILE}

DEFAULT_SCAN_FILE="app/myapp"
SCAN_FILE=${2:-$DEFAULT_SCAN_FILE}

# Create output directory if it doesn't exist
OUTPUT_DIR=$(dirname "$OUTPUT_FILE")
mkdir -p "$OUTPUT_DIR" || error_exit "Failed to create directory: $OUTPUT_DIR"


# Execute the Trivy command
echo "Executing Snyk scan..."
 snyk test --json --all-projects "$SCAN_FILE" > "$OUTPUT_FILE"  

# Check if the command was successful
if [ $? -eq 0 ] || [ $? -eq 1 ]; then
    echo "Snyk scan completed successfully. Result saved in $OUTPUT_FILE"
else
    echo "Snyk scan failed."
    exit 1
fi
