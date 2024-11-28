#!/bin/bash

# Set default values
DEFAULT_TIMESTAMP=""
TIMESTAMP=${1:-$DEFAULT_TIMESTAMP}

DEFAULT_OUTPUT_FILE="results/sbom/trivy_sbom_${TIMESTAMP}.json"
OUTPUT_FILE=${2:-$DEFAULT_OUTPUT_FILE}

DEFAULT_SCAN_FILE="app"
SCAN_FILE=${3:-$DEFAULT_SCAN_FILE}

# Create output directory if it doesn't exist
OUTPUT_DIR=$(dirname "$OUTPUT_FILE")
mkdir -p "$OUTPUT_DIR" || error_exit "Failed to create directory: $OUTPUT_DIR"


# Execute the Trivy command
echo "Executing Trivy SBOM scan..."
trivy fs --format cyclonedx --output "$OUTPUT_FILE" "$SCAN_FILE"

# Check if the command was successful
if [ $? -eq 0 ]; then
    echo "Trivy SBOM scan completed successfully. Result saved in $OUTPUT_FILE"
else
    echo "Trivy SBOM scan failed."
    exit 1
fi
