#!/bin/bash

# Function to check for command existence
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Create the tools directory if it doesn't exist
mkdir -p tools

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Install Wappalyzer
echo "Installing Wappalyzer..."
if command_exists go; then
    export GOPATH=$HOME/go
    go install -v github.com/webklex/wappalyzer@main
else
    echo "Go is not installed. Please install Go and re-run this script."
    exit 1
fi

# Clone testssl.sh
echo "Cloning testssl.sh..."
if [ ! -d "tools/testssl.sh" ]; then
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git tools/testssl.sh
else
    echo "testssl.sh already cloned."
fi

# Install nmap-formatter
echo "Installing nmap-formatter..."
if command_exists go; then
    go install github.com/vdjagilev/nmap-formatter/v2@latest
else
    echo "Go is not installed. Please install Go and re-run this script."
    exit 1
fi

echo "Setup completed successfully."
