#!/bin/bash

CUR_DIR=$PWD

echo "Installing Go packages..."
go mod tidy
cd ~/go/pkg/mod/github.com/ingonyama-zk/icicle@v0.0.0-20230727080545-2f21ec4aa7f4/goicicle
chmod +x setup.sh

echo "Compiling Icicle..."
source ./setup.sh libbn254.so
cd $CUR_DIR

echo "Icicle setup completed successfully"
echo "Run 'go run main.go' to use icicle with Celer"
