#!/bin/bash -e

# dependencies tested with Ubuntu 22.04

sudo apt update
sudo apt install -y make \
                    clang \
                    linux-tools-generic \
                    libbpf-dev

sudo apt install -y python3-bpfcc bpfcc-tools libbpfcc-tools
