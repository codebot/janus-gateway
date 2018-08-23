#!/bin/bash
#todo: integrate with real Janus build system...
set -o errexit
set -o verbose
gcc decrypt.c -o decrypt -lcrypto
