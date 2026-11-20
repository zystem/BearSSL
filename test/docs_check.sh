#!/bin/sh
# Runs the commands of the documents and compares what they print.
# Needs: make, a C compiler, openssl, python3.
cd "$(dirname "$0")/.." || exit 2
exec python3 -I test/docs_check.py
