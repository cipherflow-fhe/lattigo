#!/usr/bin/env bash
set -euo pipefail

go build -buildmode=c-archive -o liblattigo.a .
go build -buildmode=c-shared -o liblattigo.so .
