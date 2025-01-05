#!/bin/bash

. common.sh

download_latest
docker build -t gdb_pt_dump_package_tests -f Dockerfile.package .
