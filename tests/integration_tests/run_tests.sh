#!/bin/bash

set -e

print_usage() {
    echo "Usage: $0 --logfile <logfile_path>"
}

logfile=""
use_docker=""
skip_download=""

# Parse arguments manually
while [[ $# -gt 0 ]]; do
    case "$1" in
        --logfile)
            if [[ -n "$2" && "$2" != "--"* ]]; then
                logfile="$2"
                shift 2
            else
                echo "Error: --logfile requires a value."
                exit 1
            fi
            ;;
        --use_docker)
            use_docker="1"
            shift
            ;;
        --skip_download)
            skip_download="1"
            shift
            ;;
        --help|-h)
            print_usage
            exit 0
            ;;
        *)
            echo "Error: Unknown option $1"
            print_usage
            exit 1
            ;;
    esac
done

# Check if --logfile was provided
if [[ -z "${logfile}" ]]; then
    echo "Error: --logfile is a mandatory argument."
    echo "Usage: $0 --logfile <logfile_path>"
    exit 1
fi

. common.sh

if [[ -z "${skip_download}" ]]; then
    download_latest
fi

if [[ ! -z "${use_docker}" ]]; then
    project_path=$(git rev-parse --show-toplevel)
    integration_tests_dir="${project_path}/tests/integration_tests/"
    cd "${project_path}"

    uid=$(id -u)
    gid=$(id -g)

    docker build --build-arg UID=${uid} --build-arg GID=${gid} -f "${integration_tests_dir}/Dockerfile.runtests" -t gdb_pt_dump_run_tests .

    mkdir -p $(dirname "${logfile}")
    touch "${logfile}"
    fullpath=$(realpath "${logfile}")

    docker run --volume "${project_path}:/gdb-pt-dump:ro" --volume "${fullpath}:${fullpath}:rw" -e "GDB_PT_DUMP_TESTS_LOGFILE=${logfile}" -ti gdb_pt_dump_run_tests
    exit 0
fi

echo "Storing output in logfile: \"${logfile}\""

# Use half ot the available CPUs to avoid excessively high memory usage.
num_jobs=$(($(nproc) / 2))

timeout_limit=120

./run_integration_tests.py -o "cache_dir=/tmp" -v -n ${num_jobs} --timeout ${timeout_limit} 2>&1 | tee ${logfile}
