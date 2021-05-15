#!/bin/bash -e

# Setup
jenkins_jobs_dir="$(dirname "$(readlink -f "$0")")"
source $jenkins_jobs_dir/jenkins_setup.sh
cd $workspace/fishnet

usage() {
    echo "usage: $0 -p <platform>"
    echo
    echo "example:"
    echo "$0 -p pacific"
    echo
}

# Process arguments
while getopts 'p:sh' flag; do
    case "${flag}" in
        p) platform="${OPTARG}" ;;
        s) SLOW_TEST_FLAG="SKIP_SLOW_TESTS=1 " ;;
        h) usage; exit 0 ;;
        *) echo "Unexpected option \'${flag}\'"; usage; exit 1 ;;
    esac
done

# Verify required args are set
if [[ -z "$platform" ]]; then
    usage
    exit 1
fi

# Platform-specific init
if [[ "$platform" == "gibraltar" ]]; then
    marker="gb_regression"
    sdk_tar="$gb_sdk_tar"
elif [[ "$platform" == "pacific" ]]; then
    marker="hw_sanity"
    sdk_tar="$pc_sdk_tar"
else
    echo "$platform unsupported"
    exit 1
fi

$PYTHON3 ./scripts/remote_regression.py -m $marker -s $sdk_tar -jpwd $MARVIN_ACCOUNT_PSW $SLOW_TEST_FLAG -klog -cache
