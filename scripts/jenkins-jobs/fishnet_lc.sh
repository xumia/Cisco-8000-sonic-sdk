#!/bin/bash -e

# Setup
jenkins_jobs_dir="$(dirname "$(readlink -f "$0")")"
source $jenkins_jobs_dir/jenkins_setup.sh
cd $workspace/fishnet

doa_regression="false"
override_json_opt="-j ./setup/lc_jsons/lc_standalone_override.json"

usage() {
    echo "usage: $0 -p <platform>"
    echo
    echo "example:"
    echo "$0 -p pacific"
    echo
}

# Process arguments
while getopts 'p:qsh' flag; do
    case "${flag}" in
        p) platform="${OPTARG}" ;;
        q) doa_regression="true" ;;
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
    if [[ "$doa_regression" == "true" ]]; then
        marker="gb_hw_doa"
        override_json_opt="-j ./setup/doa_override_jsons/gb_lc_standalone_inject_from_npu_host_override.json"
    else
        marker="lc_gb_hw_sanity"
        override_json_opt="-j ./setup/lc_jsons/lc_standalone_override_gb.json"
    fi
    sdk_tar="$gb_sdk_tar"
elif [[ "$platform" == "pacific" ]]; then
    if [[ "$doa_regression" == "true" ]]; then
        marker="pacific_hw_doa"
        override_json_opt="-j ./setup/doa_override_jsons/pacific_lc_standalone_inject_from_npu_host_override.json"
    else
        marker="lc_hw_sanity"
    fi
    sdk_tar="$pc_sdk_tar"
else
    echo "$platform unsupported"
    exit 1
fi

$PYTHON3 ./scripts/remote_regression.py -m $marker $override_json_opt \
    -s $sdk_tar -jpwd $MARVIN_ACCOUNT_PSW $SLOW_TEST_FLAG -klog -cache
