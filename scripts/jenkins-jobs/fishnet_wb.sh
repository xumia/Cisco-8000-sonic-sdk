#!/bin/bash -e

# Setup
jenkins_jobs_dir="$(dirname "$(readlink -f "$0")")"
source $jenkins_jobs_dir/jenkins_setup.sh
cd $workspace/fishnet

# Globals
sdk_upgrade="false"

usage() {
    echo "usage: $0 -p <platform> -t <target>"
    echo
    echo "optional args:"
    echo "  -u (SDK Upgrade mode)"
    echo
    echo "example:"
    echo "$0 -p gibraltar -t hw_sanity_warm_boot"
    echo
}

# Process arguments
while getopts 'p:m:uh' flag; do
    case "${flag}" in
        p) platform="${OPTARG}" ;;
        m) marker="${OPTARG}" ;;
        u) sdk_upgrade="true" ;;
        h) usage; exit 0 ;;
        *) echo "Unexpected option \'${flag}\'"; usage; exit 1 ;;
    esac
done

# Verify required args are set
if [[ -z "$platform" ]]; then
    usage
    exit 1
fi

if [[ -z "$marker" ]]; then
    usage
    exit 1
fi

# Platform-specific init
if [[ "$platform" != "gibraltar" ]]; then
    echo "$platform unsupported"
    exit 1
fi

if [[ "$sdk_upgrade" == "true" ]]; then
    wb_mode="SDK_RELOAD_SAVE_PHASE"
    # change when SDK RELOAD mode would be fully supported (passing sdk path to upgrade)
    upgrade_arg="--sdk-upgrade-version=current_running_sdk"
else
    wb_mode="DURING_TRAFFIC_POST_MOD"
fi

$PYTHON3 ./scripts/remote_regression.py -m $marker -s $gb_sdk_tar -klog -cache -p "--warm-boot-mode=$wb_mode \
    --device-state-path=/dev/shm/device_state $upgrade_arg"
