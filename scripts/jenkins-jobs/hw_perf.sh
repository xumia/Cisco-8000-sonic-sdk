#!/bin/bash -eE

# Setup
jenkins_jobs_dir="$(dirname "$(readlink -f "$0")")"
source $jenkins_jobs_dir/jenkins_setup.sh
cd $workspace

# Local vars
KERNEL_CONSOLE="$(get_kernel_console ${BOARD})"
POWER_CONTROLLER="$(get_power_controller ${BOARD})"
BOARD="$(get_board_ip ${BOARD})"
GB_LEABA_INSMODULE_FLAGS=''

usage() {
    echo "usage: $0 -p <platform>"
    echo
    echo "example:"
    echo "$0 -p pacific"
    echo
}

# post processing that runs on error or script completion.
# "script_complete" indicates whether the end of the script was reached (== "true")
# or if we are in post_process due to an error (!= "true" or empty)
# Retrieve junit.xml if it exists
post_process() {
    script_complete="$1"
    cd $workspace

    # Disable nested trap and early exit during post_process
    set +eE
    trap - ERR

    disable_kernel_logging

    # Search for core dump and print backtrace if found
    process_core_dump $platform
    ret_val="$?"

    # Retrieve junit.xml from device
    rsync_verify root@${BOARD}:/tmp/fishnet/junit.xml ./$junit_filename

    if [[ "$ret_val" != "0" || "$script_complete" != "true" ]]; then
        echo "An error was caught during script execution. Please review log."
        exit 1
    else
        # No core dump or errors found
        echo "Success"
        exit 0
    fi
}

# Process arguments
while getopts 'p:h' flag; do
    case "${flag}" in
        p) platform="${OPTARG}" ;;
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
    GB_LEABA_INSMODULE_FLAGS="m_add_wrapper_header=1 m_gb_packet_dma_workaround=1"
    junit_filename="gb-hw-perf-junit.xml"
    prefix="gb_hw_perf"
    marker="sdk_gb_hw_sanity"
    chip_type="GB"
    sdk_tar="$gb_sdk_tar"
elif [[ "$platform" == "pacific" ]]; then
    junit_filename="pc-hw-perf-junit.xml"
    prefix="pc_hw_perf"
    marker="sdk_hw_sanity"
    chip_type="PC"
    sdk_tar="$pc_sdk_tar"
else
    echo "$platform unsupported"
    exit 1
fi

# Log kernel console to file while running
enable_kernel_logging ${prefix}

# Boot device
/auto/asic-tools/sw/sdk/restart_board_and_test_alive.sh ${BOARD} ${POWER_CONTROLLER}

rsync_verify $jenkins_jobs_dir/jenkins_setup.sh root@${BOARD}:/tmp
ret=$?
if [[ "$ret" != "0" ]]; then
    exit $ret
fi

# Trap ERR so we can always run post-processing on completion
trap post_process ERR

# Run tests
${SSHPASS_SSH} root@${BOARD} -T << EOF
    source /tmp/jenkins_setup.sh

    # Copy images from CAE archive to device
    cp -v $CAE_REPLAY_DIR/$platform-sdk-${GIT_COMMIT}.tar.gz /tmp/$platform-sdk-dev.tar.gz
    cp -v $CAE_REPLAY_DIR/fishnet-${GIT_COMMIT}.tgz /tmp/fishnet.tgz

    # Extract platform tarball
    mount -a
    cd /tmp/
    tar xf $platform-sdk-dev.tar.gz
    mkdir -p /tmp/fishnet
    cd /tmp/fishnet
    tar xzpf ../fishnet.tgz
    export SDK_ROOT="/tmp/$platform-sdk-dev/driver"
    cd \$SDK_ROOT

    # Compile and insert new leaba_module from tarball
    rmmod leaba_module
    modprobe uio
    make -C modules/leaba_module
    insmod modules/leaba_module/leaba_module.ko $GB_LEABA_INSMODULE_FLAGS

    # Change settings on device to enable core dumps
    enable_core_dump

    # Extract validation files
    mount -a
    cd /tmp/
    tar xf /cad/leaba/validation/latest-$platform
    mv validation-* validation-latest

    # Execute test script
    export PYTEST_JIRA_PASSWORD=${MARVIN_ACCOUNT_PSW}
    cd /tmp/fishnet
    ./scripts/release_candidate.sh -d $BOARD -c $chip_type -V /tmp/validation-latest/ -m $marker -S /tmp/$platform-sdk-dev -p '-sv --junit-prefix=$prefix'
EOF

post_process "true"
