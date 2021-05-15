#!/bin/bash -eE

# Setup
jenkins_jobs_dir="$(dirname "$(readlink -f "$0")")"
source $jenkins_jobs_dir/jenkins_setup.sh
cd $workspace

# Local vars
KERNEL_CONSOLE="$(get_kernel_console ${BOARD})"
SPIRENT_PORT="$(get_spirent_port ${BOARD})"
SPIRENT="$(get_spirent_ip ${BOARD})"
SPIRENT_SESSION_MANAGER="$(get_spirent_mgr ${BOARD})"
POWER_CONTROLLER="$(get_power_controller ${BOARD})"
BOARD_TYPE="$(get_board_type ${BOARD})"
BOARD="$(get_board_ip ${BOARD})"

usage() {
    echo "usage: $0 -p <platform>"
    echo
    echo "example:"
    echo "$0 -p gibraltar"
    echo
}

# post processing that runs on error or script completion.
# "script_complete" indicates whether the end of the script was reached (== "true")
# or if we are in post_process due to an error (!= "true" or empty)
# Retrieve junit.xml and reports_dir if they exist
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
    rsync_verify root@$BOARD:/tmp/$platform-sdk-dev/driver/junit.xml ./$junit_filename
    rsync_verify -r root@$BOARD:/tmp/reports_dir .

    if [[ "$ret_val" != "0" || "$script_complete" != "true" ]]; then
        echo "An error was caught during script execution. Please review log."
        exit 1
    else
        # No core dump or errors found
        echo "Success"
        exit 0
    fi
}

## MAIN

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
    M_GB_PACKET_DMA_WORKAROUND="m_gb_packet_dma_workaround=1"
    ASIC_TYPE="GIBRALTAR_A0"
    junit_filename="gb-ports-junit.xml"
    prefix="gb_ports"
else
    echo "$platform unsupported"
    exit 1
fi

# Log kernel console to file while running
enable_kernel_logging ${prefix}

# Boot device
/auto/asic-tools/sw/sdk/restart_board_and_test_alive.sh ${BOARD} ${POWER_CONTROLLER}

# Create environment setup script
test_iterations=1
REPORTS_DIR=/tmp/reports_dir
cat << EOF > ./env_setup.sh
    export  REPORTS_DIR='$REPORTS_DIR' \
            board_ip='$BOARD' \
            test_iterations='$test_iterations' \
            board_type='$BOARD_TYPE' \
            board_cfg_path=examples/sanity/'$BOARD_TYPE'_compact_cpu_board_config.json \
            spirent_session_manager_ip='$SPIRENT_SESSION_MANAGER' \
            spirent_ip='$SPIRENT' \
            spirent_port='$SPIRENT_PORT' \
            connectivity_dir=test/board/mixes/ \
            serdes_params_json=examples/sanity/'$BOARD_TYPE'_serdes_settings.json
EOF

# Copy environment setup script onto device
rsync_verify ./env_setup.sh root@$BOARD:/tmp/env_setup.sh
ret=$?
if [[ "$ret" != "0" ]]; then
    exit $ret
fi
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
    mkdir -p /tmp/fishnet
    cd fishnet
    tar xzpf ../fishnet.tgz
    cd /tmp
    tar xf $platform-sdk-dev.tar.gz
    export FISHNET="/tmp/fishnet"
    export FRAMEWORK="/tmp/fishnet"

    export NPSUITE="/tmp/$platform-sdk-dev/npsuite"
    export SDK_ROOT="/tmp/$platform-sdk-dev/driver"
    cd \$SDK_ROOT

    # Compile and insert new leaba_module from tarball
    rmmod leaba_module
    modprobe uio
    make -C modules/leaba_module
    insmod modules/leaba_module/leaba_module.ko m_add_wrapper_header=1 $M_GB_PACKET_DMA_WORKAROUND

    # Change settings on device to enable core dumps
    enable_core_dump

    # Execute test make targets
    cd \$SDK_ROOT
    source /tmp/env_setup.sh
    mkdir -p $REPORTS_DIR
    if [[ "$platform" == "gibraltar" ]]; then
        env IGNORE_MBIST_ERRORS=1 ASIC=$ASIC_TYPE ASIC_RESTART_SCRIPT=/cad/leaba/BSP/current/blacktip/device_power_cycle_and_mbist.sh make -f test/board/Makefile
    else
        env IGNORE_MBIST_ERRORS=1 ASIC=$ASIC_TYPE make -f test/board/Makefile
    fi
EOF

post_process "true"
