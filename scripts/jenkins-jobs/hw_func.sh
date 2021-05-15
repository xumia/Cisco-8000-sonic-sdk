#!/bin/bash -eE

# Setup
jenkins_jobs_dir="$(dirname "$(readlink -f "$0")")"
source $jenkins_jobs_dir/jenkins_setup.sh
cd $workspace

# Local vars
KERNEL_CONSOLE="$(get_kernel_console ${BOARD})"
POWER_CONTROLLER="$(get_power_controller ${BOARD})"
BOARD="$(get_board_ip ${BOARD})"
M_GB_PACKET_DMA_WORKAROUND=''
make_args="-k"
wb_supported="false"
wb_prefix=''

usage() {
    echo "usage: $0 -p <platform> -t <target> [-m <matilda-mode>]"
    echo
    echo "optional args:"
    echo "  -t <target> (select a subset of make targets)"
    echo "  -m <matilda-mode> (select matilda mode)"
    echo
    echo "example:"
    echo "$0 -p pacific -t sanity -m 3.2A"
    echo
}

# post processing that runs on error or script completion.
# "script_ret" is the return code for the overall script status.
post_process() {
    script_ret="$1"

    # Disable nested trap and early exit during post_process
    set +eE
    trap - ERR

    disable_kernel_logging

    # Search for core dump and print backtrace if found
    process_core_dump $platform
    core_ret=$?

    if [[ $script_ret != 0 ]]; then
        if [[ $script_ret == $TIMEOUT_RET ]]; then
            # timeout successfully killed process with default signal
            echo "ERROR: timeout occurred! Process was terminated."
        elif [[ $script_ret == $TIMEOUT_KILL_RET ]]; then
            # First attempt from timeout failed. Had to forcefull SIGKILL to stop process
            echo "ERROR: timeout occurred and process stuck! KILL signal was sent."
        else
            # Any error was hit, including a crash with a core dump
            echo "An error was caught during script execution. Please review log."
        fi
        exit $script_ret
    elif [[ $core_ret != 0 ]]; then
        # A core dump was found during execution without an error return code. Override
        echo "An error was caught during script execution. Please review log."
        exit $core_ret
    else
        # No core dump, error, or timeout occurred
        echo "Success"
        exit 0
    fi
}

## MAIN

# Process arguments
while getopts 'p:t:m:sh' flag; do
    case "${flag}" in
        p) platform="${OPTARG}" ;;
        t) target="${OPTARG}" ;;
        m) matilda_mode="${OPTARG}" ;;
        s) SLOW_TEST_FLAG="SKIP_SLOW_TESTS=1 " ;;
        h) usage; exit 0 ;;
        *) echo "Unexpected option \'${flag}\'"; usage; exit 1 ;;
    esac
done

# Verify required args are set
if [[ -z "$platform" || -z "$target" ]]; then
    usage
    exit 1
fi

if [[ "$target" == "test-warmboot" ]]; then
    wb_prefix="wb_"
fi
prefix_end="hw_${wb_prefix}func"

# Platform-specific init
if [[ "$platform" == "gibraltar" ]]; then
    # Generic GB settings
    M_GB_PACKET_DMA_WORKAROUND="m_gb_packet_dma_workaround=1"
    if [[ -n "$matilda_mode" ]]; then
        # Matilda GB settings
        prefix="gb_ma_${prefix_end}"
        timeout_val="51h"
        make_args="${make_args} MATILDA_TEST_MODE=\"${matilda_mode}\""
    else
        # Non-Matilda GB settings
        wb_supported="true"
        prefix="gb_${prefix_end}"
        timeout_val="45h"
    fi
elif [[ "$platform" == "pacific" ]]; then
    prefix="pc_${prefix_end}"
    timeout_val="30h"
elif [[ "$platform" == "graphene" ]]; then
    prefix="gr_hw_func"
    timeout_val="30h"
else
    echo "$platform unsupported"
    usage
    exit 1
fi

if [[ "$wb_supported" != "true" && "$target" == "test-warmboot" ]]; then
    echo "$target unsupported for $platform"
    usage
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
trap 'post_process $?' ERR

# Run tests
timeout -k 5m $timeout_val ${SSHPASS_SSH} root@${BOARD} -T << EOF
    source /tmp/jenkins_setup.sh

    # Copy image from CAE archive to device
    cp -v $CAE_REPLAY_DIR/$platform-sdk-${GIT_COMMIT}.tar.gz /tmp/$platform-sdk-dev.tar.gz

    # Extract platform tarball
    mount -a
    cd /tmp/
    # Make sure we clean-up any old sdk binaries before we extract
    rm -rf $platform-sdk-dev
    tar xf $platform-sdk-dev.tar.gz
    export SDK_ROOT="/tmp/$platform-sdk-dev/driver"
    cd \$SDK_ROOT

    # Compile and insert new leaba_module from tarball
    rmmod leaba_module
    modprobe uio
    make -C modules/leaba_module
    LEABA_MODULE_PATH=modules/leaba_module/leaba_module.ko
    insmod \$LEABA_MODULE_PATH m_add_wrapper_header=1 $M_GB_PACKET_DMA_WORKAROUND

    # Change settings on device to enable core dumps
    enable_core_dump
            
    # Execute test make targets
    cd \$SDK_ROOT
    if [[ "$platform" == "gibraltar" ]]; then
        env LEABA_KERNEL_MODULE_PATH=\$LEABA_MODULE_PATH ASIC_RESTART_SCRIPT=/cad/leaba/BSP/current/blacktip/device_power_cycle_and_mbist.sh make -f test/api/Makefile $target $SLOW_TEST_FLAG $make_args
    else
        env LEABA_KERNEL_MODULE_PATH=\$LEABA_MODULE_PATH make -f test/api/Makefile $target $SLOW_TEST_FLAG $make_args
    fi
EOF

post_process $SUCCESS
