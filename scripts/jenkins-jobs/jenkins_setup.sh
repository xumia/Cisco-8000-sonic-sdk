#!/bin/bash

# Variables
# Only set these variables if within a git repo
CISCO_GIT=/auto/asic-tools/sw/git/2.17.1/bin/git
LEABA_GIT=/common/pkgs/git/2.11.1/bin/git.bin
if [[ -f $CISCO_GIT || -f $LEABA_GIT ]]; then
    if git rev-parse --git-dir > /dev/null 2>&1; then
        workspace="$(git rev-parse --show-toplevel)"
        gb_sdk_tar="$workspace/gibraltar-sdk-dev.tar.gz"
        pc_sdk_tar="$workspace/pacific-sdk-dev.tar.gz"
    fi
fi

# Globals
TIMEOUT_RET=124
TIMEOUT_KILL_RET=137
SUCCESS=0
SLOW_TEST_FLAG=""

# Commands
LSF_8C="/auto/edatools/bin/bsub -Is -P cag-sw.p -q build -R \"rusage[cores=8]\""
LSF_12C="/auto/edatools/bin/bsub -Is -P cag-sw.p -q build -R \"rusage[cores=12]\""
PYTHON3="/auto/asic-tools/sw/python/3.6.10/bin/python3"
SSHPASS="/auto/asic-tools/sw/sshpass/1.06/bin/sshpass"
SSHPASS_SSH="$SSHPASS -p $DEVICE_CRED_PSW -v ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=10 -o ServerAliveCountMax=90"
SSHPASS_SCP="$SSHPASS -p $DEVICE_CRED_PSW -v scp -o StrictHostKeyChecking=no"
SSHPASS_RSYNC="$SSHPASS -p $DEVICE_CRED_PSW -v /usr/bin/rsync -LIvc"

# Setup Environment
export RSYNC_RSH="ssh -o StrictHostKeyChecking=no"

# Helper Functions

#######################################
# Lockable Resource data management functions
#
# LRs have the format:
# <device_ip>:<board_type>:<pwr_ctl>:<spirent_mgr>:<spirent_ip>:<spirent_port>:<kernel_console>

# Gets the board IP 
get_board_ip() {
    echo ${1} | cut -f 1 -d :
}

# Gets the board type, such as "sherman"
get_board_type() {
    echo ${1} | cut -f 2 -d :
}

# Gets the board type from string as "sherman/P7"
get_board_type_with_proto() {
    echo ${1} | cut -f 2 -d : | cut -f 1 -d /
}

# Gets the board proto type
get_board_proto_ver() {
    echo ${1} | cut -f 2 -d : | cut -f 2 -d /
}

# Gets the power controller IP
get_power_controller() {
    echo ${1} | cut -f 3 -d :
}

# Gets the Spirent Session Manager
get_spirent_mgr() {
    echo ${1} | cut -f 4 -d :
}

# Gets the Spirent IP
get_spirent_ip() {
    echo ${1} | cut -f 5 -d :
}

# Gets the Spirent port
get_spirent_port() {
    echo ${1} | cut -f 6 -d :
}

# Gets the kernel console IP/port
get_kernel_console() {
    echo ${1} | cut -f 7 -d :
}
#######################################

rsync_verify() {
    # Transfer file with checksum and retry on failure
    $SSHPASS_RSYNC -P $@
    ret="$?"
    max_retries=15
    for (( retry_cnt=1; retry_cnt<=$max_retries; retry_cnt++ )); do
        if [[ "$ret" == "23" || "$ret" == "24" ]]; then
            # Partial transfer occurred. Need to append the rest of the file
            # 23 - Partial transfer due to error
            # 24 - Partial transfer due to vanished source files
            echo "Transfer was interrupted with return code '$ret'"
            echo "Attempting to append remainder of the file (retry $retry_cnt of $max_retries)"
            $SSHPASS_RSYNC --append-verify $@
            ret="$?"
        elif [[ "$ret" != "0" ]]; then
            echo "Transfer failed with return code '$ret'"
            echo "retrying (retry $retry_cnt of $max_retries)"
            $SSHPASS_RSYNC -P $@
            ret="$?"
        else
            # Success
            break
        fi
    done

    # This handles the else case for a failure not related to partial transfer as well
    # as a failure on the attempt to append the remaining data.
    if [[ "$ret" != "0" ]]; then
        echo "ERROR: transfer failed with arg(s) '$@'"
        echo "rsync returned '$ret'"
    fi
}

# Connects to kernel console and writes to file
enable_kernel_logging() {
    prefix="$@"
    kernel_log="$workspace/${prefix}_kernel_console.txt"

    if [[ "$KERNEL_CONSOLE" != "tbd" && ! -z "$KERNEL_CONSOLE" ]]; then
        console_ip="$(echo "$KERNEL_CONSOLE" | cut -f 1 -d /)"
        port="$(echo "$KERNEL_CONSOLE" | cut -f 2 -d /)"
        line="$(($port - 2000))"

        # Expect script to automate connecting to kernel console and write to log in ws
        $workspace/scripts/kernel_console.py $console_ip $port $BOARD \
            $DEVICE_CRED_USR $DEVICE_CRED_PSW > $kernel_log 2>&1 &
        export con_pid=$!
        echo "Kernel console logging enabled"
    else
        export con_pid="na"
        echo "Warning: no kernel console provided in LR data."
        echo "API returned '$KERNEL_CONSOLE' for board '$BOARD'"
    fi
}

# Kill PID of kernel logger
disable_kernel_logging() {
    if [[ "$con_pid" != "na" ]]; then
        # Kill console logger with SIGTERM
        # output redirected to ignore "<PID> doesn't exist" or "Terminated <PID>"
        { kill $con_pid && wait $con_pid; } 2>/dev/null
        echo "Kernel console logging disabled"
    fi
}

NEW_CORE_DIR="/var/crash/latest"
ARCHIVE_CORE_DIR="/var/crash/prev"
CORE_FORMAT="core_%e_%p.%t"

enable_core_dump() {
    # Enable
    ulimit -c unlimited
    mkdir -p $NEW_CORE_DIR
    sysctl -w kernel.core_pattern=$NEW_CORE_DIR/$CORE_FORMAT

    # Move old core files from NEW_CORE_DIR so they are not mistaken as new
    mkdir -p $ARCHIVE_CORE_DIR
    if [ ! -z "$(ls -A $NEW_CORE_DIR/)" ]; then
        mv $NEW_CORE_DIR/* $ARCHIVE_CORE_DIR/.
    fi

    # Only keep a history of 30 core files per device
    archived_cores="$(ls -1t $ARCHIVE_CORE_DIR/)"
    num_archived="$(echo "$archived_cores" | wc -l)"
    iter="0"
    while read -r core; do
        iter="$((iter + 1))"
        if [[ "$iter" -gt "30" ]]; then
            rm -f $ARCHIVE_CORE_DIR/$core
        fi
    done <<< "$archived_cores"
}

process_core_dump() {
    platform="$1"
    SDK_ROOT="/tmp/$platform-sdk-dev/driver"

    # Search for newest core dump in /var/crash/latest
    core_dump="$(${SSHPASS_SSH} root@${BOARD} -T << EOF
        # Search for new core dumps in /var/crash/latest, filtering to newest if more than one
        echo "$NEW_CORE_DIR/\$(ls -1t $NEW_CORE_DIR | grep "core_python\|core_pytest" | head -n 1)"
EOF
    )"

    # There may be login messages echoed before we run any commands on the remote.
    # Filter to the last line to ignore them.
    core_dump="$(echo -e "$core_dump" | tail -n 1 | grep "core_python\|core_pytest")"

    if [ ! -z $core_dump ]; then
        ${SSHPASS_SSH} root@${BOARD} -T << EOF
            # Dump backtrace for existing core
            echo "core dump file is: $core_dump"

            # Create temp GDB script to dump all thread backtraces
            cd $SDK_ROOT
            tmp="./gdb_script"
            echo "thread apply all bt" > \$tmp
            gdb -batch -nx -q -x "\$tmp" -e modules/leaba_module/leaba_module.ko -c $core_dump
            rm -f \$tmp
EOF

        return 1
    fi
}
