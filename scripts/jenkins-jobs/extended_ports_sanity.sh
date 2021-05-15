#!/bin/bash -xeE
# TODO - script needs to be converted to be generic for future platforms and
# support all newest features/improvements.

# Setup
jenkins_jobs_dir="$(dirname "$(readlink -f "$0")")"
source $jenkins_jobs_dir/jenkins_setup.sh
cd $workspace
error=false

# Local vars
KERNEL_CONSOLE="$(get_kernel_console ${BOARD})"
POWER_CONTROLLER="$(get_power_controller ${BOARD})"
BOARD_TYPE="$(get_board_type_with_proto ${BOARD})"
BOARD_PROTO="$(get_board_proto_ver ${BOARD})"
BOARD="$(get_board_ip ${BOARD})"

# Retrieve junit.xml and testing reports during post-processing once tests have
# completed
post_process() {
    cd $workspace

    # Disable logging for now, as design is different and will require more work to support
    # disable_kernel_logging

    # Retrieve result files
    ${SSHPASS_SCP} root@$BOARD:/tmp/gibraltar-sdk-dev/driver/junit.xml ./gb_extended_junit.xml
    ${SSHPASS_SCP} -r root@$BOARD:/tmp/extended_ports_sanity_logs .
    cp ./gb_extended_junit.xml extended_ports_sanity_logs/.

    if [ $error == true ] || [ "$1" != "complete" ]; then
        echo "Failure during tests execution"
        exit -1
    else
        exit 0
    fi
}

# Disable logging for now, as design is different and will require more work to support
# prefix="gb_ext_ports"
# password is also custom
# # Log kernel console to file while running
# enable_kernel_logging ${prefix}

# Boot device
# /auto/asic-tools/sw/sdk/restart_board_and_test_alive.sh ${BOARD} ${POWER_CONTROLLER}

# Copy images to device
${SSHPASS_SCP} ${REPLAY_DIR}/gibraltar-sdk-${GIT_COMMIT}.tar.gz root@$BOARD:/tmp/gibraltar-sdk-dev.tar.gz
${SSHPASS_SCP} ${REPLAY_DIR}/fishnet-${GIT_COMMIT}.tgz root@${BOARD}:/tmp/fishnet.tgz

# Trap ERR so we can always run post-processing on completion
trap post_process ERR

# Setup device environment
test_iterations=1
REPORTS_DIR=/tmp/extended_ports_sanity_logs
cat << EOF > ./gibraltar_source_file
    export  REPORTS_DIR='$REPORTS_DIR' \
            board_ip='$BOARD' \
            test_iterations='$test_iterations' \
            board_type='$BOARD_TYPE' \
            board_proto='$BOARD_PROTO' \
            serdes_params_json=examples/sanity/'$BOARD_TYPE'_serdes_settings.json \
            device_rev=gibraltar \
            board_cfg_path=examples/sanity/churchillP1_board_config.json \
            board_connect_path=test/ports/config/gibraltar_ports_conn_config.json \
            PYTEST=/sherman/auto/herotools/packages/leaba-sdk-cel7/bin/pytest
EOF

 

${SSHPASS_SCP} ./gibraltar_source_file root@$BOARD:/tmp/gibraltar_source_file
${SSHPASS_SSH} root@${BOARD} -T << EOF
    if [ ! -d "/sherman" ]; then
        echo "172.25.40.103:/sherman/   /sherman   nfs   defaults,vers=3,nolock,noauto   0 0" >> /etc/fstab
        mkdir -p /sherman ; mount /sherman ; ln -s /sherman/auto
    fi
    cd /bin/; rm lspci; ln -s /sbin/lspci lspci
    killall -9 python3

    cd /tmp/
    mkdir -p /tmp/fishnet
    cd fishnet
    tar xzpf ../fishnet.tgz
    cd /tmp
    rm -rf extended_ports_sanity_logs
    rm -rf gibraltar-sdk-dev
    tar xf gibraltar-sdk-dev.tar.gz
EOF

# Run tests
${SSHPASS_SSH} root@${BOARD} -T << EOF
    cd /tmp/
    export FISHNET="/tmp/fishnet"
    export FRAMEWORK="/tmp/fishnet"
    export NPSUITE="/tmp/gibraltar-sdk-dev/npsuite"
    export SDK_ROOT="/tmp/gibraltar-sdk-dev/driver"
    export IGNORE_MBIST_ERRORS=1

    cd \$SDK_ROOT
    source /tmp/gibraltar_source_file
    mkdir -p $REPORTS_DIR
    env IGNORE_MBIST_ERRORS=1 ASIC=GIBRALTAR_A0 ASIC_RESTART_SCRIPT=/sherman/bsp/src/churchill/gb_asic_restart_script.sh /sherman/jenkins/make -f test/ports/Makefile 
EOF
if [ $? != "0" ]; then
    error=true
fi

post_process "complete"
