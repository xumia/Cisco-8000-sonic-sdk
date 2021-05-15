#!/bin/bash

usage(){
   echo "possible options:"
   echo "--asic <asic type> - asic type can be GB or PA"
   echo "-e - echo mode. Don't run enything. Just show the commands that should run"
   echo "--gdb - run test with gdb"
   echo "-h - print this help message"
   echo "--json <json test setup file> - If not provided, file will be deduced from device IP"
   echo "--pdb - add --pdb to pytest flags"
   echo "-s - add -s to Pytest flags"
   echo "--second_only - do only the second run of two phase run"
   echo "--sim - run using nsim (if not running on HW, or no leaba module loaded, this will be added automatically)"
   echo "-t <test name> (example: -t tm)"
   export test_names=`ls test/python/hw/hwtest*.py | cut -d. -f 1 | cut -d_ -f2-`
   echo "  available test names are:"
   echo ${test_names}
   echo "--two_phase - do two phase warm boot run (exit the process after warm boot shudwon, and run pytest again in warmboot_init mode)"
   echo "--warmboot - do warm boot at specific point in the test (if defined), without exiting the pytest process"
   exit 1
}

if [ `basename $PWD` != "sai" ]; then
  echo "Must be running from sai directory"
  exit
fi

TEMP=$(getopt -o 'ehst:' --long 'asic:, gdb, json:, pdb, second_only, sim, two_phase, warmboot' -n 'run_hw_test.sh' -- "$@")

if [ $? -ne 0 ]; then
  usage
fi

eval set -- "$TEMP"
unset TEMP

if [ -d "/common/pkgs/python/3.6.10" ] ; then
  # leaba python path
  PYTEST_BIN=/common/pkgs/python/3.6.10/bin/pytest
  PYTHON_BIN='/common/pkgs/python/3.6.10/bin/python3.6'
else
  # sj18-leaba-02 python path
  if [ -d "/auto/asic-tools/sw/python/3.6.10" ] ; then
    PYTEST_BIN=/auto/asic-tools/sw/python/3.6.10/bin/pytest
    PYTHON_BIN=/auto/asic-tools/sw/python/3.6.10/bin/python
  else
    # HW test unit in SJ18
    if [ -d "/usr/local/lib/python3.6" ] ; then
      # Preshing P3, sj18-leaba-07, 172.22.252.152
      # Blacktip, sj18-leaba-24, 172.22.252.169
      # GB_ATL board evt2, sj18-leaba-27, 172.22.252.172
      PYTEST_BIN=/usr/local/bin/pytest
      PYTHON_BIN=/usr/local/bin/python3.6
    else
      echo "Could not find python path"
      exit 1
    fi
  fi
fi

DO_WARM_BOOT=0
ECHO=""
EXTRA_PYTEST_ARGS=""
FIRST_RUN=1
GDB=""
HW_TYPE=gibraltar
FISHNET_ASIC_NAME=GB
JSON_FILE="default"
LEABA_VALIDATION_PATH=
SDK_PATH=`pwd`/../
SIM_ARG="none"
TEST_FRAMEWORK=${SDK_PATH}/fishnet
BSP_LIB_PATH=""
if [ ! -e $TEST_FRAMEWORK ]; then
    TEST_FRAMEWORK=test/python/hw/bsp
    BSP_LIB_PATH=/bsp/lib
    JSON_FILE="none"
    if [ ! -e $BSP_LIB_PATH ]; then
        echo "No fishnet,exists,and no BSP installed"
        exit 1
    fi 
fi

TEST_NAME="no_test"
TWO_PHASE=0

while true; do
  case "$1" in
    '--asic')
      FISHNET_ASIC_NAME=$2
      shift 2
      continue
    ;;
    '-e')
      ECHO=echo
      shift 1
      continue
    ;;
    '--gdb')
      GDB="gdb --args ${PYTHON_BIN}"
      shift 1
      continue
    ;;
    '-h')
      usage
    ;;
    '--json')
        JSON_FILE=$2
        shift 2
        continue
    ;;
    '--pdb')
      EXTRA_PYTEST_ARGS="${EXTRA_PYTEST_ARGS} --pdb"
      shift 1
      continue
    ;;
    '-s')
      EXTRA_PYTEST_ARGS="${EXTRA_PYTEST_ARGS} -s"
      shift 1
      continue
    ;;
    '--second_only')
      FIRST_RUN=0
      shift 1
      continue
    ;;
    '--sim')
      SIM_ARG="--sim"
      shift 1
      continue
    ;;
    '-t')
      TEST_NAME=$2
      shift 2
      continue
    ;;
    '--two_phase')
      TWO_PHASE=1
      shift 1
      continue
    ;;
    '--warmboot')
      DO_WARM_BOOT=1
      shift 1
      continue
    ;;
    '--')
      shift
      break
    ;;
  esac
done

if [ ${FISHNET_ASIC_NAME} == "PA" ]; then
  unset ASIC
  HW_TYPE=pacific
else
  if [ ${FISHNET_ASIC_NAME} == "GB" ]; then
    HW_TYPE=gibraltar
    export ASIC="GIBRALTAR_A0"
  else
    echo "Wrong asic. Must be PA or GB"
    exit 1
  fi
fi

LEABA_PATH=${SDK_PATH}/driver/${HW_TYPE}

if [ ${TEST_NAME} == "no_test" ]; then
  echo "Must provide test name using -t <test name>"
  echo "-h for help"
  exit 1
else
    TEST_FILE=test/python/hw/hwtest_${TEST_NAME}.py
    if [ ! -e $TEST_FILE ]; then
        echo "test $TEST_NAME does not exist"
        test_names=`ls test/python/hw/hwtest*.py | cut -d. -f 1 | cut -d_ -f2-`
        echo "  available test names are:"
        echo ${test_names}
        exit 1
    fi
fi

##### define the BASE_OUTPUT_DIR
running_from_compiled=0
if [ -d "$LEABA_PATH/out" ]; then
   echo 'Running from compiled version:' $LEABA_PATH
   if [ -d "$SDK_PATH/sai/out/${HW_TYPE}/opt3" ]; then
      export OPT='opt3'
   else
      export OPT='noopt-debug'
   fi
   export BASE_OUTPUT_DIR=$LEABA_PATH/out/$OPT
   running_from_compiled=1
else
   echo 'Running from release version:' $LEABA_PATH
   export BASE_OUTPUT_DIR=$LEABA_PATH
fi

echo using sai/out/${HW_TYPE}/${OPT}
export NPL=${SDK_PATH}/npl

##### export Env variables
export LAB_PATH=$LEABA_VALIDATION_PATH/validation
export PYTHONPATH=$BASE_OUTPUT_DIR/pylib:$SDK_PATH/driver/shared/src/lld:$SDK_PATH/driver/shared/test/api:$LEABA_PATH/test/hld:$SDK_PATH/driver/shared/test/utils:${SDK_PATH}/sai/test/python:$SDK_PATH/sai/out/${HW_TYPE}/${OPT}/pylib:$TEST_FRAMEWORK:${BSP_LIB_PATH}
export LD_LIBRARY_PATH=$BASE_OUTPUT_DIR/lib:${BSP_LIB_PATH}
export NSIM_SOURCE_PATH=$NPL/cisco_router/
export NSIM_LEABA_DEFINED_FOLDER=$NPL/${HW_TYPE}/leaba_defined/
export NSIM_HW_DEF_FILE=$NSIM_LEABA_DEFINED_FOLDER/hw_definitions/hw_definitions.json
#export PYTHONPATH=$PYTHONPATH:$LAB_PATH/${HW_TYPE}:$PYTHONPATH:$LAB_PATH/${HW_TYPE}/global:$PYTHONPATH:$LAB_PATH/${HW_TYPE}/bin:$PYTHONPATH:$LAB_PATH/h:$PYTHONPATH:$LEABA_VALIDATION_PATH
export LEABA_SDK_PATH=$BASE_OUTPUT_DIR

export LEABA_VALIDATION_PATH=$VAL_VER
export LAB_PATH=$LEABA_VALIDATION_PATH

export PYTHONPATH=${PYTHONPATH}:$LAB_PATH
export PYTHONPATH=${PYTHONPATH}:$LAB_PATH/validation
export PYTHONPATH=${PYTHONPATH}:$LAB_PATH/validation/bin
export PYTHONPATH=${PYTHONPATH}:$LAB_PATH/validation/global


# assuming that if we are root, we run on HW
if [ `whoami` == 'root' ]; then
    /sbin/lsmod | grep leaba >& /dev/null
    if [ $? -ne 0 ]; then
        echo "No leaba module loaded. Trying to load"
        modprobe uio
        cd `find ../driver/${HW_TYPE}/ -name leaba_module`
        make
        if [ -f leaba_module.ko ]; then
            insmod leaba_module.ko # m_add_wrapper_header=1
        else
            echo "Failed loading. Exiting"
            exit 1
        fi
        cd -
    fi
    DEVICE_IP=`/sbin/ifconfig | grep -w inet | grep -v 127.0.0.1 | awk '{print $2}'`
else
    DEVICE_IP=10.56.18.96
    SIM_ARG="--sim"
fi

if [ a${JSON_FILE} == "adefault" ]; then
    FISHNET_JSON_FILE=../fishnet/setup/regression_jsons/${DEVICE_IP}_regression.json
    SAI_JSON_FILE=test/python/hw/setup/${DEVICE_IP}.json
    if [ -e ${SAI_JSON_FILE} ]; then
        JSON_FILE=${SAI_JSON_FILE}
    else
        if [ -e ${FISHNET_JSON_FILE} ]; then
            JSON_FILE=${FISHNET_JSON_FILE}
        else
            echo "Could not find config files $SAI_JSON_FILE or $FISHNET_JSON_FILE"
            echo "If you have proper config file for your setup, try adding --json <file name>"
            exit 1
        fi
    fi
else
    if [ ! ${JSON_FILE} == "" ]; then
        if [ ! -e ${SAI_JSON_FILE} ]; then
            echo "json config file $JSON_FILE does not exist"
            exit 1
        fi
    fi
fi

if [ ${SIM_ARG} != "--sim" ]; then
    SIM_ARG=""
fi

WARM_BOOT_FLAGS="--warmboot none"
SECOND_RUN=0
if [ $DO_WARM_BOOT == 1 ]; then
    WARM_BOOT_FLAGS="--warmboot point"
fi

if [ $TWO_PHASE == 1 ]; then
    WARM_BOOT_FLAGS="--warmboot point --warmboot_shutdown_count 1"
    SECOND_RUN=1
fi

#first time do warm boot shutdown
if [ $FIRST_RUN == 1 ]; then
    ${ECHO} ${GDB} ${PYTEST_BIN} ${TEST_FILE} --json ${JSON_FILE} ${WARM_BOOT_FLAGS} ${EXTRA_PYTEST_ARGS} ${SIM_ARG} --asic ${FISHNET_ASIC_NAME}
    if [ $? != 0 ]; then
       echo Failure: first run failed
       exit 1
    fi
fi

# second run. Do warm boot init
if [ $SECOND_RUN == 1 ]; then
    # ??? todo add fishnet warm boot flag after it is merged to master
    ${ECHO} ${PYTEST_BIN} ${TEST_FILE} --json ${JSON_FILE} --warmboot_init ${EXTRA_PYTEST_ARGS} ${SIM_ARG} --asic ${FISHNET_ASIC_NAME}
fi

if [ $? != 0 ]; then
   echo Failure: warm boot init run failed
   exit 1
fi
