#!/bin/bash

# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

script_name=$(basename $0)
script_dir=$(dirname $0)

source $script_dir/sdk_bash_utils.sh

USAGE="
Usage: $script_name [OPTIONS] <Arguments>
Runs NSIM test.
OPTIONS:
  -h|--help                              Print help message and exit
  --dryrun                               Only print commands that would be executed
  -a <asic>                              Asic type: [$valid_devices_choices]
  --opt <value>                          Use to set OPT value other than OPT=3
  --opt3                                 Assume env OPT=3,       instead of passing env OPT=3
  --debug                                Assume env DEBUG=1,     instead of passing env DEBUG=1
  --clang                                Assume env USE_CLANG=1, instead of passing env USE_CLANG=1
  --run                                  Run test,               default is --run
  --pdb                                  Run test with PDB
  --gdb                                  Run test with GDB
  --gdbpdb                               Run test with GDB and PDB
  --sai                                  Run SAI test with pytest
  --testdir <testdir>                    All Tests within a test directory are run
  --sub_test <subtest name>              Subtest to run in the test case
  --log <short|full>                     Turn on NSIM logging
  --sai_log <sdk|unspecified|all|max...> Turn on SAI logging

  Environment variables sourced (see Example below):
    DEBUG         or call script with --debug
    OPT           or call script with --opt <value> or --opt3
    USE_CLANG     or call script with --clang

Arguments:
  --test <test filename>                 Test case to run, \"shared/test/api\" is optional
                                         For example,
                                         --test shared/test/api/l2_switch/test_l2_switch_mac_forwarding.py
                                         --test l2_switch/test_l2_switch_mac_forwarding.py
                                         --test sai/test/python/ip_routing/test_basic_router_v4.py
Examples:
  Need to specify -a <asic> if running script from outside driver/<asic> dir
  \$ cd sdk
  \$ $script_name -a pacific --debug --opt 3 --log full --run --test driver/pacific/shared/test/api/bfd/test_ipv6_sh_inject.py
  \$ $script_name -a pacific --debug --opt 3 --log full --run --test shared/test/api/bfd/test_ipv6_sh_inject.py
  \$ $script_name -a pacific --debug --opt 3 --log full --run --test bfd/test_ipv6_sh_inject.py

  No need to specify -a <asic> if running script from driver/<asic> dir
  cd sdk/driver/pacific
  \$ $script_name --debug --opt3 --log full --test bfd/test_ipv6_sh_inject.py
  \$ env DEBUG=1 OPT=3 $script_name --log full --test bfd/test_ipv6_sh_inject.py
"

Usage () {
    echo "$USAGE"
    exit
}

TEMP=$(getopt -o 'h,a:' --long 'help,dryrun,opt:,opt3,debug,clang,run,pdb,gdb,gdbpdb,sai,log:,sai_log:,test:,testdir:,sub_test:' -n 'sim_run.sh' -- "$@")

if [ $? -ne 0 ]; then
        echo 'Terminating...' >&2
        exit 1
fi

eval set -- "$TEMP"
unset TEMP

dryrun=0
sub_test_case=""
test_dir=""
while true; do
        case "$1" in
			'-h'|'--help')
				Usage
				exit
			;;
			'--dryrun')
				dryrun=1
                shift 1
			;;
        	'-a')
				asic_type=$2
				shift 2
                validate_asic_name "$asic_type"
                if [ $? == 0 ]; then
                    msg "Invalid asic \"$asic_type\""
                    exit 1
                fi
			;;
			'--opt')
                if [ -n "$OPT" ]; then
                    msg "OPT already set, either use --opt <value> or --opt3"
                    exit 1
                fi
				OPT=$2
				shift 2
			;;
			'--opt3')
                if [ -n "$OPT" ]; then
                    msg "OPT already set, either use --opt <value> or --opt3"
                    exit 1
                fi
				OPT=3
				shift 1
			;;
			'--debug')
				DEBUG=1
				shift 1
			;;
			'--clang')
				USE_CLANG=1
				shift 1
			;;
			'--run')
				run_type="run"
				shift 1
			;;
			'--pdb')
				run_type="pdb"
				shift 1
			;;
			'--gdb')
				run_type="gdb"
				shift 1
			;;
			'--gdbpdb')
				run_type="gdbpdb"
				shift 1
			;;
			'--log')
				log=$2
				shift 2
			;;
			'--sai')
				sai_run_type="yes"
				shift 1
			;;
			'--sai_log')
				sai_log=$2
				shift 2
			;;
			'--test')
				test_case=$2
				shift 2
			;;
			'--testdir')
				test_dir=$2
				shift 2
			;;
			'--sub_test')
				sub_test_case=$2
				shift 2
				continue
			;;
			'--')
				shift
				break
			;;
			*)
				msg 'Invalid arguments'
				exit 1
			;;
		esac
done

SDK_ROOT=$(find_sdk_root)
if [ -z $SDK_ROOT ] ; then
	msg "SDK root not found" ; exit 1 ;
fi

NPSUITE_DIR=$(find_npsuite_dir)
if [[ "$NPSUITE_DIR" == *"ERROR"* ]]; then
    echo -e "$NPSUITE_DIR"
    exit 1 ;
fi

# NOTE: Update this to your site-specific toolchain location
if [ -d "/common/pkgs/python/3.6.10" ] ; then
    TARGET_PYTHON='/common/pkgs/python/3.6.10/bin/python3.6'
	TARGET_PYTEST='/common/pkgs/python/3.6.10/bin/pytest'
	GCC_LD_LIB='/common/pkgs/gcc/4.9.4/lib64/'
else
	if [ -d "/auto/asic-tools/sw/python/3.6.10" ] ; then
		TARGET_PYTHON='/auto/asic-tools/sw/python/3.6.10/bin/python3.6'
		TARGET_PYTEST='/auto/asic-tools/sw/python/3.6.10/bin/pytest'
	fi
	GCC_LD_LIB='/auto/asic-tools/sw/gcc/4.9.4/lib64:/auto/asic-tools/sw/python/3.6.10/lib'
fi

# Produce base directory name based on OPT, DEBUG and USE_CLANG environment variables
base_dir=""
default_opt="0"
default_debug="1"
default_clang="0"
if [ -z $OPT ] ; then
	OPT=$default_opt
fi
if [ -z $DEBUG ] ; then
	DEBUG=$default_debug
fi
if [ -z $USE_CLANG ] ; then
	USE_CLANG=$default_clang
fi
case "$OPT" in
	'0')
		base_dir="noopt"
	;;
	*)
		base_dir="opt$OPT"
	;;
esac
if [ "$DEBUG" == "1" ] ; then
	base_dir="$base_dir-debug"
fi
if [ "$USE_CLANG" == "1" ] ; then
	base_dir="$base_dir-clang"
fi
if [ -z $run_type ]; then
	run_type="run"
fi

# Determine asic type based on current dir
asic_dir=$(basename $(pwd))
validate_asic_name "$asic_dir"
if [ $? == 0 ]; then
    unset asic_dir
fi

if [ -z $asic_type ] ; then
    if [ -n "$asic_dir" ]; then
        asic_type=$asic_dir
    else
        msg "Specify -a <asic> on command line or run script from driver/asic dir"
        exit 1
    fi
else
    if [ -n "$asic_dir" -a "$asic_dir" != "$asic_type" ]; then
        msg "Mismatch, Asic specified on command line is $asic_type but current asic dir is $asic_dir"
        msg "Script terminated to avoid confusion"
        exit 1
    fi
fi

if [ ! -d "$SDK_ROOT/driver/$asic_type/out/$base_dir" ] ; then
	msg "$SDK_ROOT/driver/$asic_type/out/$base_dir not found"
	msg "Build SDK first for $asic_type"
    exit 1
fi

SDK_LIB_BASE="$SDK_ROOT/driver/$asic_type/out/$base_dir"
SAI_LIB_BASE="$SDK_ROOT/sai/out/$asic_type/$base_dir"

if [ -n "$test_case" -a -n "$test_dir" ]; then
    msg "Both --test and --testdir cannot be specified"
    exit 1 ;
fi

# Make sure test case exists
if [ -z $test_dir ] ; then
    if [ -f "$test_case" ] ; then
        :
    elif [ -f "shared/test/api/$test_case" ]; then
        test_case=shared/test/api/$test_case
    elif [ -f "$SDK_ROOT/$test_case" ] ; then
	    test_case="$SDK_ROOT/$test_case"
    elif [ -f $SDK_ROOT/driver/$test_case ] ; then
        test_case="$SDK_ROOT/driver/$test_case"
    elif [ -f $SDK_ROOT/driver/shared/test/api/$test_case ] ; then
        test_case="$SDK_ROOT/driver/shared/test/api/$test_case"
    else
        msg "Test $test_case not found"
        exit 1 ;
    fi
else
    if [ -d $SDK_ROOT/$test_dir ] ; then
	    test_case="$SDK_ROOT/$test_dir"
    else
	    msg "Test Directory $test_dir is not found"
		exit 1 ;
    fi
fi
msg "TEST: $test_case"

# SDK lib dependency
EXTRA_LD_LIB="$GCC_LD_LIB:$SDK_LIB_BASE/lib:$SDK_LIB_BASE/pylib:$NPSUITE_DIR/lib"
BASE_OUTPUT_DIR="$SDK_LIB_BASE"

SDK_PYTHON_PATH="$SDK_LIB_BASE/lib:$SDK_LIB_BASE/pylib:$SDK_ROOT/driver/shared/test/api:$SDK_ROOT/driver/$asic_type/test/hld"
SDK_PYTHON_PATH="${SDK_PYTHON_PATH}:$SDK_ROOT/driver/$asic_type/test/api:$SDK_ROOT/driver/shared/examples/sanity:$SDK_ROOT/driver/shared/test/utils"

if [ -z $sai_run_type ] ; then
    cd $SDK_ROOT/driver/${asic_type}
fi

# SAI lib dependency
EXTRA_LD_LIB="$EXTRA_LD_LIB:$SAI_LIB_BASE/lib:$SAI_LIB_BASE/pylib"
SDK_PYTHON_PATH="$SDK_PYTHON_PATH:$SDK_ROOT/sai/test/python:$SDK_ROOT/sai:$SAI_LIB_BASE/pylib"
RES_OUTPUT_DIR="$SAI_LIB_BASE/res"

# NSIM lib dependency
nsim_source_path="$SDK_ROOT/npl/cisco_router"
case $asic_type in
	'pacific' )
		nsim_leaba_defined_folder="$SDK_ROOT/devices/$asic_type/leaba_defined"
	;;
	'gibraltar' )
		nsim_leaba_defined_folder="$SDK_ROOT/devices/$asic_type/leaba_defined"
	;;
	'asic3' )
		nsim_leaba_defined_folder="$SDK_ROOT/devices/akpg/$asic_type/leaba_defined"
	;;
	'asic4' )
		nsim_leaba_defined_folder="$SDK_ROOT/devices/akpg/$asic_type/leaba_defined"
	;;
	'asic5' )
		nsim_leaba_defined_folder="$SDK_ROOT/devices/akpg/$asic_type/leaba_defined"
	;;
	*)
		msg 'Invalid ASIC type'
		exit 1
	;;
esac

# ASIC dependency
env_common_string="NSIM_SOURCE_PATH=$nsim_source_path NSIM_LEABA_DEFINED_FOLDER=$nsim_leaba_defined_folder NPSUITE_ROOT=$NPSUITE_DIR"
env_common_string="$env_common_string SDK_ROOT=$SDK_ROOT LD_LIBRARY_PATH=$EXTRA_LD_LIB PYTHONPATH=$SDK_PYTHON_PATH BASE_OUTPUT_DIR=$BASE_OUTPUT_DIR RES_OUTPUT_DIR=$RES_OUTPUT_DIR"
case $asic_type in
	'pacific' )
		env_string="env ASIC=PACIFIC_A0 $env_common_string"
	;;
	'gibraltar' )
		env_string="env ASIC=GIBRALTAR_A0 BOARD_TYPE=blacktip $env_common_string"
	;;
	'asic3' )
		env_string="env ASIC=ASIC3_A0 $env_common_string"
	;;
	'asic4' )
		env_string="env ASIC=ASIC4_A0 $env_common_string"
	;;
	'asic5' )
		env_string="env ASIC=ASIC5_A0 $env_common_string"
	;;
	*)
		msg 'Invalid ASIC type'
		exit 1
	;;
esac

# Logging related options
log_string=""
if [ ! -z $log ] ; then
	case $log in
		short)
			log_string="${log_string} ENABLE_NSIM_LOG=0"
			shift
		;;
		full)
			log_string="${log_string} ENABLE_NSIM_LOG=1"
			shift
		;;
		*)
			msg 'Invalid logging arguments'
			exit 1
		;;
	esac
	env_string="${env_string} ${log_string}"
fi

log_string=""
if [ ! -z $sai_log ] ; then
	log_string="SAI_LOG_${sai_log}=DEBUG SAI_NSIM_RECORD_DIR=${SDK_ROOT}"
	env_string="${env_string} ${log_string}"
fi

if [ ! -z $sai_run_type ] ; then
	TARGET_PYTHON=$TARGET_PYTEST
	if [ ! -z $sai_log ] ; then
       TARGET_PYTHON="$TARGET_PYTHON -s"
	fi
fi

env_string="${env_string} SAI_SKIP_HOSTIF_NETDEV_CREATION=1"

# Execute the test case
case "$run_type" in
	run)
		if [ -z $sub_test_case ] ; then
			cmd_to_run="$env_string $TARGET_PYTHON $test_case -v" ;
		else
			if [ ! -z $sai_run_type ] ; then
				cmd_to_run="$env_string $TARGET_PYTHON $test_case -k $sub_test_case" ;
			else
				cmd_to_run="$env_string $TARGET_PYTHON $test_case $sub_test_case" ;
			fi
		fi
		shift ;;
    gdb)
		cmd_to_run="gdb --args $env_string $TARGET_PYTHON $test_case" ;
    	shift ;;
    pdb)
		if [ ! -z $sai_run_type ] ; then
			cmd_to_run="$env_string $TARGET_PYTHON -vvvs --pdb --trace $test_case" ;
			if [ ! -z $sub_test_case ] ; then
				cmd_to_run="$cmd_to_run -k $sub_test_case"
			fi
		else
    		cmd_to_run="$env_string $TARGET_PYTHON -m pdb $test_case" ;
    	fi
    	shift ;;
    gdbpdb)
		if [ ! -z $sai_run_type ] ; then
			cmd_to_run="gdb --args $env_string $TARGET_PYTHON -vvvs --pdb --trace $test_case" ;
			if [ ! -z $sub_test_case ] ; then
				cmd_to_run="$cmd_to_run -k $sub_test_case"
			fi
		else
    		cmd_to_run="gdb --args $env_string $TARGET_PYTHON -m pdb $test_case" ;
    	fi
    	shift ;;
	*) echo "No run type or invalid run type provided" ; exit 1 ;
esac
msg "$cmd_to_run" ;
if [ $dryrun -eq 0 ]; then
    $cmd_to_run
fi
