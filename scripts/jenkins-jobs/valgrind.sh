#!/bin/bash -e

# Setup
jenkins_jobs_dir="$(dirname "$(readlink -f "$0")")"
source $jenkins_jobs_dir/jenkins_setup.sh
make_args="-j 12 -l 12 OPT=3 DEBUG=0 VALGRIND_DONT_TRACK_ORIGIN=1 -k"
cd $workspace

usage() {
    echo "usage: $0 -p <platform>"
    echo
    echo "optional args:"
    echo "  -t <lpm|api> (select a subset of make targets)"
    echo
    echo "example:"
    echo "$0 -p pacific -t api"
    echo
}

# Process arguments
while getopts 'p:t:sh' flag; do
    case "${flag}" in
        p) platform="${OPTARG}" ;;
        t) target="${OPTARG}" ;;
        s) SLOW_TEST_FLAG="SKIP_SLOW_TESTS=1 " ;;
        h) usage; exit 0 ;;
        *) echo "Unexpected option \'${flag}\'"; usage; exit 1 ;;
    esac
done

# Verify required args are set
if [[ -z "$platform" ]]; then
    usage
    exit 1
elif [[ "$platform" != "pacific" ]]; then
    echo "$platform unsupported"
    exit 1
fi

if [[ "$target" == "api" ]]; then
    make_target="test-valgrind"
    make_args="${make_args} JENKINS_VALGRIND_RUN=1" #Disables LPM
elif [[ "$target" == "lpm" ]]; then
    make_target="test-hw-tables-lpm-test-valgrind"
else
    make_target="test-valgrind"
fi

$LSF_12C -W 2160 make -C driver/$platform $make_target $SLOW_TEST_FLAG $make_args
