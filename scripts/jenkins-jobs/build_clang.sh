#!/bin/bash -e

# Setup
jenkins_jobs_dir="$(dirname "$(readlink -f "$0")")"
source $jenkins_jobs_dir/jenkins_setup.sh
cd $workspace

$LSF_8C -W 480 make -C driver -j 8 -l 8 OPT=3 DEBUG=0 USE_CLANG=1
rm -rf driver/*/out/opt3-debug-clang
