#!/bin/bash -e
set -x

LIB=/cad/leaba/sdk/eng/current/driver/lib
env LD_LIBRARY_PATH=$LIB PYTHONPATH=$LIB /common/pkgs/python/3.6.10/bin/python3.6 -i ./load_and_run_firmware.py $*
