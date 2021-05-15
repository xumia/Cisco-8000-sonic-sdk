#! /bin/bash

function usage() {
    echo -e "\nUsage: $(basename $0) <SDK_VER> <port_rw> <port_int>"
    echo Example: $(basename $0) /cad/leaba/sdk/eng/current 9876 9877
    exit 0
}

if [ $# -ne 3 ]; then
    usage
fi

export SDK_VER=$1
export DRIVER=$SDK_VER/driver
export NPL=$SDK_VER/npl/pacific
export NPLAPI_METADATA_FILE=$DRIVER/build/src/ra/npl_tables.json
export NSIM_SOURCE_PATH=$SDK_VER/npl/cisco_router
export NSIM_LEABA_DEFINED_FOLDER=$NPL/leaba_defined
export LD_LIBRARY_PATH=$DRIVER/lib
export PYTHONPATH=$DRIVER/lib:$DRIVER/test/hld

if [ ! -d "$DRIVER" ]; then
    echo Error: "$SDK_VER" does not point to an SDK root
    usage
fi

echo LD_LIBRARY_PATH=$LD_LIBRARY_PATH

cd $(dirname $0)
/common/pkgs/python/3.6.10/bin/python3.6 ./rtl_test_access_engine.py --port_rw $2 --port_int $3
