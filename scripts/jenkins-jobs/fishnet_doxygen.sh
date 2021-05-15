#!/bin/bash -e

# Compiles and uploads doxygen statistics to fishnet.cisco.com
publish="false"

usage() {
    echo "usage: $0"
    echo
    echo "There are no args at this time"
}

# Process arguments
while getopts 'h' flag; do
    case "${flag}" in
        h) usage; exit 0 ;;
        *) echo "Unexpected option \'${flag}\'"; usage; exit 1 ;;
    esac
done

# Compile
export DOT_PATH=/auto/asic-tools/sw/graphviz/2.38.0/bin/
export LD_LIBRARY_PATH=/auto/asic-tools/sw/graphviz/2.38.0/lib:$LD_LIBRARY_PATH
echo "Compiling Doxygen files..."
rm -rf fishnet/docs/html
/auto/asic-tools/sw/doxygen/1.8.10/bin/doxygen fishnet/scripts/doxyFile

if [[ "$GIT_BRANCH" == "master" ]]; then
    # Publish statistics to /auto mount
    echo "Publishing..."
    rm -rf /auto/fishnet-web/fishnet/doxygen/*
    cp -R fishnet/docs/html/* /auto/fishnet-web/fishnet/doxygen/
    chmod 775 -R /auto/fishnet-web/fishnet/doxygen/*
fi

echo "Done"
