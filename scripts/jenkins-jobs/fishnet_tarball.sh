#!/bin/bash

fnet_tarball="fishnet.tgz"

cd fishnet

# Delete all old logs and tarballs
echo "Deleting previous tarball"
find . -name "*junit.xml" -delete
find . -name "*nsim.log" -delete
find . -name "fishnet*tgz" -delete

set -e
# create local tar of fishnet
echo "Creating new tarball"
tar -czpf ../$fnet_tarball . --exclude=docs
mv ../$fnet_tarball .
readlink -ev ./$fnet_tarball

echo "Success"
exit 0
