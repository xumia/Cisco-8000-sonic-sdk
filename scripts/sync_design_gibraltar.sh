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


##############################################################################################
# Copy LBR and defines files from design repo to devices folder
#
# Usage example: The below command will copy relevant LBR files from the Perforce local 
#                working set (at ~/p4 in this example) into the devices folder in the SDK
#                local working set. If the letter 'R' is given as the 3rd parameter then the
#                README file in the SDK devices LBR folder will be updated with the Perforce
#                revision.
#    sync_design_gibraltar.sh ~/p4/asic/cagbb/gibraltar/trunk/design ~/sdk/devices/gibraltar R
##############################################################################################

if [ $# -lt 2 ]; then
    echo 'Usage: sync_lbrs.sh <Path to design repo files> <Path to devices folder> [R]'
    exit 2
fi
design_folder=$1
devices_folder=$2

# copy lbr files
devices_lbr_folder=$devices_folder/lbr.pd_ver_2.0
local_lbrs=`find $devices_lbr_folder -type f -name \*.lbr`
for local_lbr_file_full_path in $local_lbrs; do

    # skip unused_lbr subfolder
    if [[ "$local_lbr_file_full_path" == *"unused_lbr"* ]]; then
        continue
    fi

    #skip sbif_db.lbr
    if [[ "$local_lbr_file_full_path" == *"sbif_db.lbr"* ]]; then
        continue
    fi

    # copy the lbr file from design to devices
    local_lbr_file_rel_path=${local_lbr_file_full_path#$devices_lbr_folder}
    design_lbr_file_path=$design_folder$local_lbr_file_rel_path
    cp $design_lbr_file_path $local_lbr_file_full_path
done

echo LBR files copied

# copy defines files
devices_define_folder=$devices_folder/defines.pd_ver_2.0
local_defines=`find $devices_define_folder -type f -name \*.v`
for local_define_full_path in $local_defines; do
    relative_define_path=${local_define_full_path#$devices_define_folder}
    design_define_path=$design_folder/defines/$relative_define_path
    cp $design_define_path $local_define_full_path
done

echo Define files copied

# if 3 parameter is 'R' then update the README file with the design revision
# it requires that 
#   1) the design folder is a perforce client workspace
#   2) the shell in which this script runs can execute p4 commands
#      a) run 'module load /common/cadhome/modulefiles/eda/perforce/2017.1'
#      b) follow instructions at https://asic-web.cisco.com/twiki/bin/view/CAG/InfraPerforceBasics
if [ $# -gt 2 ]; then
    if [ $3 == "R" ]; then
        devices_readme_file=`realpath $devices_folder/README`
        if ! pushd `realpath $design_folder`; then
            echo "Cannot change directory to design repo folder \"$design_folder\""
            exit 1
        fi
        mv -f $devices_readme_file ${devices_readme_file}.orig
        cmd='p4 changes -m 1 ./...#have'
        $cmd > $devices_readme_file
        popd
    fi
fi



echo Done

