# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

valid_devices=(pacific gibraltar palladium argon graphene)
valid_devices_choices=$(IFS="|" ; echo "${valid_devices[*]}")

function validate_asic_name()
{
    local asic_type=$1
    for asic in "${valid_devices[@]}"
    do
        if [ "$asic_type" == "$asic" ]; then
           return 1
        fi
    done
    return 0
}

# font_style:
#
# bold    Start bold text
# smul    Start underlined text
# rmul    End underlined text
# rev Start reverse video
# blink   Start blinking text
# invis   Start invisible text
# smso    Start "standout" mode
# rmso    End "standout" mode
# sgr0    Turn off all attributes
# setaf <value>   Set foreground color
# setab <value>   Set background color
#
# font_color:
#
# 0   Black
# 1   Red
# 2   Green
# 3   Yellow
# 4   Blue
# 5   Magenta
# 6   Cyan
# 7   White
# 8   Not used
# 9   Reset to default colo
function msg()
{
    tmp_msg=`date +"%F %r"`
    tmp_msg=`echo [$tmp_msg ${0##/*/}]`

    case "$#" in
        '3')
            font_color=$3
            font_style=$2
            tput setaf $font_color; tput $font_style; echo "$tmp_msg $1"
        ;;
        '2')
            font_style=$2
            org_msg=$1
            tput $font_style; echo "$tmp_msg $1"
        ;;
        '1')
            org_msg=$1
            echo "$tmp_msg $1"
        ;;
        *)
            msg "Missing arguments"
            return 1
    esac
    tput sgr0
}

function find_sdk_root()
{
    # ASSUMPTION: already inside a SDK repository
    # Search upward to find the root of SDK repository
    curr_dir=$PWD
    while [ "$curr_dir" != "/" ];
    do
        if [ -f "$curr_dir/README.BIN" ]; then
            echo $curr_dir
            return
        fi
        curr_dir=$(dirname $curr_dir)
    done
}

function find_npsuite_dir()
{
    if [ -n "$NPSUITE_ROOT" ]; then
        default_npsuite_dir=$(dirname $NPSUITE_ROOT)
    else
        # Check all possible locations for npsuite releases
        default_npsuite_dir=/auto/npsuite/releases
        if [ ! -d $default_npsuite_dir ]; then
            default_npsuite_dir=/cad/leaba/npsuite/releases
            if [ ! -d $default_npsuite_dir ]; then
                default_npsuite_dir=/nobackup/$USER/npsuite
                if [ ! -d $default_npsuite_dir ]; then
                    msg "ERROR: official npsuite not found"
                    return 1
                fi
            fi
        fi
    fi

    sdk_root=$(find_sdk_root)
    if [ -z $sdk_root ]; then
        msg "ERROR: SDK root not found"
        return 1
    fi

    if [ -f "${sdk_root}/build/Makefile.envsetup" ] ; then
        # Newer SDK changed NPSUITE related info
        npsuite_ver=`grep "NPSUITE_VER ?=" ${sdk_root}/build/Makefile.envsetup | sed -e 's/NPSUITE_VER ?= //'`
    else
        # Older SDK has NPSUITE saved in Makefile
        npsuite_ver=`grep "export NPS" Makefile | grep "/auto/" | sed -e 's/.*releases\///'`
        if [ -z $npsuite_ver ]; then
            npsuite_ver=`grep "NPSUITE_VERSION :=" Makefile | sed -e 's/.*\:\= //'`
        fi
    fi
    if [ -z $npsuite_ver ]; then
        msg "ERROR: npsuite version not found"
        return 1
    else
        npsuite_ver="npsuite-$npsuite_ver"
    fi

    if [ ! -d $default_npsuite_dir ]; then
        msg "ERROR: official npsuite not found, dir $default_npsuite_dir does not exist"
        return 1
    fi

    if [ -z "$NPSUITE_ROOT" ]; then
        export NPSUITE_ROOT=$default_npsuite_dir/$npsuite_ver
    else
        if [ "$NPSUITE_ROOT" != "$default_npsuite_dir/$npsuite_ver" ]; then
            msg "ERROR: Env. variable NPSUITE_ROOT does not match Makefile in SDK"
            msg "ERROR: NPSUITE_ROOT=$NPSUITE_ROOT != $default_npsuite_dir/$npsuite_ver"
            return 1
        fi
    fi
    echo $NPSUITE_ROOT
}
