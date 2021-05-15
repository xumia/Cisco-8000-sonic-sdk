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

export PATH=$PATH:/usr/sbin/
export LD_LIBRARY_PATH=out/noopt-debug/lib
export PYTHONPATH=out/noopt-debug/lib

PYTHON=/common/pkgs/python/3.6.10/bin/python3

for t in p2p bridging routing; do
    for l in `seq 0 107`; do
        for s in `seq 0 5`; do
            for i in `seq 0 1`; do
                for p in `seq 0 2 16`; do
                    cmd="$PYTHON  examples/sanity/test/sanity_test.py -c bridging -c p2p -c routing -t $t -l $l -s=$s -i=$i -p=$p"
                    echo $cmd
                    $cmd
                    if [ $? -ne 0 ]; then
                        echo FAIL
                        exit 2
                    fi
                done
            done
        done
    done
done

for v in `seq 2048 2155`; do
    for s in `seq 0 5`; do
        for i in `seq 0 1`; do
            for p in `seq 0 2 16`; do
                cmd="$PYTHON  examples/sanity/test/sanity_test.py -c board-p2p -t board-p2p -v $v -s=$s -i=$i -p=$p"
                echo $cmd
                $cmd
                if [ $? -ne 0 ]; then
                    echo FAIL
                    exit 2
                fi
            done
        done
    done
done


echo PASS
