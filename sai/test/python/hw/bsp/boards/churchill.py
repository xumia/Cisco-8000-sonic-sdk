# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

"""
Blacktip board class to handle board definitions
"""
from boards.board import BaseBoard
from bsp_c8201_32fh import *
import time
import os


class Churchill(BaseBoard):
    def __init__(self, freq, voltage):
        self.device_core_freq = freq
        self.voltage = voltage

        # bsp platform initialization, this is required before any operation to the devices
        rc = cbsp_platform_init(0)
        if rc:
            print("bsp platform init failed")
            return
        # apply hardware reset sequence to NP Q200
        dev_id = cbsp_devid_get(CBSP_DEV_TYPE_NP, 0)
        rc = cbsp_reset_device(dev_id)
        time.sleep(1)
        os.system("echo 1 > /sys/bus/pci/devices/0000:00:03.1/remove")
        time.sleep(1.5)
        os.system("echo 1 > /sys/bus/pci/rescan")
        time.sleep(1.5)
