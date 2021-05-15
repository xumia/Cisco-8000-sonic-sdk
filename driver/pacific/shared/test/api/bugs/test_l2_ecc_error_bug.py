#!/usr/bin/env python3
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

from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import interrupt_utils
import decor

VRF_GID = 0x112 if not decor.is_gibraltar() else 0xF12


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Auto restoring of notification pipes after WB not supported.")
class l2_ecc_error(unittest.TestCase):

    def setUp(self):

        self.device = sim_utils.create_device(1)
        self.critical_fd, self.normal_fd = self.device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_check_notifications(self):
        vrf = self.device.create_vrf(VRF_GID)
        crit, norm = interrupt_utils.read_notifications(self.critical_fd, self.normal_fd, .1)
        self.assertEqual(len(crit), 0)
        self.assertEqual(len(norm), 0)


if __name__ == '__main__':
    unittest.main()
