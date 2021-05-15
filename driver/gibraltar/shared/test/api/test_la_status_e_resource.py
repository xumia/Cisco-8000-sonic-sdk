#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import decor
import unittest
from leaba import sdk as sdk
from sdk_test_case_base import *
import topology as T
import sim_utils

HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
MIRROR_CMD_GID = 9
MIRROR_VLAN = 0xA12
PUNT_SLICE = T.get_device_slice(2)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not enabled on GR-HW")
class la_status_e_resource(sdk_test_case_base):

    def test_la_status_e_resource(self):
        sampling_rate = 1.0
        self.mirror_cmd = T.create_l2_mirror_command(
            self.device,
            MIRROR_CMD_GID,
            self.topology.inject_ports[PUNT_SLICE],
            HOST_MAC_ADDR,
            MIRROR_VLAN,
            sampling_rate)
        priority = 0

        with self.assertRaises(sdk.ResourceException) as e:
            for idx in range(sdk.LA_EVENT_ETHERNET_FIRST, sdk.LA_EVENT_SVL_LAST):
                self.device.set_snoop_configuration(idx, priority, False, False, self.mirror_cmd)

        STATUS = e.exception
        self.assertEqual(STATUS.status.get_info().type, sdk.la_status_info.type_e_E_RESOURCE_TABLE)
        msg = STATUS.status.get_info().message()  # Call message() to make sure its implemented
        self.assertGreater(len(msg), 0)


if __name__ == '__main__':
    unittest.main()
