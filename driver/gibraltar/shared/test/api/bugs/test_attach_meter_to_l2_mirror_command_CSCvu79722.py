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

import unittest
import topology as T
import sim_utils
import decor

DEVICE_ID = 1
MIRROR_CMD_GID = 9

MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET

HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
MIRROR_VLAN = 0xA12


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class attach_meter_to_l2_mirror_command_CSCvu79722(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(DEVICE_ID)
        self.topology = T.topology(self, self.device)
        if not any(self.topology.inject_ports):
            self.topology.create_inject_ports()

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_attach_meter_to_l2_mirror_command(self):

        meter = T.create_meter_set(self, self.device, is_aggregate=True, is_statistical=True)
        pci_port = self.topology.inject_ports[0]

        self.mirror_cmd = T.create_l2_mirror_command(self.device, MIRROR_CMD_EGRESS_GID, pci_port, HOST_MAC_ADDR, MIRROR_VLAN, 1.0)

        self.mirror_cmd.set_meter(meter)
        self.mirror_cmd.set_meter(None)


if __name__ == '__main__':
    unittest.main()
