#!/usr/bin/env python3
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

import sys
import unittest
from leaba import sdk
from packet_test_utils import *
from scapy.all import *
import sim_utils
import topology as T
from sdk_test_case_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_meter(sdk_test_case_base):
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    METER_SET_SIZE = 1

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        IP()

    INPUT_PACKET, __ = enlarge_packet_to_min_length(INPUT_PACKET_BASE)

    def setUp(self):
        super().setUp()
        # QOS profile
        self.qos_profile = self.device.create_ingress_qos_profile()
        pcpdei0 = sdk.la_vlan_pcpdei()  # init'ed to 0 by ctor
        self.qos_profile.set_metering_enabled_mapping(pcpdei0, True)

        # create port
        self.topology.rx_l2_ac_port.hld_obj.set_ingress_qos_profile(self.qos_profile)

        # create meter
        self.meter_set = T.create_meter_set(self, self.device, set_size=2)

        # attach meter to port
        self.topology.rx_l2_ac_port.hld_obj.set_meter(self.meter_set)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_run(self):
        # profile reset should return EBUSY
        with self.assertRaises(sdk.BusyException):
            self.meter_set.set_meter_profile(1, None)

        with self.assertRaises(sdk.BusyException):
            self.meter_set.set_meter_action_profile(1, None)

        # detach the meter from the port
        self.topology.rx_l2_ac_port.hld_obj.set_meter(None)

        # profile reset should work
        self.meter_set.set_meter_profile(1, None)
        self.meter_set.set_meter_action_profile(1, None)


if __name__ == '__main__':
    unittest.main()
