#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
from leaba import sdk
from packet_test_utils import *
from ipv6_lpts.ipv6_lpts_base import *
from scapy.all import *
import sim_utils
import topology as T

METER_SET_SIZE = 4
AC_PORT_GID_BASE = 600

IN_SLICE = T.get_device_slice(1)
IN_IFG = 0
IN_SERDES_FIRST = T.get_device_first_serdes(4)
IN_SERDES_LAST = IN_SERDES_FIRST + 1
VLAN = 0xAB9
SYS_PORT_GID_BASE = 23

MAX_L2_AC_PORT = 4096

# CSCvo65115 - crash occurs if meter counters hit OOR and lpts insert w/meter was attempted twice


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_ipv6_lpts_oor_CSCvo65115(ipv6_lpts_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_lpts_oor_CSCvo65115(self):
        lpts = self.create_lpts_instance()
        self.setup_forus_dest()

        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        k1.val.ipv6.protocol = 6
        k1.mask.ipv6.protocol = sdk.la_l4_protocol_e_RESERVED

        result = sdk.la_lpts_result()
        result.flow_type = 11
        result.punt_code = 120
        result.tc = 0
        result.dest = self.punt_dest

        # Create a MAC port
        self.mac_port = T.mac_port(self, self.device, IN_SLICE, IN_IFG, IN_SERDES_FIRST, IN_SERDES_LAST)

        # Create an ethernet port on top of a system port, on top of a MAC port
        self.sys_port = T.system_port(self, self.device, SYS_PORT_GID_BASE, self.mac_port)
        self.eth_port = T.sa_ethernet_port(self, self.device, self.sys_port)

        # Create l2_ac_port meters until meter counter OOR is hit
        with self.assertRaises(sdk.ResourceException):
            for i in range(MAX_L2_AC_PORT):
                ac_port = T.l2_ac_port(
                    self,
                    self.device,
                    AC_PORT_GID_BASE + i,
                    self.topology.filter_group_def,
                    None,
                    self.eth_port,
                    None,
                    VLAN + i,
                    0x0)

                # attach ac_port to the meter set
                ac_port.hld_obj.set_meter(T.create_meter_set(self, self.device, is_aggregate=False, set_size=METER_SET_SIZE))

        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)
        result.meter = T.create_meter_set(self, self.device, is_aggregate=True)
        with self.assertRaises(sdk.ResourceException):
            self.push_lpts_entry(lpts, 0, k1, result)

        with self.assertRaises(sdk.ResourceException):
            self.push_lpts_entry(lpts, 0, k1, result)

        lpts.clear()
        count = lpts.get_count()
        self.assertEqual(count, 0)


if __name__ == '__main__':
    unittest.main()
