#!/usr/bin/env python3
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


import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
from sdk_test_case_base import *
import sim_utils
import warm_boot_test_utils as wb
import ip_test_base
import os
import decor

SA = T.mac_addr('be:ef:5d:35:7a:35')
SIP = T.ipv4_addr('12.10.12.10')
DIP = T.ipv4_addr('82.81.95.250')
PRIVATE_DATA = 0x1234567890abcdef
TTL = 128


wb.enable_auto_warm_boot()
# allow max 2 WB invocations for the same SDK method
wb.MAX_WB_INVOCATIONS_PER_SDK_METHOD = 2


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_valgrind(), "Skip due to long valgrind run")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
@unittest.skipUnless(decor.is_pacific() or decor.is_gibraltar(), "WB is currently supported by GB and PAC only")
class auto_warm_boot_l3_ac_routing(unittest.TestCase):

    def test_auto_warm_boot_ipv4_l3_ac_routing(self):
        # create topology in test function, not in setUpClass()/setUp() because SDK
        # mutator function don't trigger WB if called from setUpClass()/setUp()
        device = sim_utils.create_device(1)
        topology = T.topology(self, device, create_default_topology=True)

        l3_port_impl_class = T.ip_l3_ac_base
        l3_port_impl = l3_port_impl_class(topology)

        ip_impl = ip_test_base.ipv4_test_base
        subnet = ip_impl.build_prefix(DIP, length=16)

        ip_impl.add_subnet(l3_port_impl.tx_port, subnet)
        ip_impl.add_host(l3_port_impl.tx_port, DIP, l3_port_impl.reg_nh.mac_addr)

        input_packet_base = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

        output_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1)

        input_packet, output_packet = U.pad_input_and_output_packets(input_packet_base, output_packet_base)

        U.run_and_compare(
            self,
            device,
            input_packet,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            output_packet,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            l3_port_impl.serdes_reg)

        device.tearDown()


if __name__ == '__main__':
    unittest.main()
