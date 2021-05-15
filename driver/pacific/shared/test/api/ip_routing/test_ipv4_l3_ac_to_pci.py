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


import decor
import unittest
from leaba import sdk
import packet_test_utils as U
from packet_test_defs import *
import sim_utils
import topology as T

from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *

from ip_test_base import *
from sdk_test_case_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_route_to_pci(sdk_test_case_base):
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    TX_SLICE = T.get_device_slice(2)

    AC_PORT_GID_BASE = 0x321

    PRIVATE_DATA = 0x1234567890abcdef
    TTL = 128
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')

    DST_MAC = T.mac_addr('00:fe:ca:fe:ca:fe')
    SRC_MAC = T.mac_addr('00:ad:de:ad:de:ad')

    IPV4_INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_ONE_TAG_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_ONE_TAG_PORT_VID) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

    IPV4_EXPECTED_OUTPUT_PACKET_BASE = \
        Ether(dst=DST_MAC.addr_str, src=SRC_MAC.addr_str) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1)

    IPV4_INPUT_PACKET, IPV4_EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(
        IPV4_INPUT_PACKET_BASE, IPV4_EXPECTED_OUTPUT_PACKET_BASE)

    def setUp(self):

        super().setUp()
        # MATILDA_SAVE -- need review

        self.TX_SLICE = T.choose_active_slices(self.device, self.TX_SLICE, [4, 2])

        # exit ports
        self.device.destroy(self.topology.inject_ports[self.TX_SLICE].hld_obj)
        self.tx_eth_port = T.sa_ethernet_port(self, self.device, self.topology.inject_ports[self.TX_SLICE].sys_port)
        self.tx_l3_ac_port = T.l3_ac_port(self, self.device, self.AC_PORT_GID_BASE,
                                          self.tx_eth_port, self.topology.vrf, self.SRC_MAC, 0, 0)
        self.tx_l3_ac_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        # set routes
        self.nh = T.next_hop(self, self.device, T.NH_L3_AC_REG_GID + 1, self.DST_MAC, self.tx_l3_ac_port)
        self.prefix = ipv4_test_base.build_prefix(self.DIP, 24)
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.nh.hld_obj, self.PRIVATE_DATA, False)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_run(self):
        pci_serdes = self.device.get_pci_serdes()

        U.run_and_compare(self, self.device,
                          self.IPV4_INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.IPV4_EXPECTED_OUTPUT_PACKET, self.TX_SLICE, 0, pci_serdes)


if __name__ == '__main__':
    unittest.main()
