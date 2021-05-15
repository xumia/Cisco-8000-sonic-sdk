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
import sim_utils
import topology as T

from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *

from ip_test_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_route_to_pci(unittest.TestCase):
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    TX_SLICE = 2

    SYS_PORT_GID_BASE = 0x123
    AC_PORT_GID_BASE = 0x321

    PRIVATE_DATA = 0x1234567890abcdef
    TTL = 128
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')

    IPV4_INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

    IPV4_EXPECTED_OUTPUT_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1)

    IPV4_INPUT_PACKET, IPV4_EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(
        IPV4_INPUT_PACKET_BASE, IPV4_EXPECTED_OUTPUT_PACKET_BASE)

    def setUp(self):
        self.maxDiff = None  # Show whole strings on failures (unittest variable)

        ac_port_gid = self.AC_PORT_GID_BASE

        self.device = sim_utils.create_device(1)
        self.topology = T.topology(self, self.device, create_default_topology=False)

        self.topology.create_inject_ports()

        # MATILDA_SAVE -- need review
        if (self.TX_SLICE not in self.device.get_used_slices()):
            self.TX_SLICE = T.choose_active_slices(self.device, self.TX_SLICE, [4, 2])

        self.vrf = T.vrf(self, self.device, T.VRF_GID)
        self.switch = T.switch(self, self.device, T.TX_SWITCH_GID)

        # entry ports
        self.rx_eth_port = T.ethernet_port(self, self.device, T.RX_SLICE, T.RX_IFG, self.SYS_PORT_GID_BASE)
        self.rx_l3_ac_port = T.l3_ac_port(self, self.device, ac_port_gid,
                                          self.rx_eth_port, self.vrf, T.RX_L3_AC_MAC, T.RX_L3_AC_PORT_VID1, 0)
        ac_port_gid += 1
        self.rx_l3_ac_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        # exit ports

        self.device.destroy(self.topology.inject_ports[self.TX_SLICE].hld_obj)
        self.tx_eth_port = T.sa_ethernet_port(self, self.device, self.topology.inject_ports[self.TX_SLICE].sys_port)
        self.tx_l2_ac_port = T.l2_ac_port(
            self,
            self.device,
            ac_port_gid,
            None,
            self.switch,
            self.tx_eth_port,
            T.NH_SVI_REG_MAC,
            0,
            0)
        ac_port_gid += 1
        svi_port_gid = ac_port_gid
        self.tx_svi_port = T.svi_port(self, self.device, svi_port_gid, self.switch, self.vrf, T.TX_SVI_MAC)
        self.tx_svi_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        # set routes
        self.nh = T.next_hop(self, self.device, T.NH_L3_AC_REG_GID, T.NH_SVI_REG_MAC, self.tx_svi_port)
        self.prefix = ipv4_test_base.build_prefix(self.DIP, 24)
        self.vrf.hld_obj.add_ipv4_route(self.prefix, self.nh.hld_obj, self.PRIVATE_DATA, False)

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_run(self):
        pci_serdes = self.device.get_pci_serdes()

        U.run_and_compare(self, self.device,
                          self.IPV4_INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.IPV4_EXPECTED_OUTPUT_PACKET, self.TX_SLICE, 0, pci_serdes)


if __name__ == '__main__':
    unittest.main()
