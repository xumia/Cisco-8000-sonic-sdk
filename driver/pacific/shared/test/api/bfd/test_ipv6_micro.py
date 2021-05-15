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

import unittest
from leaba import sdk
from packet_test_utils import *
from scapy.all import *
from bfd_ipv6_base import *
import decor
import topology as T
import ip_test_base
import lldcli


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
class ipv6_micro(bfd_ipv6_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_micro(self):

        run_and_drop(
            self,
            self.device,
            self.INPUT_IPV6_MICRO_PACKET,
            self.s_rx_slice,
            self.s_rx_ifg,
            self.s_first_serdes_p2)

        # Session rx counter is at offset 1
        counter = self.bfd_ipv6_micro_session.get_counter()
        packets, bytes = counter.read(1, True, True)
        self.assertEqual(packets, 1)

        # Now test the path of bringup the member with micro BFD
        # remove the system port from the spa port
        self.m_spa_port.remove(self.m_sys_port2)

        # create a new ethernet port with that system port
        ethernet_port = T.sa_ethernet_port(self, self.device, self.m_sys_port2)

        # create a new l3ac port
        l3_ac = T.l3_ac_port(self,
                             self.device,
                             self.s_l3_ac_new_gid,
                             ethernet_port,
                             self.topology.global_vrf,
                             self.s_rx_mac)
        l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, False)
        l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, False)

        # remove the forus route
        prefix = self.ip_impl.build_prefix(self.s_ipv6_address_forus, length=128)
        self.ip_impl.delete_route(self.topology.vrf, prefix)

        # enable the trap
        counter = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_BFD_MICRO_IP_DISABLED, 0,
                                           counter, self.cpu_punt_dest[3],
                                           False, False, True, 0)
        run_and_compare(self,
                        self.device,
                        self.INPUT_IPV6_MICRO_PACKET,
                        self.s_rx_slice,
                        self.s_rx_ifg,
                        self.s_first_serdes_p2,
                        self.PUNT_PACKET_IPV6_MICRO_DISABLE_IP_PACKET,
                        self.PI_SLICE,
                        self.PI_IFG,
                        self.PI_PIF_FIRST)

        packets, bytes = counter.read(0, True, True)
        self.assertEqual(packets, 1)


if __name__ == '__main__':
    unittest.main()
