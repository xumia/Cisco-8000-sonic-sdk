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


from scapy.all import *
from l3_protection_group.l3_protection_group_base import *
import sys
import unittest
from leaba import sdk
import ip_test_base
import sim_utils
import topology as T
import packet_test_utils as U
import decor

U.parse_ip_after_mpls()

# CSCvo49813
# Calling set_nh_lsp_properties on a te_tunnel using a counter freed
# via clear_nh_lsp_properties fails in some cases


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class tunnel_counter_reuse_after_clear_CSCvo49813(l3_protection_group_base):

    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl_class = ip_test_base.ipv4_test_base
    DIP = T.ipv4_addr('82.81.95.250')

    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR - it only has one ifg")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_tunnel_counter_reuse_after_clear_CSCvo49813(self):
        prot_monitor = T.protection_monitor(self, self.device)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            self.PROTECTION_GROUP_ID,
            self.l3_port_impl.reg_nh.hld_obj,
            self.l3_port_impl.ext_nh.hld_obj,
            prot_monitor.hld_obj)

        te_tunnel = T.te_tunnel(self, self.device, l3_protection_group_base.TE_TUNNEL1_GID, l3_prot_group.hld_obj)

        # Issue only occurs in case where interfaces are on same slice, but different ifg
        mac_port1 = T.mac_port(self, self.device, 2, 0, 14, 15)
        mac_port2 = T.mac_port(self, self.device, 2, 1, 8, 9)

        sys_port1 = T.system_port(self, self.device, 0x10, mac_port1)
        sys_port2 = T.system_port(self, self.device, 0x20, mac_port2)

        spa_port = T.spa_port(self, self.device, 0x40)

        spa_port.add(sys_port1)
        spa_port.add(sys_port2)

        eth_port = T.sa_ethernet_port(self, self.device, spa_port)
        mac_addr = T.mac_addr('71:72:73:74:25:76')
        l3_ac_port = T.l3_ac_port(self, self.device, 0x50, eth_port, self.topology.vrf, mac_addr)
        nh = T.next_hop(self, self.device, 0x60, mac_addr, l3_ac_port)

        te_counter_primary = self.device.create_counter(1)
        te_labels = []

        te_tunnel.hld_obj.set_nh_lsp_properties(nh.hld_obj, te_labels, te_counter_primary)
        te_tunnel.hld_obj.set_ipv6_explicit_null_enabled(True)

        spa_port.remove(sys_port1)
        spa_port.remove(sys_port2)

        te_tunnel.hld_obj.clear_nh_lsp_properties(nh.hld_obj)

        te_counter_backup = self.device.create_counter(1)
        te_labels = []

        te_tunnel.hld_obj.set_nh_lsp_properties(self.l3_port_impl.ext_nh.hld_obj, te_labels, te_counter_primary)


if __name__ == '__main__':
    unittest.main()
