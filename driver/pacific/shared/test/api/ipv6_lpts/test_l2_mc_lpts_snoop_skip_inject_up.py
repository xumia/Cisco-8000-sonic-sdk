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

import unittest
from leaba import sdk
from packet_test_utils import *
from ipv6_lpts_base import *
from scapy.all import *
import sim_utils
import decor
import topology as T
import ip_test_base


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_mc_lpts(ipv6_lpts_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_mc_snoop_lpts(self):
        lpts = self.create_lpts_instance()
        self.setup_forus_dest()

        self.setup_l2_mc_snoop(True)

        self.l2_ac_port_for_inject = T.l2_ac_port(
            self, self.device,
            T.TX_L2_AC_PORT_DEF_GID + 10,
            None,
            self.topology.rx_switch,
            self.topology.tx_svi_eth_port_def,
            T. NH_SVI_DEF_MAC,
            T.RX_L2_AC_PORT_VID1,
            T.RX_L2_AC_PORT_VID2)

        INJECT_UP_PACKET = \
            Ether(dst=T.INJECT_PORT_MAC_ADDR, src=HOST_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=PUNT_VLAN, type=Ethertype.Inject.value) / \
            InjectUp(ssp_gid=T.TX_SVI_SYS_PORT_DEF_GID) / \
            INPUT_PACKET_ND_MC_SVI

        ingress_packet = {'data': INJECT_UP_PACKET, 'slice': T.TX_SLICE_DEF, 'ifg': T.PI_IFG, 'pif': self.device.get_pci_serdes()}
        expected_packets = []
        # expected_packets.append({'data': PUNT_PACKET_ND_MC_SVI_SNOOP, 'slice': INJECT_SLICE,
        #                         'ifg': INJECT_IFG, 'pif': INJECT_PIF_FIRST})
        expected_packets.append({'data': INPUT_PACKET_ND_MC_SVI, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)


if __name__ == '__main__':
    unittest.main()
