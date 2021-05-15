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

from packet_test_utils import *
from lc_base import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T

MC_GROUP_ID = 0x15


class lc_l2_switch_mc_base(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(INGRESS_DEVICE_ID, slice_modes=sim_utils.LINECARD_3N_3F_DEV)

        self.topology = T.topology(self, self.device, create_default_topology=False)

        self.create_packets()

    def tearDown(self):
        self.device.tearDown()

    def create_packets(self):
        ingress_rx_pkt_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN) / \
            IP() / TCP()

        ingress_tx_pkt_base = \
            TS_PLB(header_type="ONE_PKT_TS3",       # Single packet, 3 timestamps
                   fcn=0,                           # Forward congestion notification
                   link_fc=0,                       # Link FC
                   plb_context="MC",                # Multicast
                   ts3=[0, 0, 0],                    # Inject fabric time
                   src_device=INGRESS_DEVICE_ID,
                   src_slice=INGRESS_RX_SLICE,
                   reserved=0) / \
            TM(header_type="MMM",               # All Multicast (ingress/fabric/egress)
               vce=0,                           # VOQ congestion experienced flag
               tc=0,                            # Traffic class
               dp=0,                            # DP?
               multicast_id=MC_GROUP_ID) / \
            NPU_Header_ext(base_type="NPU_NO_IVE",          # NPU Header data is taken from the actual packet produced by LC NSIM.
                           fwd_header_type="ETHERNET",
                           fwd_qos_tag=0x40,                # All values below were not analized for semantic meaning,
                           lb_key=0xe5de,                   # they are just pasted from a decoded packet.
                           slp_qos_id=15,
                           encap_type=8,
                           encap=0xa019000000000000,
                           ipv4_first_fragment=1,
                           fwd_slp_info=0x8000a,
                           fwd_relay_id=100) / \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN) / \
            IP() / TCP()

        egress_tx_pkt_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN) / \
            IP() / TCP()

        self.ingress_rx_pkt, base_input_packet_payload_size = enlarge_packet_to_min_length(ingress_rx_pkt_base)
        self.ingress_tx_pkt = add_payload(ingress_tx_pkt_base, base_input_packet_payload_size)
        self.egress_rx_pkt = self.ingress_tx_pkt
        self.egress_tx_pkt = add_payload(egress_tx_pkt_base, base_input_packet_payload_size)
