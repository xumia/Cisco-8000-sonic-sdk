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
import decor
import topology as T
import decor

MC_GROUP_ID = 0x10010
MC_GROUP_ADDR = 'FF31:0123:4567:89AB:CDEF::2222'
MC_DEST_MAC = '33:33:00:00:22:22'
MC_SIP = '8000:FEDC:BA98:7654:3210::2'
MC_TEST_THRESHOLD = 4096
MC_FABRIC_MCID = 0xffff


class lc_multicast_v6_base(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(INGRESS_DEVICE_ID, slice_modes=sim_utils.LINECARD_3N_3F_DEV)

        self.topology = T.topology(self, self.device, create_default_topology=False)

        self.mc_group_addr = T.ipv6_addr(MC_GROUP_ADDR)
        self.mc_sip = T.ipv6_addr(MC_SIP)

        self.topology.create_inject_ports()
        self.device.set_is_fabric_time_master(True)

        self.create_packets()

    def tearDown(self):
        # Reset the multicast scale threshold to free the recycle port
        self.device.set_int_property(sdk.la_device_property_e_MULTICAST_MCID_SCALE_THRESHOLD, (1 << 16))

        self.device.tearDown()

    def create_packets(self):
        TTL = 64
        lb_key = 0xa2c4  # pacific load balance key

        if decor.is_gibraltar():
            lb_key = 0x9a16  # gibraltar load balance key

        ingress_rx_pkt_base = Ether(dst=MC_DEST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN) / \
            IPv6(dst=MC_GROUP_ADDR, src=MC_SIP, hlim=TTL) / TCP()

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
               multicast_id=MC_FABRIC_MCID) / \
            NPU_Header_ext(base_type="NPU_NO_IVE",          # NPU Header data is taken from the actual packet produced by LC NSIM.
                           fwd_header_type="IPV6",
                           fwd_qos_tag=0x00,                # All values below were not analized for semantic meaning,
                           lb_key=lb_key,                   # they are just pasted from a decoded packet.
                           slp_qos_id=15,
                           encap_type=0,
                           encap=0x0,
                           punt_mc_expand_encap=MC_GROUP_ID,
                           ipv4_first_fragment=1,
                           ttl=TTL,
                           fwd_slp_info=0xa0,
                           fwd_relay_id=0) / \
            IPv6(dst=MC_GROUP_ADDR, src=MC_SIP) / TCP()

        egress_tx_pkt_base = Ether(dst=MC_DEST_MAC, src="40:41:42:43:44:45") / \
            IPv6(dst=MC_GROUP_ADDR, src=MC_SIP, hlim=(TTL - 1)) / TCP()

        self.ingress_rx_pkt, base_input_packet_payload_size = enlarge_packet_to_min_length(ingress_rx_pkt_base)
        self.ingress_tx_pkt = add_payload(ingress_tx_pkt_base, base_input_packet_payload_size)
        self.egress_rx_pkt = self.ingress_tx_pkt
        self.egress_tx_pkt = add_payload(egress_tx_pkt_base, base_input_packet_payload_size)
