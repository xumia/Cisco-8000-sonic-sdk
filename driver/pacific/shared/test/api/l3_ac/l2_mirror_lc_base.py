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

import packet_test_utils as U
from lc_base import *
from scapy.all import *
import unittest
from leaba import sdk
import nplapicli
import topology as T

MIRROR_CMD_GID = 0b01010
MIRROR_VLAN = 0xA12

MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET

EGRESS_VLAN = 0x24
TUNNEL_TTL = 255
TUNNEL_DSCP = 46
TRAFFIC_CLASS = 0
TUNNEL_DEST = T.ipv4_addr('192.168.1.1')
TUNNEL_SOURCE = T.ipv4_addr('192.168.2.2')
SESSION_ID = 0x3ff


class l2_mirror_lc_base(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(INGRESS_DEVICE_ID, slice_modes=sim_utils.LINECARD_3N_3F_DEV)

        self.topology = T.topology(self, self.device, create_default_topology=False)

        self.create_packets()

    def tearDown(self):
        self.device.tearDown()

    def create_packets(self):
        self.ingress_rx_pkt = \
            Ether(dst=IN_L3_AC_PORT_MAC, src=SRC_MAC, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            TCP()

        self.ingress_tx_pkt = \
            TS_PLB(header_type="ONE_PKT_TS3",
                   link_fc=0,
                   fcn=0,
                   plb_context="UC_L",
                   ts3=[0, 0, 0],
                   src_device=INGRESS_DEVICE_ID,
                   src_slice=INGRESS_RX_SLICE,
                   reserved=0) / \
            TM(header_type="UUU_DD",
               vce=0,
               tc=0,
               dp=0,
               reserved=0,
               dest_device=EGRESS_DEVICE_ID,
               dest_slice=EGRESS_TX_SLICE,
               dest_oq=T.topology.get_oq_num(EGRESS_TX_IFG, EGRESS_TX_SERDES_FIRST)) / \
            self.npu_header_per_device() / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            TCP()

        self.ingress_tx_l2_mirror_pkt = \
            TS_PLB(header_type="ONE_PKT_TS3",
                   link_fc=0,
                   fcn=0,
                   plb_context="UC_L",
                   ts3=[0, 0, 0],
                   src_device=INGRESS_DEVICE_ID,
                   src_slice=INGRESS_RX_SLICE,
                   reserved=0) / \
            TM(header_type="UUU_DD",
               vce=0,
               tc=0,
               dp=0,
               reserved=0,
               dest_device=EGRESS_DEVICE_ID,
               dest_slice=EGRESS_TX_SLICE,
               dest_oq=T.topology.get_oq_num(EGRESS_TX_IFG, EGRESS_TX_SERDES_FIRST)) / \
            self.npu_header_per_device(mirror_pkt=True) / \
            NPU_Soft_Header(unparsed_0=0x000000000000b017) / \
            Ether(dst=IN_L3_AC_PORT_MAC, src=SRC_MAC, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            TCP()

        self.egress_rx_pkt = self.ingress_tx_pkt
        self.egress_rx_l2_mirror_pkt = self.ingress_tx_l2_mirror_pkt
        self.egress_tx_pkt = \
            Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                  src=OUT_L3_AC_PORT_MAC,
                  type=Ethertype.IPv4.value) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1) / \
            TCP()
        self.egress_tx_l2_mirror_pkt = \
            Ether(dst=IN_L3_AC_PORT_MAC,
                  src=SRC_MAC,
                  type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1,
                  type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=SIP.addr_str,
               dst=DIP.addr_str,
               ttl=TTL) / \
            TCP()

    def npu_header_per_device(self, mirror_pkt=False):
        lldev = self.device.device.get_ll_device()

        if lldev.is_pacific():
            if mirror_pkt:
                return NPU_Header(unparsed_0=0x1000000000000002,   # The NPU header data is arbitrary and taken as-is from the actual packet
                                  unparsed_1=0xc8c5f28e0a000000,
                                  unparsed_2=0x0011e0a00,
                                  unparsed_3=0x1ff0000a003ee)
            else:
                return NPU_Header(unparsed_0=0x1000000000000002,   # The NPU header data is arbitrary and taken as-is from the actual packet
                                  unparsed_1=0xc8c5f20300b000c0,
                                  unparsed_2=0x500,
                                  unparsed_3=0x1ff0000a003ee)
        elif lldev.is_gibraltar():
            if mirror_pkt:
                return NPU_Header(unparsed_0=0x1000000000000002,   # The NPU header data is arbitrary and taken as-is from the actual packet
                                  unparsed_1=0x1265f28e0a000000,
                                  unparsed_2=0x0011e0a00,
                                  unparsed_3=0x1ff0000a003ee)
            else:
                return NPU_Header(unparsed_0=0x1000000000000002,   # The NPU header data is arbitrary and taken as-is from the actual packet
                                  unparsed_1=0x1265f20300b000c0,
                                  unparsed_2=0x500,
                                  unparsed_3=0x1ff0000a003ee)
        else:
            raise Exception('Unknown device revision')
