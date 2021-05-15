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

###
# Implement of L2 P2P snake test
###

from leaba import sdk

import network_objects
from sanity_constants import *


class snake_routing_topology:
    BASE_VID1 = 0x700
    AC_PORT_BASE_GID = 0x510
    VRF_BASE_GID = 0x110
    NH_BASE_GID = 0x0
    USER_DATA = 0

    def __init__(self, la_dev):
        self.la_dev = la_dev
        self.reset()

    def reset(self):
        self.ac_ports = []
        self.vrfs = []
        self.nhs = []
        self.fecs = []

    @staticmethod
    def apply_ipv4_prefix_mask(addr_num, prefix_length):
        mask = ~((1 << (CHAR_BIT * BYTES_NUM_IN_IPv4_ADDR - prefix_length)) - 1)
        masked_addr_num = addr_num & mask
        return masked_addr_num

    @staticmethod
    def build_ipv4_prefix(dip, length):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = snake_routing_topology.apply_ipv4_prefix_mask(dip.to_num(), length)
        prefix.length = length
        return prefix

    def initialize(self, base_topology, dst, src, dip):

        prefix_length = 24
        prefix = self.build_ipv4_prefix(dip, prefix_length)

        for i in range(base_topology.mac_ports_num):

            # Create Rx AC port
            vrf = None
            rx_ac_port = None
            tx_ac_port = None
            fec = None
            nh = None

            rx_vid1 = snake_routing_topology.BASE_VID1 + i * 2
            tx_vid1 = snake_routing_topology.BASE_VID1 + i * 2 + 1

            if i < base_topology.loopback_num + 1:
                (status, vrf) = self.la_dev.create_vrf(snake_routing_topology.VRF_BASE_GID + i)
                if (status != sdk.LA_STATUS_SUCCESS) or (vrf is None):
                    raise Exception('Error: create_vrf failed. status=%d i=%d' % (status, i))

                (status, rx_ac_port) = self.la_dev.create_l3_ac_port(snake_routing_topology.AC_PORT_BASE_GID + i * 2,
                                                                     base_topology.eth_ports[i],
                                                                     rx_vid1,
                                                                     0,  # vid2
                                                                     dst.hld_obj,
                                                                     vrf,
                                                                     network_objects.ingress_qos_profile_def.hld_obj,
                                                                     network_objects.egress_qos_profile_def.hld_obj,
                                                                     sdk.la_egress_qos_marking_source_e_QOS_TAG)
                if (status != sdk.LA_STATUS_SUCCESS) or (rx_ac_port is None):
                    raise Exception('Error: create_l3_ac_port failed. status=%d i=%d' % (status, i))

                status = rx_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
                if status != sdk.LA_STATUS_SUCCESS:
                    raise Exception('Error: set_protocol_enabled failed. status=%d i=%d' % (status, i))

            if i > 0:
                (status, tx_ac_port) = self.la_dev.create_l3_ac_port(snake_routing_topology.AC_PORT_BASE_GID + i * 2 + 1,
                                                                     base_topology.eth_ports[i],
                                                                     tx_vid1,
                                                                     0,  # vid2
                                                                     src.hld_obj,
                                                                     self.vrfs[-1],
                                                                     network_objects.ingress_qos_profile_def.hld_obj,
                                                                     network_objects.egress_qos_profile_def.hld_obj,
                                                                     sdk.la_egress_qos_marking_source_e_QOS_TAG)
                if (status != sdk.LA_STATUS_SUCCESS) or (tx_ac_port is None):
                    raise Exception('Error: create_l3_ac_port failed. status=%d i=%d' % (status, i))

                status = tx_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
                if status != sdk.LA_STATUS_SUCCESS:
                    raise Exception('Error: set_protocol_enabled failed. status=%d i=%d' % (status, i))

                # Create the L3 destination to the L3 AC port
                (status, nh) = self.la_dev.create_next_hop(snake_routing_topology.NH_BASE_GID +
                                                           i, dst.hld_obj, tx_ac_port, sdk.la_next_hop.nh_type_e_NORMAL)
                if (status != sdk.LA_STATUS_SUCCESS) or (nh is None):
                    raise Exception('Error: create_next_hop failed. status=%d i=%d' % (status, i))

                (status, fec) = self.la_dev.create_l3_fec(nh)
                # Set the route from the previous port to the current one
                prev_vrf = self.vrfs[i - 1]
                status = prev_vrf.add_ipv4_route(prefix, fec, snake_routing_topology.USER_DATA, False)
                if status != sdk.LA_STATUS_SUCCESS:
                    raise Exception('Error: add_ipv4_route failed. status=%d i=%d' % (status, i))

                # Increment VLAN tag
                tag = sdk.la_vlan_tag_t()
                tag.tpid = TPID_Dot1Q
                tag.tci.fields.vid = rx_vid1
                status = tx_ac_port.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)
                if status != sdk.LA_STATUS_SUCCESS:
                    raise Exception('Error: set_egress_vlan_tag failed. status=%d i=%d' % (status, i))

            # Store all objects that need to be destroyed later
            if rx_ac_port is not None:
                self.ac_ports.append(rx_ac_port)
            if tx_ac_port is not None:
                self.ac_ports.append(tx_ac_port)
            if vrf is not None:
                self.vrfs.append(vrf)
            if fec is not None:
                self.fecs.append(fec)
            if nh is not None:
                self.nhs.append(nh)

        self.la_dev.flush()

    def teardown(self):
        for vrf in self.vrfs:
            status = self.la_dev.destroy(vrf)
            if status != sdk.LA_STATUS_SUCCESS:
                raise Exception('destroy failed. status=%d' % status)
        for fec in self.fecs:
            status = self.la_dev.destroy(fec)
            if status != sdk.LA_STATUS_SUCCESS:
                raise Exception('destroy failed. status=%d' % status)
        for nh in self.nhs:
            status = self.la_dev.destroy(nh)
            if status != sdk.LA_STATUS_SUCCESS:
                raise Exception('destroy failed. status=%d' % status)
        for ac_port in self.ac_ports:
            status = self.la_dev.destroy(ac_port)
            if status != sdk.LA_STATUS_SUCCESS:
                raise Exception('destroy failed. status=%d' % status)

        self.la_dev.flush()
        self.reset()
