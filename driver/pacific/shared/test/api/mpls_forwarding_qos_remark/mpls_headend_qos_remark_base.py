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

from scapy.all import *
import sys
import unittest
from leaba import sdk
import ip_test_base
import sim_utils
import topology as T
import packet_test_utils as U

U.parse_ip_after_mpls()


class mpls_headend_qos_remark_base:
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')

    PREFIX1_GID = 0x691
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    LDP_LABEL = sdk.la_mpls_label()
    LDP_LABEL.label = 0x64
    IP_TTL = 0x88
    MPLS_TTL = 0xff
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    IN_IP_DSCP = sdk.la_ip_dscp()
    IN_IP_DSCP.value = 20

    IN_OUTER_PCPDEI = sdk.la_vlan_pcpdei()
    IN_OUTER_PCPDEI.fields.pcp = 2
    IN_OUTER_PCPDEI.fields.dei = 1

    IN_PCPDEI = sdk.la_vlan_pcpdei()
    IN_PCPDEI.fields.pcp = 5
    IN_PCPDEI.fields.dei = 0

    IN_MPLS_TC = sdk.la_mpls_tc()
    IN_MPLS_TC.value = 5

    TAG_MPLS_TC = sdk.la_mpls_tc()
    TAG_MPLS_TC.value = 2

    OUT_MPLS_TC = sdk.la_mpls_tc()
    OUT_MPLS_TC.value = 4

    # QoS color list
    COLOR_LST = [sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_RED]

    my_device = None

    @classmethod
    def initialize_device(cls):
        mpls_headend_qos_remark_base.my_device = U.sim_utils.create_device(1)

    @classmethod
    def destroy_device(cls):
        mpls_headend_qos_remark_base.my_device.tearDown()

    def setUp(self):
        # Basic initialization
        self.device = mpls_headend_qos_remark_base.my_device
        self.topology = T.topology(self, self.device)
        self.ip_impl_class = ip_test_base.ipv4_test_base
        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl_class = T.ip_l3_ac_base
        self.l3_port_impl = self.l3_port_impl_class(self.topology)

        # Create and set counter
        self.egress_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.egress_counter)

        # Configure routes
        self.configure_ip_to_mpls()

        # Assign new profiles
        self.rx_port = self.topology.rx_l3_ac
        self.tx_port = self.topology.tx_l3_ac_reg

    def configure_ip_to_mpls(self):
        pfx_obj = T.prefix_object(self, self.device, mpls_headend_qos_remark_base.PREFIX1_GID, self.l3_port_impl.reg_nh.hld_obj)

        lsp_labels = []
        lsp_labels.append(mpls_headend_qos_remark_base.LDP_LABEL)

        # This uses a prefix object with no associated counter. For usage of lsp counter, check ecmp test.
        pfx_obj.hld_obj.set_nh_lsp_properties(self.l3_port_impl.reg_nh.hld_obj, lsp_labels,
                                              None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(mpls_headend_qos_remark_base.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               mpls_headend_qos_remark_base.PRIVATE_DATA_DEFAULT)
