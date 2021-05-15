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

import sys
import unittest
from leaba import sdk
from scapy.all import *
import sim_utils
import topology as T
import packet_test_utils as U
from sdk_test_case_base import *
import ip_test_base

U.parse_ip_after_mpls()
load_contrib('mpls')


class ecn_voq_set_base(sdk_test_case_base):
    DIP = T.ipv4_addr('82.81.95.250')
    PRIVATE_DATA = 0x1234567890abcdef

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            device.set_bool_property(sdk.la_device_property_e_ENABLE_ECN_QUEUING, True)

    @classmethod
    def setUpClass(cls):
        super(ecn_voq_set_base, cls).setUpClass(
            device_config_func=ecn_voq_set_base.device_config_func)

    def setUp(self):
        super().setUp()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)

        ecn_voq_cgm_profile = self.topology.create_and_init_default_cgm_profile()

        tx_eth_port_voq_set = self.topology.tx_l3_ac_eth_port_reg.sys_port.voq_set
        tx_eth_port_voq_set_size = tx_eth_port_voq_set.get_set_size()
        dest_device = self.device
        is_success, self.ecn_voq, self.ecn_vsc_vec = self.topology.allocate_voq_set(
            self.device, dest_device, T.TX_SLICE_REG, T.TX_IFG_REG, tx_eth_port_voq_set_size, use_presistant_alocation=False)
        self.assertTrue(is_success)
        ecn_voq_set = self.device.create_voq_set(
            self.ecn_voq,
            tx_eth_port_voq_set_size,
            self.ecn_vsc_vec,
            dest_device.get_id(),
            T.TX_SLICE_REG,
            T.TX_IFG_REG)
        for voq in range(tx_eth_port_voq_set_size):
            ecn_voq_set.set_cgm_profile(voq, ecn_voq_cgm_profile)

        self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj.set_ect_voq_set(ecn_voq_set)
        (res_voq_set) = self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj.get_ect_voq_set()
        self.assertEqual(res_voq_set.this, ecn_voq_set.this)

    def _test_ecn_voq(self, disable_rx=False, disable_tx=False):
        ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(ecmp, None)
        ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, ecmp, self.PRIVATE_DATA, False)

        U.run_and_compare(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
