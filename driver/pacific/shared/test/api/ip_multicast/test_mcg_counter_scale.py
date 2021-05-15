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

from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *

import decor
from packet_test_utils import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
from ipv4_mc import *
from sdk_multi_test_case_base import *
import mtu.mtu_test_utils as MTU
import ip_test_base


@unittest.skipUnless(decor.is_gibraltar(), "Relevant for gibraltar only")
@unittest.skipIf(decor.is_matilda(), "Scale is too high for Matilda")
@unittest.skipIf(True, "Test takes to long to run. disable for now")
class mcg_counter_scale(sdk_multi_test_case_base):
    MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')

    INPUT_PACKET_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_L2_SVI_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(MC_GROUP_ADDR), src=T.TX_SVI_MAC.addr_str) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_L3_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(MC_GROUP_ADDR), src=T.TX_L3_AC_REG_MAC.addr_str) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET_L2_SVI = pad_input_and_output_packets(
        INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_L2_SVI_BASE)
    INPUT_PACKET, EXPECTED_OUTPUT_PACKET_L3 = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_L3_BASE)

    output_serdes_svi = T.FIRST_SERDES_SVI
    output_serdes_l3 = T.FIRST_SERDES_L3_REG

    def tearDown(self):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def tearDownModule():
        pass

    @staticmethod
    def set_narrow_counters(device, state):
        if state == sdk.la_device.init_phase_e_CREATED:
            device.set_bool_property(sdk.la_device_property_e_ENABLE_NARROW_COUNTERS, True)

    def setUp(self):
        super().setUp()

        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        counter = self.device.create_counter(1)
        self.topology.tx_l3_ac_reg.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, counter)

        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_COUNTER_BANK
        res = self.device.get_resource_usage(rd)
        print('Counter banks used: %d' % res.used)

        self.mc_groups = []
        try_more = True
        i = 0
        while try_more:
            try:
                print('\rcreate_ip_multicast_group %d' % i, end='')
                mc_group = self.device.create_ip_multicast_group(1 + i, sdk.la_replication_paradigm_e_EGRESS)
                i += 1
            except BaseException:
                try_more = False

            if try_more:
                mc_group.add(self.topology.tx_l3_ac_reg.hld_obj, None, self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj)
                self.mc_groups.append(mc_group)

        print()

        i = 0
        self.counters = []
        for mcg in self.mc_groups:
            counter = self.device.create_counter(1)
            print('\rset_egress_counter %d' % i, end='')
            try:
                self.mc_groups[i].set_egress_counter(self.device.get_id(), counter)
            except sdk.ResourceException as e:
                print(e.status.get_info().message())
                raise
            i += 1
            self.counters.append(counter)
        print()
        print("Created %d counters" % i)

        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_COUNTER_BANK
        res = self.device.get_resource_usage(rd)
        print('Counter banks used: %d' % res.used)

    def test_scale(self):
        self.assertTrue(self.device.get_bool_property(sdk.la_device_property_e_ENABLE_NARROW_COUNTERS))

        self.assertEqual(len(self.counters), len(self.mc_groups))

        i = 0
        for mcg in self.mc_groups:
            self.topology.vrf.hld_obj.add_ipv4_multicast_route(ipv4_mc.SIP.hld_obj, self.MC_GROUP_ADDR.hld_obj, mcg,
                                                               None, False, False, None)
            r = run_and_get(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
            self.assertEqual(len(r), 1)

            print('\rreading counter %d' % i, end='')

            counter = self.topology.tx_l3_ac_reg.hld_obj.get_egress_counter(sdk.la_counter_set.type_e_PORT)
            pp, bp = counter.read(0, True, True)
            counter = mcg.get_egress_counter()[1]
            pm, bm = counter.read(0, True, True)

            if pm != 1 or pp != 1:
                print()
                print('mcg[%d] : pp=%d pm=%d' % (i, pp, pm))
                self.assertTrue(False)

            i += 1

            self.topology.vrf.hld_obj.delete_ipv4_multicast_route(ipv4_mc.SIP.hld_obj, self.MC_GROUP_ADDR.hld_obj)

        print()
        print('Test finished')


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
def setUpModule():
    sdk_multi_test_case_base.initialize(device_config_func=mcg_counter_scale.set_narrow_counters)


if __name__ == '__main__':
    unittest.main()
