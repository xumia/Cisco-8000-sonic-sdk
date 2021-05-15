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
import sim_utils
import topology as T
from scapy.all import *
import nplapicli as nplapi

import ip_test_base

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
SA = T.mac_addr('be:ef:5d:35:7a:35')

PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xA13

SYS_PORT_GID_BASE = 23
IN_SP_GID = SYS_PORT_GID_BASE
OUT_SP_GID = SYS_PORT_GID_BASE + 1
PUNT_SP_GID = SYS_PORT_GID_BASE + 2

# must be odd numbered slice due to bug in Pacific that RCY port can't be on the same slice as PCI port
PUNT_SLICE = T.get_device_slice(1)
PUNT_IFG = T.get_device_ifg(1)
PUNT_PIF_FIRST = T.get_device_first_serdes(8)

OUT_PUNT_PIF = T.PI_PIF + 1

# IPv4
# 0xc0c1c2c3
SIP = T.ipv4_addr('192.193.194.195')
# 0xd0d1d2d3
DIP_UC = T.ipv4_addr('208.209.210.211')
DIP_MC = T.ipv4_addr('224.0.0.5')

TTL = 127

INPUT_PACKET_UC_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=TTL) / \
    TCP(sport=0x1234, dport=0x2345)

INPUT_PACKET_MC_BASE = \
    Ether(dst=T.RX_L3_AC_IPv4_MC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=1, proto=89)

PUNT_PACKET_UC_BASE = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
         next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
         code=120,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         #source_lp=T.RX_L3_AC_GID, destination_lp=sdk.la_packet_types.LA_L3_LOGICAL_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
         relay_id=T.VRF_GID, lpts_flow_type=11) / \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=TTL) / \
    TCP(sport=0x1234, dport=0x2345)

PUNT_PACKET_MC_BASE = Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
         fwd_header_type=0,
         next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
         code=120,
         source_sp=T.RX_SYS_PORT_GID,
         destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID,
         # destination_lp=sdk.la_packet_types.LA_L3_LOGICAL_PORT_GID_INVALID,
         destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
         relay_id=T.VRF_GID,
         lpts_flow_type=11) / \
    Ether(dst=T.RX_L3_AC_IPv4_MC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=1, proto=89)

INPUT_PACKET_UC, PUNT_PACKET_UC = pad_input_and_output_packets(INPUT_PACKET_UC_BASE, PUNT_PACKET_UC_BASE)
INPUT_PACKET_MC, PUNT_PACKET_MC = pad_input_and_output_packets(INPUT_PACKET_MC_BASE, PUNT_PACKET_MC_BASE)


class ipv4_lpts_base(unittest.TestCase):

   # default slice mode settings. Can be changed inside each test
    slice_modes = sim_utils.STANDALONE_DEV

    def setUp(self):
        self.maxDiff = None

        self.device = sim_utils.create_device(1, slice_modes=self.slice_modes)

        self.ip_impl = ip_test_base.ipv4_test_base()
        self.topology = T.topology(self, self.device)
        self.add_default_route()

        pi_port = T.punt_inject_port(
            self,
            self.device,
            PUNT_SLICE,
            PUNT_IFG,
            PUNT_SP_GID,
            PUNT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        self.punt_dest1 = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION1_GID,
            pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)
        self.device.set_trap_configuration(
            sdk.LA_EVENT_L3_TTL_OR_HOP_LIMIT_IS_ONE,
            1,
            None,
            self.punt_dest1,
            False,
            False,
            True, 0)

        self.punt_dest2 = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)

        # enable mc traffic on l3 ac
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        self.device.set_trap_configuration(
            sdk.LA_EVENT_L3_TTL_OR_HOP_LIMIT_IS_ONE,
            1,
            None,
            self.punt_dest2,
            False,
            False,
            True, 0)

        self.stat_meter = T.create_meter_set(self, self.device, is_statistical=True, set_size=1)

    def tearDown(self):
        self.device.tearDown()

    def add_default_route(self):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x0
        prefix.length = 0
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.topology.nh_l3_ac_def.hld_obj, PRIVATE_DATA_DEFAULT, False)

    def create_lpts_instance(self, meter1=None, meter2=None, meter3=None, is_entry_meter=False):

        lpts = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV4)
        self.assertNotEqual(lpts, None)

        count = lpts.get_count()
        self.assertEqual(count, 0)

        k0 = sdk.la_lpts_key()
        k0.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k0.val.ipv4.sip.s_addr = SIP.to_num() + 1  # should not catch
        k0.mask.ipv4.sip.s_addr = 0xffffffff

        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.protocol = 6  # TCP
        k1.mask.ipv4.protocol = sdk.la_l4_protocol_e_RESERVED

        k2 = sdk.la_lpts_key()
        k2.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k2.val.ipv4.is_mc = True
        k2.mask.ipv4.is_mc = True
        k2.val.ipv4.protocol = 89
        k2.mask.ipv4.protocol = sdk.la_l4_protocol_e_RESERVED

        result = sdk.la_lpts_result()
        result.flow_type = 11
        result.punt_code = 120
        result.tc = 0
        result.dest = self.punt_dest2
        result.meter = None
        result.counter_or_meter = None
        if meter1 is not None:
            if is_entry_meter is True:
                result.counter_or_meter = meter1
            else:
                result.meter = meter1
        if result.counter_or_meter is None:
            result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)
        lpts.append(k0, result)
        count = lpts.get_count()
        self.assertEqual(count, 1)

        result.tc = 1
        result.meter = None
        result.counter_or_meter = None
        if meter2 is not None:
            if is_entry_meter is True:
                result.counter_or_meter = meter2
            else:
                result.meter = meter2
        if result.counter_or_meter is None:
            result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)

        lpts.append(k1, result)
        count = lpts.get_count()
        self.assertEqual(count, 2)

        result.dest = self.punt_dest1
        result.meter = None
        result.counter_or_meter = None
        if meter3 is not None:
            if is_entry_meter is True:
                result.counter_or_meter = meter3
            else:
                result.meter = meter3
        if result.counter_or_meter is None:
            result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)

        lpts.append(k2, result)
        count = lpts.get_count()
        self.assertEqual(count, 3)

        lpts_entry_desc = lpts.get(0)
        self.assertEqual(lpts_entry_desc.key_val.val.ipv4.sip.s_addr, k0.val.ipv4.sip.s_addr)
        self.assertEqual(lpts_entry_desc.key_val.mask.ipv4.sip.s_addr, k0.mask.ipv4.sip.s_addr)

        result.dest = self.punt_dest2

        lpts_entry_desc = lpts.get(1)
        self.assertEqual(lpts_entry_desc.key_val.val.ipv4.sip.s_addr, k1.val.ipv4.sip.s_addr)
        self.assertEqual(lpts_entry_desc.key_val.mask.ipv4.sip.s_addr, k1.mask.ipv4.sip.s_addr)
        self.assertEqual(lpts_entry_desc.result.dest.this, result.dest.this)

        result.dest = self.punt_dest1

        lpts_entry_desc = lpts.get(2)
        self.assertEqual(lpts_entry_desc.key_val.val.ipv4.protocol, k2.val.ipv4.protocol)
        self.assertEqual(lpts_entry_desc.key_val.mask.ipv4.protocol, k2.mask.ipv4.protocol)
        self.assertEqual(lpts_entry_desc.result.dest.this, result.dest.this)

        return lpts

    def setup_forus_dest(self):

        self.prefix_uc = self.ip_impl.build_prefix(DIP_UC, length=24)
        self.ip_impl.add_route(self.topology.vrf, self.prefix_uc,
                               self.topology.forus_dest,
                               PRIVATE_DATA_DEFAULT)

    def setup_forus_src(self):

        self.prefix_uc = self.ip_impl.build_prefix(SIP, length=24)
        self.ip_impl.add_route(self.topology.vrf, self.prefix_uc,
                               self.topology.forus_dest,
                               PRIVATE_DATA_DEFAULT)

    def push_lpts_entry(self, lpts, position, key, result):
        count_pre = lpts.get_count()
        lpts.push(position, key, result)

        lpts_entry_desc = lpts.get(position)
        self.assertEqual(lpts_entry_desc.key_val.val.ipv4.sip.s_addr, key.val.ipv4.sip.s_addr)
        self.assertEqual(lpts_entry_desc.key_val.mask.ipv4.sip.s_addr, key.mask.ipv4.sip.s_addr)
        self.assertEqual(lpts_entry_desc.key_val.val.ipv4.protocol, key.val.ipv4.protocol)
        self.assertEqual(lpts_entry_desc.key_val.mask.ipv4.protocol, key.mask.ipv4.protocol)
        self.assertEqual(lpts_entry_desc.result.dest.this, result.dest.this)

        count_post = lpts.get_count()
        self.assertEqual(count_post, count_pre + 1)

    def pop_lpts_entry(self, lpts, position):
        count = lpts.get_count()
        lpts.pop(position)
        count_tag = lpts.get_count()
        self.assertEqual(count_tag, count - 1)

    def trim_lpts_invalid(self, lpts):
        ''' Invalid removal from an LPTS - expect failure.'''

        count = lpts.get_count()

        try:
            lpts.pop(count)
            self.assertFail()
        except sdk.BaseException:
            pass

        count_tag = lpts.get_count()
        self.assertEqual(count, count_tag)

    def trim_lpts(self, lpts):
        ''' Remove the last entry of the LPTS. '''

        count = lpts.get_count()
        lpts.pop(count - 1)
        count_tag = lpts.get_count()
        self.assertEqual(count_tag, count - 1)

    def update_lpts_entry(self, lpts, position):
        ''' Update the lpts entry. '''

        count = lpts.get_count()

        k2 = sdk.la_lpts_key()
        k2.type = sdk.lpts_type_e_LPTS_TYPE_IPV4

        result = sdk.la_lpts_result()
        result.flow_type = 10
        result.punt_code = 11
        result.tc = 0
        result.dest = self.punt_dest2
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)

        lpts.set(position, k2, result)

        lpts_entry_desc = lpts.get(position)
        self.assertEqual(lpts_entry_desc.key_val.val.ipv4.sip.s_addr, k2.val.ipv4.sip.s_addr)
        self.assertEqual(lpts_entry_desc.result.flow_type, result.flow_type)
        self.assertEqual(lpts_entry_desc.result.punt_code, result.punt_code)
        self.assertEqual(lpts_entry_desc.result.tc, result.tc)

        # No change in count
        count_tag = lpts.get_count()
        self.assertEqual(count_tag, count)

    def verify_packet_fields(self, lpts, key, pin, pout):

        count_pre = lpts.get_count()

        result = sdk.la_lpts_result()
        result.flow_type = 11
        result.punt_code = 120
        result.tc = 0
        result.dest = self.punt_dest2
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)

        self.push_lpts_entry(lpts, 0, key, result)

        run_and_compare(self, self.device,
                        pin, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        pout, PUNT_SLICE, PUNT_IFG, PUNT_PIF_FIRST)

        count_post = lpts.get_count()
        self.assertEqual(count_post, count_pre + 1)

        lpts.pop(0)

        count_post = lpts.get_count()
        self.assertEqual(count_post, count_pre)
