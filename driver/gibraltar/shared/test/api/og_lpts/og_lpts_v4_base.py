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

SIP1 = T.ipv4_addr('10.1.1.2')
SBINCODE1 = 0xdead
SIP2 = T.ipv4_addr('20.1.1.2')
SBINCODE2 = 0xfeed
DIP1 = T.ipv4_addr('10.1.1.1')
DBINCODE1 = 0xbeef
DIP2 = T.ipv4_addr('20.1.1.1')
DBINCODE2 = 0xface

SIP_NO_PCL = T.ipv4_addr('101.1.1.2')

TTL = 127
TTL255 = 255

INPUT_PACKET_UC_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=TTL) / \
    TCP(sport=1799, dport=179)

PUNT_PACKET_UC_BASE = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
         next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
         code=120,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
         relay_id=T.VRF_GID, lpts_flow_type=11) / \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=TTL) / \
    TCP(sport=1799, dport=179)

INPUT_PACKET_UC, PUNT_PACKET_UC = pad_input_and_output_packets(INPUT_PACKET_UC_BASE, PUNT_PACKET_UC_BASE)


INPUT_PACKET_UC_BASE2 = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=TTL) / \
    TCP(sport=179, dport=1794)

PUNT_PACKET_UC_BASE2 = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
         next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
         code=120,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
         relay_id=T.VRF_GID, lpts_flow_type=11) / \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=TTL) / \
    TCP(sport=179, dport=1794)

INPUT_PACKET_UC2, PUNT_PACKET_UC2 = pad_input_and_output_packets(INPUT_PACKET_UC_BASE2, PUNT_PACKET_UC_BASE2)

INPUT_PACKET_UC_BASE3 = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP_NO_PCL.addr_str, dst=DIP_UC.addr_str, ttl=TTL) / \
    TCP(sport=179, dport=1794)

PUNT_PACKET_UC_BASE3 = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
         next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
         code=121,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
         relay_id=T.VRF_GID, lpts_flow_type=12) / \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP_NO_PCL.addr_str, dst=DIP_UC.addr_str, ttl=TTL) / \
    TCP(sport=179, dport=1794)

INPUT_PACKET_UC3, PUNT_PACKET_UC3 = pad_input_and_output_packets(INPUT_PACKET_UC_BASE3, PUNT_PACKET_UC_BASE3)

INPUT_PACKET_UC_BASE5 = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=TTL) / \
    TCP(sport=1799, dport=179, flags="A")

PUNT_PACKET_UC_BASE5 = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
         next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
         code=111,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
         relay_id=T.VRF_GID, lpts_flow_type=11) / \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=TTL) / \
    TCP(sport=1799, dport=179, flags="A")

INPUT_PACKET_UC5, PUNT_PACKET_UC5 = pad_input_and_output_packets(INPUT_PACKET_UC_BASE5, PUNT_PACKET_UC_BASE5)

INPUT_PACKET_UC_BASE7 = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=TTL255) / \
    TCP(sport=1799, dport=179)

PUNT_PACKET_UC_BASE7 = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
         next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
         code=117,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
         relay_id=T.VRF_GID, lpts_flow_type=11) / \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=TTL255) / \
    TCP(sport=1799, dport=179)

INPUT_PACKET_UC7, PUNT_PACKET_UC7 = pad_input_and_output_packets(INPUT_PACKET_UC_BASE7, PUNT_PACKET_UC_BASE7)


class og_lpts_v4_base(unittest.TestCase):

    # default slice mode settings. Can be changed inside each test
    slice_modes = sim_utils.STANDALONE_DEV

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            device.set_int_property(sdk.la_device_property_e_MAX_NUM_PCL_GIDS, 32)

    def setUp(self):
        self.maxDiff = None

        self.device = sim_utils.create_device(1, True, self.slice_modes, self.device_config_func)

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

    def create_lpts_instance(self):

        lpts = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV4)
        self.assertNotEqual(lpts, None)

        count = lpts.get_count()
        self.assertEqual(count, 0)

        src_pcl = self.create_src_pcl()

        app_prop = sdk.la_lpts_app_properties()
        app_prop.val.ip_version = 0
        app_prop.mask.ip_version = 1
        app_prop.val.protocol = 6  # TCP
        app_prop.mask.protocol = 0xff
        app_prop.val.ports.sport = 179
        app_prop.mask.ports.sport = 0xffff
        app_prop.val.ports.dport = 0
        app_prop.mask.ports.dport = 0
        lpts_app = self.device.create_og_lpts_app(app_prop, src_pcl)
        self.assertNotEqual(lpts_app, None)

        app_prop.val.ports.dport = 179
        app_prop.mask.ports.dport = 0xffff
        app_prop.val.ports.sport = 0
        app_prop.mask.ports.sport = 0
        lpts_app2 = self.device.create_og_lpts_app(app_prop, src_pcl)
        self.assertNotEqual(lpts_app2, None)

        lpts_app3 = self.device.create_og_lpts_app(app_prop, None)
        self.assertNotEqual(lpts_app3, None)

        lpts_app4 = self.device.create_og_lpts_app(app_prop, src_pcl)
        self.assertNotEqual(lpts_app4, None)

        k0 = sdk.la_lpts_key()
        k0.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k0.val.ipv4.src_og_compression_code = SBINCODE1
        k0.mask.ipv4.src_og_compression_code = 0xffff
        k0.val.ipv4.app_id = lpts_app2.get_app_id()
        k0.mask.ipv4.app_id = 0xf
        k0.val.ipv4.relay_id = T.VRF_GID
        k0.mask.ipv4.relay_id = 0x7ff
        k0.val.ipv4.established = False
        k0.mask.ipv4.established = True
        k0.val.ipv4.ttl_255 = True
        k0.mask.ipv4.ttl_255 = True
        k0.val.ipv4.protocol = 6
        k0.mask.ipv4.protocol = 0xff

        result = sdk.la_lpts_result()
        result.flow_type = 11
        result.punt_code = 117
        result.tc = 0
        result.dest = self.punt_dest2
        result.meter = None
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)

        lpts.append(k0, result)
        count = lpts.get_count()
        self.assertEqual(count, 1)

        k0.mask.ipv4.ttl_255 = False
        result.punt_code = 120
        k0.val.ipv4.dst_og_compression_code = DBINCODE1
        k0.mask.ipv4.dst_og_compression_code = 0xffff
        lpts.append(k0, result)
        count = lpts.get_count()
        self.assertEqual(count, 2)

        k0.val.ipv4.app_id = lpts_app.get_app_id()
        lpts.append(k0, result)
        count = lpts.get_count()
        self.assertEqual(count, 3)

        k0.val.ipv4.established = True
        k0.val.ipv4.app_id = lpts_app2.get_app_id()
        result.punt_code = 111
        lpts.append(k0, result)
        count = lpts.get_count()
        self.assertEqual(count, 4)

        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.src_og_compression_code = SBINCODE2
        k1.mask.ipv4.src_og_compression_code = 0xffff
        k1.val.ipv4.dst_og_compression_code = DBINCODE2
        k1.mask.ipv4.dst_og_compression_code = 0xffff
        k1.val.ipv4.app_id = lpts_app2.get_app_id()
        k1.mask.ipv4.app_id = 0xf
        k1.val.ipv4.relay_id = T.VRF_GID
        k1.mask.ipv4.relay_id = 0x7ff
        k1.val.ipv4.established = False
        k1.mask.ipv4.established = True
        k1.val.ipv4.protocol = 6
        k1.mask.ipv4.protocol = 0xff
        lpts.append(k1, result)
        count = lpts.get_count()
        self.assertEqual(count, 5)

        k1.val.ipv4.app_id = lpts_app.get_app_id()
        lpts.append(k1, result)
        count = lpts.get_count()
        self.assertEqual(count, 6)

        lpts_entry_desc = lpts.get(1)
        self.assertEqual(lpts_entry_desc.key_val.val.ipv4.src_og_compression_code, k0.val.ipv4.src_og_compression_code)
        self.assertEqual(lpts_entry_desc.key_val.mask.ipv4.src_og_compression_code, k0.mask.ipv4.src_og_compression_code)

        lpts_entry_desc = lpts.get(5)
        self.assertEqual(lpts_entry_desc.key_val.val.ipv4.src_og_compression_code, k1.val.ipv4.src_og_compression_code)
        self.assertEqual(lpts_entry_desc.key_val.mask.ipv4.src_og_compression_code, k1.mask.ipv4.src_og_compression_code)
        self.assertEqual(lpts_entry_desc.key_val.val.ipv4.dst_og_compression_code, k1.val.ipv4.dst_og_compression_code)
        self.assertEqual(lpts_entry_desc.key_val.mask.ipv4.dst_og_compression_code, k1.mask.ipv4.dst_og_compression_code)
        self.assertEqual(lpts_entry_desc.result.dest.this, result.dest.this)

        k1.val.ipv4.src_og_compression_code = 0
        k1.mask.ipv4.src_og_compression_code = 0
        k1.val.ipv4.dst_og_compression_code = 0
        k1.mask.ipv4.dst_og_compression_code = 0

        result.flow_type = 12
        result.punt_code = 121
        lpts.append(k1, result)
        count = lpts.get_count()
        self.assertEqual(count, 7)

        k1.val.ipv4.established = True
        lpts.append(k1, result)
        count = lpts.get_count()
        self.assertEqual(count, 8)

        return lpts

    def setup_forus_dest(self):
        self.prefix_uc = self.ip_impl.build_prefix(DIP_UC, length=32)
        forus_dest = self.device.create_forus_destination(DBINCODE1)
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix_uc, forus_dest, PRIVATE_DATA_DEFAULT, True)

    def create_src_pcl(self):
        src_pclEntryVec = sdk.pcl_v4_vector()

        src_pclEntry1 = sdk.la_pcl_v4()
        src_pclEntry1.prefix.addr.s_addr = SIP.to_num() & 0xffffff00
        src_pclEntry1.prefix.length = 24
        src_pclEntry1.bincode = SBINCODE1
        src_pclEntryVec.append(src_pclEntry1)

        src_pclEntry2 = sdk.la_pcl_v4()
        src_pclEntry2.prefix.addr.s_addr = SIP1.to_num() & 0xffffff00
        src_pclEntry2.prefix.length = 24
        src_pclEntry2.bincode = SBINCODE1
        src_pclEntryVec.append(src_pclEntry2)

        src_pclEntry3 = sdk.la_pcl_v4()
        src_pclEntry3.prefix.addr.s_addr = SIP2.to_num() & 0xffffff00
        src_pclEntry3.prefix.length = 24
        src_pclEntry3.bincode = SBINCODE2
        src_pclEntryVec.append(src_pclEntry3)

        src_pclEntry4 = sdk.la_pcl_v4()
        src_pclEntry4.prefix.addr.s_addr = 0
        src_pclEntry4.prefix.length = 0
        src_pclEntry4.bincode = 0x70000
        src_pclEntryVec.append(src_pclEntry4)

        src_pcl = self.device.create_pcl(src_pclEntryVec, sdk.pcl_feature_type_e_LPTS)
        self.assertNotEqual(src_pcl, None)
        return src_pcl
