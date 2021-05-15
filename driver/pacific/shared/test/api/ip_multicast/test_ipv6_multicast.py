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


import decor
from packet_test_utils import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
from ipv4_mc import *
from ipv6_mc import *
from sdk_multi_test_case_base import *

from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *

from ipv4_s_g_mc_base import *
from ipv4_g_mc_base import *
from egress_member_punt_base import *
from unmatched_mc_base import *

from ipv6_g_mc_base import *
from ipv6_s_g_mc_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_address_checking(sdk_multi_test_case_base):
    MC_GROUP_GID = 0x13
    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    MC_GROUP_ADDRESSES = [
        T.ipv6_addr('ff31:0000:0000:0000:0000:0001:ffe8:658f'),
        T.ipv6_addr('ff31:0000:0000:0000:0000:0002:ffe8:658f'),
        T.ipv6_addr('ff31:0000:0000:0000:0002:0001:ffe8:658f'),
        T.ipv6_addr('ff31:0000:0000:0002:0000:0001:ffe8:658f'),
        T.ipv6_addr('ff31:0000:0002:0000:0000:0001:ffe8:658f'),
        T.ipv6_addr('ff31:0002:0000:0000:0000:0001:ffe8:658f')]

    def setUp(self):
        super().setUp()
        self.mc_group = self.device.create_ip_multicast_group(
            ipv6_address_checking.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.vrf = self.device.create_vrf(100)
        punt_and_forward = False
        self.vrf.add_ipv6_multicast_route(
            ipv6_address_checking.SIP.hld_obj,
            ipv6_address_checking.MC_GROUP_ADDRESSES[0].hld_obj,
            self.mc_group,
            None,
            False,
            punt_and_forward,
            None)

    def test_ipv6_address_checking(self):

        punt_and_forward = False
        # Add should fail for addresses that are different only in higher bits
        i = 1
        for mc_group_addr in ipv6_address_checking.MC_GROUP_ADDRESSES[1:]:
            with self.assertRaises(sdk.ExistException):
                self.vrf.add_ipv6_multicast_route(
                    ipv6_address_checking.SIP.hld_obj,
                    mc_group_addr.hld_obj,
                    self.mc_group,
                    None,
                    False,
                    punt_and_forward,
                    None)
            i += 1

        # Get should succeed for existing entry
        info = self.vrf.get_ipv6_multicast_route(
            ipv6_address_checking.SIP.hld_obj,
            ipv6_address_checking.MC_GROUP_ADDRESSES[0].hld_obj)
        self.assertEqual(info.mcg.this, self.mc_group.this)

        # Get should fail for addresses that are different than the existing entry
        i = 1
        for mc_group_addr in ipv6_address_checking.MC_GROUP_ADDRESSES[1:]:
            with self.assertRaises(sdk.NotFoundException):
                self.vrf.get_ipv6_multicast_route(ipv6_address_checking.SIP.hld_obj, mc_group_addr.hld_obj)
            i += 1

        # Modify should succeed for existing entry
        counter = self.device.create_counter(1)
        self.vrf.modify_ipv6_multicast_route(
            ipv6_address_checking.SIP.hld_obj,
            ipv6_address_checking.MC_GROUP_ADDRESSES[0].hld_obj,
            self.mc_group,
            None,
            False,
            punt_and_forward,
            counter)

        # Modify should fail for addresses that are different than the existing entry
        i = 1
        for mc_group_addr in ipv6_address_checking.MC_GROUP_ADDRESSES[1:]:
            with self.assertRaises(sdk.NotFoundException):
                self.vrf.modify_ipv6_multicast_route(ipv6_address_checking.SIP.hld_obj, mc_group_addr.hld_obj,
                                                     self.mc_group, None, False, punt_and_forward, counter)
            i += 1

        # Delete should fail for addresses that are different than the existing entry
        i = 1
        for mc_group_addr in ipv6_address_checking.MC_GROUP_ADDRESSES[1:]:
            with self.assertRaises(sdk.NotFoundException):
                self.vrf.delete_ipv6_multicast_route(ipv6_address_checking.SIP.hld_obj, mc_group_addr.hld_obj)
            i += 1

        # Delete should succeed for existing entry
        self.vrf.delete_ipv6_multicast_route(ipv6_address_checking.SIP.hld_obj, ipv6_address_checking.MC_GROUP_ADDRESSES[0].hld_obj)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_l3_ac_egress_member_punt(egress_member_punt_ipv6_test, egress_member_punt_l3_ac_test, egress_member_punt_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_member_punt(self):
        self.do_test_egress_member_punt()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_member_punt_member_remove(self):
        self.do_test_egress_member_punt_member_remove()

    def test_egress_member_punt_member_get(self):
        self.do_test_egress_member_punt_member_get()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_l3_ac_g_mc_mtu(ipv6_g_mc):

    INPUT_PACKET_BASE = Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_g_mc.MC_GROUP_ADDR),
                              src=mc_base.SA.addr_str,
                              type=Ethertype.QinQ.value) / Dot1Q(vlan=T.RX_L3_AC_PORT_VID1,
                                                                 type=Ethertype.Dot1Q.value) / Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / IPv6(src=ipv6_mc.SIP.addr_str,
                                                                                                                                       dst=ipv6_g_mc.MC_GROUP_ADDR.addr_str,
                                                                                                                                       hlim=mc_base.TTL,
                                                                                                                                       plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_g_mc.MC_GROUP_ADDR),
                                        src=T.TX_L3_AC_REG_MAC.addr_str) / IPv6(src=ipv6_mc.SIP.addr_str,
                                                                                dst=ipv6_g_mc.MC_GROUP_ADDR.addr_str,
                                                                                hlim=mc_base.TTL - 1,
                                                                                plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_DEF_BASE = Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_g_mc.MC_GROUP_ADDR),
                                            src=T.TX_L3_AC_DEF_MAC.addr_str) / IPv6(src=ipv6_mc.SIP.addr_str,
                                                                                    dst=ipv6_g_mc.MC_GROUP_ADDR.addr_str,
                                                                                    hlim=mc_base.TTL - 1,
                                                                                    plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    __, EXPECTED_OUTPUT_PACKET_DEF = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_DEF_BASE)

    l3_port_impl_class = T.ip_l3_ac_base
    output_serdes = T.FIRST_SERDES_L3

    def test_route_mtu(self):
        self.do_test_route_mtu()

    def get_tx_l2_port(self):
        return None

    def get_tx_l2_port_def(self):
        return None

    def get_tx_sys_port(self):
        return self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_l3_ac_g_mc(ipv6_g_mc):

    l3_port_impl_class = T.ip_l3_ac_base
    output_serdes = T.FIRST_SERDES_L3
    ip_impl = ip_test_base.ipv6_test_base()
    svi = False

    def setUp(self):
        ipv6_g_mc.setUp(self)
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)
        mc_base.rechoose_odd_inject_slice(self.device)

        # Add subnet for DC pass
        subnet = self.ip_impl.build_prefix(ipv6_mc.SIP, length=32)
        self.ip_impl.add_subnet(self.topology.rx_l3_ac, subnet)

        # Add route for DC fail
        nh = T.next_hop(self, self.device, mc_base.NH_GID, mc_base.NH_MAC, self.topology.rx_l3_ac)
        fec = T.fec(self, self.device, nh)
        prefix = self.ip_impl.build_prefix(ipv6_mc.SIP_FEC, length=32)
        self.ip_impl.add_route(self.topology.vrf, prefix, fec, mc_base.PRIVATE_DATA)

    def construct_packet(self, mc_mac, source_ip):
        INPUT_PACKET_BASE = \
            Ether(dst=ipv6_mc.get_mc_sa_addr_str(mc_mac), src=mc_base.SA.addr_str, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IPv6(src=source_ip.addr_str, dst=mc_mac.addr_str, hlim=mc_base.TTL, plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=ipv6_mc.get_mc_sa_addr_str(mc_mac), src=T.TX_L3_AC_REG_MAC.addr_str) / \
            IPv6(src=source_ip.addr_str, dst=mc_mac.addr_str, hlim=mc_base.TTL - 1, plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_DEF_BASE = \
            Ether(dst=ipv6_mc.get_mc_sa_addr_str(mc_mac), src=T.TX_L3_AC_DEF_MAC.addr_str) / \
            IPv6(src=source_ip.addr_str, dst=mc_mac.addr_str, hlim=mc_base.TTL - 1, plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

        self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
        __, self.EXPECTED_OUTPUT_PACKET_DEF = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_DEF_BASE)

    def construct_punt_packet(self, trap_code):
        self.EXPECTED_OUTPUT_PACKET_PUNT = \
            Ether(dst=mc_base.HOST_MAC_ADDR, src=mc_base.PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=mc_base.PUNT_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
                 next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                 code=trap_code,
                 source_sp=T.RX_SYS_PORT_GID,
                 destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=T.RX_L3_AC_GID,
                 destination_lp=trap_code,
                 relay_id=T.VRF_GID,
                 lpts_flow_type=0) / \
            self.INPUT_PACKET

    def construct_snoop_packet(self):
        self.EXPECTED_OUTPUT_PACKET_SNOOP = \
            Ether(dst=mc_base.HOST_MAC_ADDR, src=mc_base.PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=mc_base.MIRROR_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV6,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
                 next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                 code=mc_base.MIRROR_CMD_INGRESS_GID,
                 source_sp=T.RX_SYS_PORT_GID,
                 destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=T.RX_L3_AC_GID,
                 destination_lp=0,
                 relay_id=T.VRF_GID,
                 lpts_flow_type=0) / \
            self.INPUT_PACKET

    # For all tests:
    # 1. construct input and expected output packets (with required mc_mac and sip)
    # 2. construct any expected cpu packets (trap or snoop packets)
    # 3. set the rpf value (for rpf pass or rpf fail)
    # 4. set trap boolean, if set to True, it is a trap otherwise snoop
    #    this value is used in base class to construct the expected_packets list
    # 5. set pcount - packet count
    #    this value is used in base class to verify the counters
    # The original cases with 'none' rpf are also maintained. They are considered
    # rpf pass cases with directly connected check pass or fail.
    #
    # For (*,g) miss cases, different mc mac is used.
    # For DC fail cases (directly connected check fail), different source ip is used.
    # For RPF fail cases, rx_l3_ac1 is used.

    def test_route_gmiss_dcfail(self):
        #(*,g) miss, dc fail: Action: drop
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR_MISS, ipv6_mc.SIP_DCFAIL)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_gmiss_dcfail_ir(self):
        #(*,g) miss, dc fail: Action: drop
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR_MISS, ipv6_mc.SIP_DCFAIL)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route_ir()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_route_gmiss_dcfail_fec(self):
        #(*,g) miss, dc fail: Action: drop
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR_MISS, ipv6_mc.SIP_FEC)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_gmiss_dcfail_fec_ir(self):
        #(*,g) miss, dc fail: Action: drop
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR_MISS, ipv6_mc.SIP_FEC)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route_ir()

    def test_route_gmiss_dcpass(self):
        #(*,g) miss, dc pass: Action: punt
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR_MISS, ipv6_mc.SIP)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_DC_PASS)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_gmiss_dcpass_ir(self):
        #(*,g) miss, dc pass: Action: punt
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR_MISS, ipv6_mc.SIP)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_DC_PASS)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route_ir(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_nonerpf_dcfail(self):
        #(*,g) none rpf, dc fail: Action: forward
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_DCFAIL)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_nonerpf_dcfail_ir(self):
        #(*,g) none rpf, dc fail: Action: forward
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_DCFAIL)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route_ir()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_nonerpf_dcfail_fec(self):
        #(*,g) none rpf, dc fail: Action: forward
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_FEC)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_nonerpf_dcfail_fec_ir(self):
        #(*,g) none rpf, dc fail: Action: forward
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_FEC)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route_ir()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_nonerpf_dcpass(self):
        #(*,g) none rpf, dc pass: Action: snoop and forward
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP)
        self.construct_snoop_packet()
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_nonerpf_dcpass_ir(self):
        #(*,g) none rpf, dc pass: Action: snoop and forward
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP)
        self.construct_snoop_packet()
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route_ir(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpffail_dcfail(self):
        #(*,g) hit rpf fail, dc fail: Action: punt
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_DCFAIL)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpffail_dcfail_ir(self):
        #(*,g) hit rpf fail, dc fail: Action: punt
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_DCFAIL)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route_ir(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_route_rpffail_dcfail_fec(self):
        #(*,g) hit rpf fail, dc fail: Action: punt
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_FEC)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpffail_dcfail_fec_ir(self):
        #(*,g) hit rpf fail, dc fail: Action: punt
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_FEC)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route_ir(extra_packet=punt_packet)

    def test_route_rpffail_dcpass(self):
        #(*,g) hit rpf fail, dc pass: Action: punt
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_DC_PASS)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpffail_dcpass_ir(self):
        #(*,g) hit rpf fail, dc pass: Action: punt
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_DC_PASS)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route_ir(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpfpass_dcfail(self):
        #(*,g) hit rpf pass, dc fail: Action: forward
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_DCFAIL)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpfpass_dcfail_ir(self):
        #(*,g) hit rpf pass, dc fail: Action: forward
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_DCFAIL)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route_ir()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpfpass_dcfail_fec(self):
        #(*,g) hit rpf pass, dc fail: Action: forward
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_FEC)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpfpass_dcfail_fec_ir(self):
        #(*,g) hit rpf pass, dc fail: Action: forward
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_FEC)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route_ir()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpfpass_dcpass(self):
        #(*,g) hit rpf pass, dc pass: Action: snoop and forward
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP)
        self.construct_snoop_packet()
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpfpass_dcpass_ir(self):
        #(*,g) hit rpf pass, dc pass: Action: snoop and forward
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP)
        self.construct_snoop_packet()
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route_ir(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_empty_mcg(self):
        # Even MC packets that do not belong to any MC group need to be able to be mirrored before being dropped
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = None
        self.is_mcast_route_hit = True
        self.do_test_route_to_empty_mcg(extra_packet=snoop_packet)

    def get_tx_l2_port(self):
        return None

    def get_tx_l2_port_def(self):
        return None

    def get_tx_sys_port(self):
        return self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_l3_ac_s_g_mc(ipv6_s_g_mc):
    INPUT_PACKET_BASE = Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR),
                              src=mc_base.SA.addr_str,
                              type=Ethertype.QinQ.value) / Dot1Q(vlan=T.RX_L3_AC_PORT_VID1,
                                                                 type=Ethertype.Dot1Q.value) / Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / IPv6(src=ipv6_mc.SIP.addr_str,
                                                                                                                                       dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str,
                                                                                                                                       hlim=mc_base.TTL,
                                                                                                                                       plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR),
                                        src=T.TX_L3_AC_REG_MAC.addr_str) / IPv6(src=ipv6_mc.SIP.addr_str,
                                                                                dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str,
                                                                                hlim=mc_base.TTL - 1,
                                                                                plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_DEF_BASE = Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR),
                                            src=T.TX_L3_AC_DEF_MAC.addr_str) / IPv6(src=ipv6_mc.SIP.addr_str,
                                                                                    dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str,
                                                                                    hlim=mc_base.TTL - 1,
                                                                                    plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    __, EXPECTED_OUTPUT_PACKET_DEF = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_DEF_BASE)

    INPUT_PACKET_BASE3 = Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR),
                               src=mc_base.SA.addr_str,
                               type=Ethertype.QinQ.value) / Dot1Q(vlan=T.RX_L3_AC_PORT_VID1,
                                                                  type=Ethertype.Dot1Q.value) / Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / IPv6(src=ipv6_mc.SIP3.addr_str,
                                                                                                                                        dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str,
                                                                                                                                        hlim=mc_base.TTL,
                                                                                                                                        plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE3 = Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR),
                                         src=T.TX_L3_AC_REG_MAC.addr_str) / IPv6(src=ipv6_mc.SIP3.addr_str,
                                                                                 dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str,
                                                                                 hlim=mc_base.TTL - 1,
                                                                                 plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_DEF_BASE3 = Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR),
                                             src=T.TX_L3_AC_DEF_MAC.addr_str) / IPv6(src=ipv6_mc.SIP3.addr_str,
                                                                                     dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str,
                                                                                     hlim=mc_base.TTL - 1,
                                                                                     plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET3, EXPECTED_OUTPUT_PACKET3 = pad_input_and_output_packets(INPUT_PACKET_BASE3, EXPECTED_OUTPUT_PACKET_BASE3)
    __, EXPECTED_OUTPUT_PACKET_DEF3 = pad_input_and_output_packets(INPUT_PACKET_BASE3, EXPECTED_OUTPUT_PACKET_DEF_BASE3)

    EXPECTED_OUTPUT_PACKET_PUNT = \
        Ether(dst=mc_base.HOST_MAC_ADDR, src=mc_base.PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=mc_base.PUNT_VLAN, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
             fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
             next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
             code=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL,
             source_sp=T.RX_SYS_PORT_GID,
             destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             source_lp=T.RX_L3_AC_GID,
             destination_lp=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL,
             relay_id=T.VRF_GID,
             lpts_flow_type=0) / \
        INPUT_PACKET

    EXPECTED_OUTPUT_PACKET_PUNT3 = \
        Ether(dst=mc_base.HOST_MAC_ADDR, src=mc_base.PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=mc_base.PUNT_VLAN, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
             fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
             next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
             code=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL,
             source_sp=T.RX_SYS_PORT_GID1,
             destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             source_lp=T.RX_L3_AC_GID1,
             destination_lp=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL,
             relay_id=T.VRF_GID,
             lpts_flow_type=0) / \
        INPUT_PACKET3

    l3_port_impl_class = T.ip_l3_ac_base
    output_serdes = T.FIRST_SERDES_L3
    svi = False

    #(s,g)hit, none rpf, Action: Forward
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_sg_nonerpf(self):
        self.trap = False
        self.is_mcast_route_hit = True
        self.rpf_intf = None
        self.rpf_intf3 = None
        self.do_test_route()

    #(s,g)hit, none rpf, Action: Forward
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_sg_nonerpf_ir(self):
        self.trap = False
        self.is_mcast_route_hit = True
        self.rpf_intf = None
        self.rpf_intf3 = None
        self.do_test_route_ir()

    #(s,g)hit, rpf-fail, Action: Drop (punt_on_rpf_fail set to False)
    def test_route_sg_rpffail(self):
        self.trap = True
        self.is_mcast_route_hit = False
        self.rpf_intf = self.topology.tx_l3_ac_reg.hld_obj
        self.rpf_intf3 = self.topology.tx_l3_ac_def.hld_obj
        self.do_test_route()

    #(s,g)hit, rpf-fail, Action: Drop (punt_on_rpf_fail set to False)
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_sg_rpffail_ir(self):
        self.trap = True
        self.is_mcast_route_hit = False
        self.rpf_intf = self.topology.tx_l3_ac_reg.hld_obj
        self.rpf_intf3 = self.topology.tx_l3_ac_def.hld_obj
        self.do_test_route_ir()

    #(s,g)hit, rpf-fail, Action: Punt (punt_on_rpf_fail set to True)
    def test_route_sg_rpffail_punt(self):
        self.trap = True
        self.is_mcast_route_hit = False
        self.rpf_intf = self.topology.tx_l3_ac_reg.hld_obj
        self.rpf_intf3 = self.topology.tx_l3_ac_def.hld_obj
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        punt_packet3 = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT3,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.do_test_route(extra_packet=punt_packet, extra_packet3=punt_packet3, punt_on_rpf_fail=True)

    #(s,g)hit, rpf-fail, Action: Punt (punt_on_rpf_fail set to True)
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_sg_rpffail_punt_ir(self):
        self.trap = True
        self.is_mcast_route_hit = False
        self.rpf_intf = self.topology.tx_l3_ac_reg.hld_obj
        self.rpf_intf3 = self.topology.tx_l3_ac_def.hld_obj
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        punt_packet3 = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT3,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.do_test_route_ir(extra_packet=punt_packet, extra_packet3=punt_packet3, punt_on_rpf_fail=True)

    #(s,g)hit, rpf-pass, Action: Forward
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_sg_rpfpass(self):
        self.trap = False
        self.is_mcast_route_hit = True
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.rpf_intf3 = self.topology.rx_l3_ac1.hld_obj
        self.do_test_route()

    #(s,g)hit, rpf-pass, Action: Forward
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_sg_rpfpass_ir(self):
        self.trap = False
        self.is_mcast_route_hit = True
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.rpf_intf3 = self.topology.rx_l3_ac1.hld_obj
        self.do_test_route_ir()

    #(s,g)hit, rpf-pass, Action: Forward (punt_on_rpf_fail set to True)
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_sg_rpfpass_punt_on_rpf_fail_true(self):
        self.trap = False
        self.is_mcast_route_hit = True
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.rpf_intf3 = self.topology.rx_l3_ac1.hld_obj
        self.do_test_route(punt_on_rpf_fail=True)

    #(s,g)hit, rpf-pass, Action: Forward (punt_on_rpf_fail set to True)
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_sg_rpfpass_punt_on_rpf_fail_true_ir(self):
        self.trap = False
        self.is_mcast_route_hit = True
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.rpf_intf3 = self.topology.rx_l3_ac1.hld_obj
        self.do_test_route_ir(punt_on_rpf_fail=True)

    def get_tx_l2_port(self):
        return None

    def get_tx_l2_port_def(self):
        return None

    def get_tx_sys_port(self):
        return self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_l3_ac_unmatched_mc(unmatched_mc_ipv6_test, unmatched_mc_l3_ac_test, unmatched_mc_base):

    def test_unmatched_mc_invalid_params(self):
        self.do_test_invalid_params()

    def test_unmatched_mc_default(self):
        self.do_test_unmatched_mc_default()

    def test_unmatched_mc(self):
        self.do_test_unmatched_mc()

    def test_unmatched_mc_long_addr(self):
        self.do_test_unmatched_mc_long_addr()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_same_route(ipv6_s_g_mc):

    l3_port_impl_class = T.ip_l3_ac_base

    def test_ipv6_same_route_2_vrfs(self):
        self._test_ipv6_same_route_2_vrfs()

    def get_tx_l2_port(self):
        return None

    def get_tx_l2_port_def(self):
        return None

    def get_tx_sys_port(self):
        return self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_svi_egress_member_punt(egress_member_punt_ipv6_test, egress_member_punt_svi_test, egress_member_punt_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_member_punt(self):
        self.do_test_egress_member_punt()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_member_punt_member_remove(self):
        self.do_test_egress_member_punt_member_remove()

    def test_egress_member_punt_member_get(self):
        self.do_test_egress_member_punt_member_get()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_svi_g_mc_mtu(ipv6_g_mc):
    RX_SVI_GID = 0x2a

    INPUT_PACKET_BASE = Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_g_mc.MC_GROUP_ADDR),
                              src=mc_base.SA.addr_str,
                              type=Ethertype.Dot1Q.value) / Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / IPv6(src=ipv6_mc.SIP.addr_str,
                                                                                                    dst=ipv6_g_mc.MC_GROUP_ADDR.addr_str,
                                                                                                    hlim=mc_base.TTL,
                                                                                                    plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_g_mc.MC_GROUP_ADDR),
                                        src=T.TX_SVI_MAC.addr_str) / IPv6(src=ipv6_mc.SIP.addr_str,
                                                                          dst=ipv6_g_mc.MC_GROUP_ADDR.addr_str,
                                                                          hlim=mc_base.TTL - 1,
                                                                          plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    EXPECTED_OUTPUT_PACKET_DEF = EXPECTED_OUTPUT_PACKET

    l3_port_impl_class = T.ip_svi_base
    output_serdes = T.FIRST_SERDES_SVI

    def setUp(self):
        ipv6_g_mc.setUp(self)

    def test_route_mtu(self):
        self.do_test_route_mtu()

    def get_tx_l2_port(self):
        return self.topology.tx_l2_ac_port_reg.hld_obj

    def get_tx_l2_port_def(self):
        return self.topology.tx_l2_ac_port_def.hld_obj

    def get_tx_sys_port(self):
        return self.topology.tx_svi_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_svi_eth_port_def.sys_port.hld_obj


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_svi_g_mc(ipv6_g_mc):
    RX_SVI_GID = 0x2a

    l3_port_impl_class = T.ip_svi_base
    output_serdes = T.FIRST_SERDES_SVI
    ip_impl = ip_test_base.ipv6_test_base()
    svi = True

    def setUp(self):
        # MATILDA_SAVE -- need review
        if (mc_base.BRIDGE_SLICE not in self.device.get_used_slices()):
            self.skipTest("This device cannot be used in Mathilda Mode")
            return

        ipv6_g_mc.setUp(self)
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        # Add subnet for DC pass
        subnet = self.ip_impl.build_prefix(ipv6_mc.SIP, length=32)
        self.ip_impl.add_subnet(self.topology.rx_l3_ac, subnet)

        # Add route for DC fail
        nh = T.next_hop(self, self.device, mc_base.NH_GID, mc_base.NH_MAC, self.topology.rx_l3_ac)
        fec = T.fec(self, self.device, nh)
        prefix = self.ip_impl.build_prefix(ipv6_mc.SIP_FEC, length=32)
        self.ip_impl.add_route(self.topology.vrf, prefix, fec, mc_base.PRIVATE_DATA)

        # Create port in rx_svi to receive bridge copies
        self.eth_port1 = T.ethernet_port(
            self,
            self.device,
            mc_base.BRIDGE_SLICE,
            mc_base.BRIDGE_IFG,
            mc_base.BRIDGE_SYS_PORT1_GID,
            mc_base.BRIDGE_SERDES1,
            mc_base.BRIDGE_SERDES1 + 1)
        self.ac_port1 = T.l2_ac_port(self, self.device, mc_base.BRIDGE_AC_PORT1_GID, None, self.topology.rx_switch,
                                     self.eth_port1, T.RX_MAC, T.RX_L2_AC_PORT_VID1, T.RX_L2_AC_PORT_VID2)
        self.mc_group.add(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj, self.eth_port1.sys_port.hld_obj)

        self.eth_port2 = T.ethernet_port(
            self,
            self.device,
            mc_base.BRIDGE_SLICE,
            mc_base.BRIDGE_IFG,
            mc_base.BRIDGE_SYS_PORT2_GID,
            mc_base.BRIDGE_SERDES2,
            mc_base.BRIDGE_SERDES2 + 1)
        self.ac_port2 = T.l2_ac_port(self, self.device, mc_base.BRIDGE_AC_PORT2_GID, None, self.topology.rx_switch,
                                     self.eth_port2, T.RX_MAC, T.RX_L2_AC_PORT_VID1, T.RX_L2_AC_PORT_VID2)
        self.mc_group.add(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)

        self.rxsw_floodset = self.device.create_l2_multicast_group(mc_base.MC_GROUP_GID + 5, sdk.la_replication_paradigm_e_EGRESS)
        self.rxsw_floodset.add(self.ac_port1.hld_obj, self.eth_port1.sys_port.hld_obj)
        self.rxsw_floodset.add(self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)
        self.topology.rx_switch.hld_obj.set_flood_destination(self.rxsw_floodset)

        self.rxsw_mrouter = self.device.create_l2_multicast_group(mc_base.MC_GROUP_GID + 6, sdk.la_replication_paradigm_e_EGRESS)
        self.rxsw_mrouter.add(self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)

        self.topology.rx_switch.hld_obj.set_ipv6_multicast_enabled(True)
        self.rxsw_snoop = self.device.create_l2_multicast_group(mc_base.MC_GROUP_GID + 7, sdk.la_replication_paradigm_e_EGRESS)
        self.rxsw_snoop.add(self.ac_port1.hld_obj, self.eth_port1.sys_port.hld_obj)
        self.rxsw_snoop.add(self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)

    def construct_packet(self, mc_mac, source_ip):
        INPUT_PACKET_BASE = \
            Ether(dst=ipv6_mc.get_mc_sa_addr_str(mc_mac), src=mc_base.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            IPv6(src=source_ip.addr_str, dst=mc_mac.addr_str, hlim=mc_base.TTL, plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=ipv6_mc.get_mc_sa_addr_str(mc_mac), src=T.TX_SVI_MAC.addr_str) / \
            IPv6(src=source_ip.addr_str, dst=mc_mac.addr_str, hlim=mc_base.TTL - 1, plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

        self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
        self.EXPECTED_OUTPUT_PACKET_DEF = self.EXPECTED_OUTPUT_PACKET

    def construct_snoop_packet(self):
        self.EXPECTED_OUTPUT_PACKET_SNOOP = \
            Ether(dst=mc_base.HOST_MAC_ADDR, src=mc_base.PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=mc_base.MIRROR_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6_COLLAPSED_MC,
                 next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                 code=mc_base.MIRROR_CMD_INGRESS_GID,
                 source_sp=T.RX_SYS_PORT_GID,
                 destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=T.RX_SVI_GID,
                 destination_lp=0,
                 relay_id=T.VRF_GID,
                 lpts_flow_type=0) / \
            self.INPUT_PACKET

    # For all tests:
    # 1. construct input and expected output packets (with required mc_mac and sip)
    # 2. construct any expected cpu packets (trap or snoop packets)
    # 3. set the rpf value (for rpf pass or rpf fail)
    # 4. set trap boolean, if set to True, it is a trap otherwise snoop
    #    this value is used in base class to construct the expected_packets list
    # 5. set pcount - packet count
    #    this value is used in base class to verify the counters
    # 6. set svi to True, when incoming packet is on svi, packet may be bridged in
    #    some test cases. This value is used in base class to verify if the
    #    expected_packets list should include bridged copies or not
    # The original cases with 'none' rpf are also maintained. They are considered
    # rpf pass cases with directly connected check pass or fail.
    #
    # For (*,g) miss cases, different mc mac is used.
    # For DC fail cases (directly connected check fail), different source ip is used.
    # For RPF fail cases, rx_svi1 is used.

    #(*,g) miss cases are yet to be done. Commenting these test cases for now, until,
    # NPL changes are ready

    @unittest.skipIf(True, "Awaiting NPL support for this test")
    #(*,g) miss, dc fail Action: snoop and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_route_gmiss_dcfail(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR_MISS, ipv6_mc.SIP_DCFAIL)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = False
        self.trap = True
        self.do_test_route(extra_packet=snoop_packet)

    @unittest.skipIf(True, "Awaiting NPL support for this test")
    #(*,g) miss, dc fail Action: snoop and bridge
    def test_route_gmiss_dcfail_ir(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR_MISS, ipv6_mc.SIP_DCFAIL)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = False
        self.trap = True
        self.do_test_route_ir(extra_packet=snoop_packet)

    @unittest.skipIf(True, "Awaiting NPL support for this test")
    #(*,g) miss, dc fail Action: snoop and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_route_gmiss_dcfail_fec(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR_MISS, ipv6_mc.SIP_FEC)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = False
        self.trap = True
        self.do_test_route(extra_packet=snoop_packet)

    @unittest.skipIf(True, "Awaiting NPL support for this test")
    #(*,g) miss, dc fail Action: snoop and bridge
    def test_route_gmiss_dcfail_fec_ir(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR_MISS, ipv6_mc.SIP_FEC)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = False
        self.trap = True
        self.do_test_route_ir(extra_packet=snoop_packet)

    @unittest.skipIf(True, "Awaiting NPL support for this test")
    #(*,g) miss, dc pass Action: snoop and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_route_gmiss_dcpass(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR_MISS, ipv6_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = False
        self.trap = True
        self.do_test_route(extra_packet=snoop_packet)

    @unittest.skipIf(True, "Awaiting NPL support for this test")
    #(*,g) miss, dc pass Action: snoop and bridge
    def test_route_gmiss_dcpass_ir(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR_MISS, ipv6_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = False
        self.trap = True
        self.do_test_route_ir(extra_packet=snoop_packet)

    #(*,g) none rpf, dc fail Action: forward and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_nonerpf_dcfail(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_DCFAIL)
        self.rpf_intf = None
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route()

    #(*,g) none rpf, dc fail Action: forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_nonerpf_dcfail_ir(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_DCFAIL)
        self.rpf_intf = None
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route_ir()

    #(*,g) none rpf, dc fail Action: forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_nonerpf_dcfail_fec(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_FEC)
        self.rpf_intf = None
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route()

    #(*,g) none rpf, dc fail Action: forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_nonerpf_dcfail_fec_ir(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_FEC)
        self.rpf_intf = None
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route_ir()

    #(*,g) none rpf, dc pass Action: snoop, forward and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_nonerpf_dcpass(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = None
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route(extra_packet=snoop_packet)

    #(*,g) none rpf, dc pass Action: snoop, forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_nonerpf_dcpass_ir(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = None
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route_ir(extra_packet=snoop_packet)

    #(*,g) hit rpf-fail, dc fail Action: snoop and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpffail_dcfail(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True

        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_DCFAIL)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi1.hld_obj
        self.is_mcast_route_hit = True
        self.trap = True
        self.do_test_route(extra_packet=snoop_packet)

    #(*,g) hit rpf-fail, dc fail Action: snoop and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpffail_dcfail_ir(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True

        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_DCFAIL)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi1.hld_obj
        self.is_mcast_route_hit = True
        self.trap = True
        self.do_test_route_ir(extra_packet=snoop_packet)

    #(*,g) hit rpf-fail, dc fail Action: snoop and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpffail_dcfail_fec(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True

        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_FEC)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi1.hld_obj
        self.is_mcast_route_hit = True
        self.trap = True
        self.do_test_route(extra_packet=snoop_packet)

    #(*,g) hit rpf-fail, dc fail Action: snoop and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpffail_dcfail_fec_ir(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True

        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_FEC)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi1.hld_obj
        self.is_mcast_route_hit = True
        self.trap = True
        self.do_test_route_ir(extra_packet=snoop_packet)

    #(*,g) hit rpf-fail, dc pass Action: snoop and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpffail_dcpass(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True

        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi1.hld_obj
        self.is_mcast_route_hit = True
        self.trap = True
        self.do_test_route(extra_packet=snoop_packet)

    #(*,g) hit rpf-fail, dc pass Action: snoop and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpffail_dcpass_ir(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True

        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi1.hld_obj
        self.is_mcast_route_hit = True
        self.trap = True
        self.do_test_route_ir(extra_packet=snoop_packet)

    #(*,g) hit rpf-pass, dc fail Action: forward and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpfpass_dcfail(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_DCFAIL)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route()

    #(*,g) hit rpf-pass, dc fail Action: forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpfpass_dcfail_ir(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_DCFAIL)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route_ir()

    #(*,g) hit rpf-pass, dc fail Action: forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpfpass_dcfail_fec(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_FEC)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route()

    #(*,g) hit rpf-pass, dc fail Action: forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpfpass_dcfail_fec_ir(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP_FEC)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route_ir()

    #(*,g) hit rpf-pass, dc pass Action: snoop forward and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpfpass_dcpass(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route(extra_packet=snoop_packet)

    #(*,g) hit rpf-pass, dc pass Action: snoop forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpfpass_dcpass_ir(self):
        self.construct_packet(ipv6_g_mc.MC_GROUP_ADDR, ipv6_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route_ir(extra_packet=snoop_packet)

    def get_tx_l2_port(self):
        return self.topology.tx_l2_ac_port_reg.hld_obj

    def get_tx_l2_port_def(self):
        return self.topology.tx_l2_ac_port_def.hld_obj

    def get_tx_sys_port(self):
        return self.topology.tx_svi_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_svi_eth_port_def.sys_port.hld_obj


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_mulitcast_disabled(sdk_multi_test_case_base):
    ttl = 127
    mc_group_addr = T.ipv6_addr('ff01:0:0:0:0:1:ffe8:658f')
    src_mac = T.mac_addr('be:ef:5d:35:7a:35')

    def setUp(self):
        super().setUp()
        mc_base.create_l2_ports(self)
        self.create_packets()

    def create_packets(self):
        INPUT_PACKET_BASE = \
            Ether(dst=ipv6_mc.get_mc_sa_addr_str(self.mc_group_addr), src=self.src_mac.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            IPv6(src=ipv6_mc.SIP.addr_str, dst=self.mc_group_addr.addr_str, hlim=self.ttl, plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=ipv6_mc.get_mc_sa_addr_str(self.mc_group_addr), src=self.src_mac.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            IPv6(src=ipv6_mc.SIP.addr_str, dst=self.mc_group_addr.addr_str, hlim=self.ttl, plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

        self.input_packet, self.output_packet = pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    def test_multicast_disabled(self):
        # IPV4_MC protocol is disabled on rx_svi, packet should be flooded on ingress vlan.
        ingress_packet = {'data': self.input_packet, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        egress_packets = []
        egress_packets.append({'data': self.output_packet, 'slice': T.RX_SLICE,
                               'ifg': T.RX_IFG, 'pif': mc_base.SERDES4})
        egress_packets.append({'data': self.output_packet, 'slice': T.RX_SLICE,
                               'ifg': T.RX_IFG, 'pif': mc_base.SERDES6})
        U.run_and_compare_list(self, self.device, ingress_packet, egress_packets)


@unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
class ipv6_mulitcast_stp_block(sdk_multi_test_case_base):
    ttl = 127
    mc_group_addr = T.ipv6_addr('ff01:0:0:0:0:1:ffe8:658f')
    src_mac = T.mac_addr('be:ef:5d:35:7a:35')

    def setUp(self):
        super().setUp()
        self.create_packets()
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)
        self.topology.tx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        self.mc_group = self.device.create_ip_multicast_group(mc_base.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group.add(
            self.topology.tx_svi.hld_obj,
            self.topology.tx_l2_ac_port_reg.hld_obj,
            self.topology.tx_svi_eth_port_reg.sys_port.hld_obj)
        self.mc_group.add(
            self.topology.tx_svi.hld_obj,
            self.topology.tx_l2_ac_port_def.hld_obj,
            self.topology.tx_svi_eth_port_def.sys_port.hld_obj)

    def create_packets(self):
        INPUT_PACKET_BASE = \
            Ether(dst=ipv6_mc.get_mc_sa_addr_str(self.mc_group_addr), src=self.src_mac.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            IPv6(src=ipv6_mc.SIP.addr_str, dst=self.mc_group_addr.addr_str, hlim=self.ttl, plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=ipv6_mc.get_mc_sa_addr_str(self.mc_group_addr),
                                            src=T.TX_SVI_MAC.addr_str) / IPv6(src=ipv6_mc.SIP.addr_str,
                                                                              dst=self.mc_group_addr.addr_str,
                                                                              hlim=self.ttl - 1,
                                                                              plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

        self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)

    def do_test_route(self):
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.mc_group_addr.hld_obj, self.mc_group, None, False, False, None)
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': T.FIRST_SERDES_SVI})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_SVI})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def test_incoming_port_stp_block(self):
        self.do_test_route()
        self.topology.rx_l2_ac_port.hld_obj.set_stp_state(sdk.la_port_stp_state_e_BLOCKING)
        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
def setUpModule():
    sdk_multi_test_case_base.initialize()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
def tearDownModule():
    sdk_multi_test_case_base.destroy()


if __name__ == '__main__':
    unittest.main()
