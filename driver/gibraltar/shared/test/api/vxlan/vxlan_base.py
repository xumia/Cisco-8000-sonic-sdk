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
from leaba import hldcli
import test_hldcli
import packet_test_utils as U
import scapy.all as S
import topology as T
import packet_test_defs as P
import ip_test_base
import time
import nplapicli as nplapi
import decor
from enum import Enum


class tunnel_mode(Enum):
    ENCAP_DECAP = 0
    ENCAP_ONLY = 1
    DECAP_ONLY = 2
    DEFAULT = 3


class vxlan_base(unittest.TestCase):
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    INNER_TTL = 200
    OUTER_TTL = 255
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    OUTPUT_VID = 0xac
    INGRESS_UMC_GROUP_GID = 0x40
    INGRESS_OMC_GROUP_GID = 0x50
    L2MC_GROUP_GID = 0x10
    L3MC_GROUP_GID = 0x20
    UND_MC_GROUP_GID = 0x30
    L3MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')
    L3MC_GROUP_ADDR_V6 = T.ipv6_addr('ff01:0:0:0:0:1:ffe8:658f')
    UND_MC_GROUP_ADDR = T.ipv4_addr('225.4.5.6')
    L2_MC_GROUP_ADDR = T.ipv4_addr('225.6.7.9')

    def setUp(self):

        self.maxDiff = None  # Show whole strings on failures (unittest variable)
        self.device = U.sim_utils.create_device(1)
        # self.device.nsim_provider.set_logging(True)

        self.topology = T.topology(self, self.device)

        self.topology.tx_l3_ac_eth_port_def.hld_obj.set_service_mapping_type(sdk.la_ethernet_port.service_mapping_type_e_SMALL)

        self.l3_port_impl = T.ip_l3_ac_base(self.topology)

        self.add_default_route()
        # self.setup_recycle_port()

        self.vxlan_2_pass_test = False

    def tearDown(self):
        self.device.tearDown()

    def add_default_route(self):
        prefix = self.underlay_ip_impl.get_default_prefix()
        self.underlay_ip_impl.add_route(self.topology.vrf, prefix,
                                        self.l3_port_impl.def_nh,
                                        vxlan_base.PRIVATE_DATA_DEFAULT)
        self.has_default_route = True

    def destroy_default_route(self):
        if self.has_default_route:
            prefix = self.underlay_ip_impl.get_default_prefix()
            self.underlay_ip_impl.delete_route(self.topology.vrf, prefix)
            self.has_default_route = False

    def setup_recycle_port(self):
        for slice in [1, 3, 5]:
            rcy_port = T.recycle_sys_port(self, self.device, slice, T.PI_IFG + 1, T.RCY_SYS_PORT_GID_BASE - slice - 12)


class vxlan_next_hop:
    def __init__(self, device, mac_addr, l3_port, vxlan_l2_port=None):
        self.device = device
        self.mac_addr = mac_addr
        self.hld_obj = self.device.create_vxlan_next_hop(mac_addr.hld_obj, l3_port.hld_obj, vxlan_l2_port)

    def destroy(self):
        if self.hld_obj is not None:
            self.device.destroy(self.hld_obj)
        self.hld_obj = None


def get_vxlan_lb_hash(device, lb_vector, stage):
    group_size = 1
    seed = 65535
    shift_amount = hldcli.get_lb_hash_shift_amount(device)
    out_hash = hldcli.resolution_utils_do_lb_resolution(lb_vector,
                                                        group_size,
                                                        nplapi.NPL_LB_CONSISTENCY_MODE_CONSISTENCE_ENABLED,
                                                        stage,
                                                        seed,
                                                        shift_amount)
    return out_hash & 0x0FFF  # NPL only uses lower 12 bits


class vxlan_l2_single_port(vxlan_base):
    IPv4_ADDRESS_SIZE = T.ipv4_addr.NUM_OF_BYTES
    IPv6_ADDRESS_SIZE = T.ipv6_addr.NUM_OF_BYTES
    NEW_TX_L3_AC_DEF_MAC = T.mac_addr('50:52:53:54:55:56')
    NEW_TX_L3_AC_REG_MAC = T.mac_addr('60:62:63:64:65:66')
    NEW_TX_L3_AC_EXT_MAC = T.mac_addr('70:72:73:74:75:76')
    VXLAN_L2_PORT_GID = 0x250
    VXLAN_DECAP_PORT_GID = 0x1ffff
    VXLAN_SIP = T.ipv4_addr('12.10.12.11')
    VXLAN_DIP = T.ipv4_addr('12.1.95.250')
    VXLAN_SIP2 = T.ipv4_addr('24.20.24.22')
    VXLAN_DIP2 = T.ipv4_addr('24.2.190.240')
    VXLAN_UC_DIP = T.ipv4_addr('12.1.95.250')
    #VXLAN_DIP_ANY = T.ipv4_addr('15.1.85.200')
    VXLAN_DIP_ANY = T.ipv4_addr('0.0.0.0')
    VXLAN_MCAST_DIP = T.ipv4_addr('224.0.0.0')
    VXLAN_SRC_MAC = T.mac_addr('06:12:34:56:78:9a')
    VXLAN_DST_MAC = T.mac_addr('08:bc:de:23:45:67')
    L2_SRC_MAC = T.mac_addr('02:11:22:33:44:55')
    L2_DST_MAC = T.mac_addr('04:66:77:88:99:aa')
    DUMMY_SVI_MAC = T.mac_addr('30:32:33:34:35:36')
    DUMMY_SVI_NH_GID = 0x123
    DUMMY_SVI_NH_MAC = T.mac_addr('20:22:23:24:25:26')
    OUTER_SRC_MAC = '00:11:22:33:44:55'
    SDA_MAC = T.mac_addr('10:12:13:14:15:16')
    RESERVED_SMAC = T.mac_addr('00:00:00:00:00:01')
    RECYCLE_PORT_MAC = T.mac_addr('00:11:22:33:44:55')
    RECYCLE_PORT_MAC2 = T.mac_addr('00:22:44:66:88:11')
    RCY_DST_MAC = T.mac_addr('07:66:77:88:99:aa')
    L2_UCAST_MAC = T.mac_addr('ca:fe:ca:fe:ca:fe')
    L2_MCAST_MAC = T.mac_addr('01:00:5e:00:00:01')
    L2_IPV6_MCAST_MAC = T.mac_addr('33:33:00:00:00:01')
    L2_BCAST_MAC = T.mac_addr('ff:ff:ff:ff:ff:ff')
    MC_GROUP_GID = 0x13
    SIP = T.ipv4_addr('12.10.12.10')
    PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
    HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
    SYS_PORT_GID_BASE = 23
    IN_SP_GID = SYS_PORT_GID_BASE
    OUT_SP_GID = SYS_PORT_GID_BASE + 1
    PI_SP_GID = SYS_PORT_GID_BASE + 2
    PI_SLICE = T.get_device_slice(3)
    PI_IFG = T.get_device_ifg(1)
    PI_PIF_FIRST = T.get_device_first_serdes(8)
    PUNT_VLAN = 0xA13
    MIRROR_CMD_GID = 9

    MIRROR_GID_INGRESS_OFFSET = 32
    MIRROR_GID_EGRESS_OFFSET = 0
    MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
    MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET
    MIRROR_VLAN = 0xA12
    VXLAN_SIP_PREFIX = ip_test_base.ipv4_test_base.build_prefix(VXLAN_SIP, length=32)
    VXLAN_SIP2_PREFIX = ip_test_base.ipv4_test_base.build_prefix(VXLAN_SIP2, length=32)
    TUNNEL_MODE = tunnel_mode.DEFAULT
    IR = False

    def setUp(self):
        super().setUp()
        vxlan_l2_single_port.PI_SLICE = T.choose_active_slices(self.device, vxlan_l2_single_port.PI_SLICE, [3, 1, 5])

    def is_ipv6(self):
        if self.underlay_ip_impl.BYTES_NUM_IN_ADDR == self.IPv6_ADDRESS_SIZE:
            return True
        else:
            return False

    def set_vxlan_dip(self, dip):
        vxlan_l2_single_port.VXLAN_DIP = T.ipv4_addr(dip)

    def set_vxlan_sip_prefix(self, sip, length):
        vxlan_l2_single_port.VXLAN_SIP_PREFIX = ip_test_base.ipv4_test_base.build_prefix(T.ipv4_addr(sip), length)

    def set_ingress_rep(self, ir):
        vxlan_l2_single_port.IR = ir

    def set_l2_multicast(self, l2_mc):
        self.topology.tx_switch.hld_obj.set_ipv4_multicast_enabled(l2_mc)
        self.topology.tx_switch.hld_obj.set_ipv6_multicast_enabled(l2_mc)

    def create_recycle_ac_port(self):
        # MATILDA_SAVE -- need review
        # if non of the odd slices are active, than crush.
        default_slice = T.get_device_slice(1)
        slice_for_recycle = T.choose_active_slices(self.device, default_slice, [1, 3, 5])

        self.recycle_eth_port = self.device.create_ethernet_port(
            self.topology.recycle_ports[slice_for_recycle].sys_port.hld_obj,
            sdk.la_ethernet_port.port_type_e_AC)
        self.recycle_eth_port.set_ac_profile(self.topology.ac_profile_def.hld_obj)
        self.recycle_l2_ac_port = self.device.create_ac_l2_service_port(
            T.RX_L2_AC_PORT_GID + 0x200,
            self.recycle_eth_port,
            T.RX_L2_AC_PORT_VID1,
            0,
            self.topology.filter_group_def,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)

        self.recycle_l2_ac_port.attach_to_switch(self.topology.rx_switch1.hld_obj)
        self.recycle_l2_ac_port.set_stp_state(sdk.la_port_stp_state_e_FORWARDING)

        self.topology.rx_switch.hld_obj.set_mac_entry(
            vxlan_l2_single_port.RCY_DST_MAC.hld_obj,
            self.recycle_l2_ac_port,
            sdk.LA_MAC_AGING_TIME_NEVER)
        self.topology.rx_switch1.hld_obj.set_mac_entry(
            vxlan_l2_single_port.RCY_DST_MAC.hld_obj,
            self.topology.rx_l2_ac_port1.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        self.recycle_l3_ac_port = self.device.create_l3_ac_port(
            T.RX_L3_AC_GID + 0x200,
            self.recycle_eth_port,
            0x567,
            0,
            vxlan_l2_single_port.RECYCLE_PORT_MAC.hld_obj,
            self.topology.vrf.hld_obj,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)

        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        self.recycle_nh = self.device.create_next_hop(
            T.NH_L3_AC_REG_GID + 0x100,
            vxlan_l2_single_port.RECYCLE_PORT_MAC.hld_obj,
            self.recycle_l3_ac_port,
            sdk.la_next_hop.nh_type_e_NORMAL)

        # Set the vlan for the tx side for l3 ac
        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0x8100
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = 0x567

        self.recycle_l3_ac_port.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

        # Create second Recycle L3 AC for decap
        self.recycle_l3_ac_port_decap = self.device.create_l3_ac_port(
            T.RX_L3_AC_GID + 0x300,
            self.recycle_eth_port,
            0x577,
            0,
            vxlan_l2_single_port.RECYCLE_PORT_MAC2.hld_obj,
            self.topology.vrf.hld_obj,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)

        self.recycle_l3_ac_port_decap.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.recycle_l3_ac_port_decap.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        self.recycle_l3_ac_port_decap.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        self.recycle_l3_ac_port_decap.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        self.recycle_nh_decap = self.device.create_next_hop(
            T.NH_L3_AC_REG_GID + 0x200,
            vxlan_l2_single_port.RECYCLE_PORT_MAC2.hld_obj,
            self.recycle_l3_ac_port_decap,
            sdk.la_next_hop.nh_type_e_NORMAL)

        # Set the vlan for the tx side for l3 ac
        tag1 = sdk.la_vlan_tag_t()
        tag1.tpid = 0x8100
        tag1.tci.fields.pcp = 0
        tag1.tci.fields.dei = 0
        tag1.tci.fields.vid = 0x577

        self.recycle_l3_ac_port_decap.set_egress_vlan_tag(tag1, sdk.LA_VLAN_TAG_UNTAGGED)

    def destroy_recycle_ac_port(self):
        self.device.destroy(self.recycle_nh)
        self.device.destroy(self.recycle_nh_decap)
        self.device.destroy(self.recycle_l3_ac_port)
        self.device.destroy(self.recycle_l3_ac_port_decap)
        self.device.destroy(self.recycle_l2_ac_port)
        self.device.destroy(self.recycle_eth_port)

    def create_recycle_ac_port_spa(self):
        self.recycle_spa_port = self.device.create_spa_port(1)

        # MATILDA_SAVE -- need review

        for slice_id in [1, 3, 5]:
            if slice_id in self.device.get_used_slices():
                self.recycle_spa_port.add(self.topology.recycle_ports[slice_id].sys_port.hld_obj)
                self.recycle_spa_port.set_member_transmit_enabled(self.topology.recycle_ports[slice_id].sys_port.hld_obj, True)

        self.recycle_eth_port = self.device.create_ethernet_port(self.recycle_spa_port, sdk.la_ethernet_port.port_type_e_AC)
        self.recycle_eth_port.set_ac_profile(self.topology.ac_profile_def.hld_obj)
        self.recycle_l2_ac_port = self.device.create_ac_l2_service_port(
            T.RX_L2_AC_PORT_GID + 0x100,
            self.recycle_eth_port,
            0x123,
            0,
            self.topology.filter_group_def,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)

        self.recycle_l3_ac_port = self.device.create_l3_ac_port(
            T.RX_L3_AC_GID + 0x100,
            self.recycle_eth_port,
            0x567,
            0,
            vxlan_l2_single_port.RECYCLE_PORT_MAC.hld_obj,
            self.topology.vrf.hld_obj,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)

        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        self.recycle_l3_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        self.recycle_nh = self.device.create_next_hop(
            T.NH_L3_AC_REG_GID + 0x100,
            vxlan_l2_single_port.RECYCLE_PORT_MAC.hld_obj,
            self.recycle_l3_ac_port,
            sdk.la_next_hop.nh_type_e_NORMAL)
        # self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)

        # Set the vlan for the tx side for l3 ac
        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0x8100
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = 0x567

        self.recycle_l3_ac_port.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

    def setup_vxlan_2_pass(self):
        self.vxlan_l2_port.set_l3_destination(self.recycle_nh)
        self.vxlan_2_pass_test = True

    def single_port_setup(self, set_mode=tunnel_mode.DEFAULT, set_l3_filter=False):
        # make the l3 port address unicast mac address
        self.topology.tx_l3_ac_def.hld_obj.set_mac(
            vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.hld_obj)
        self.topology.tx_l3_ac_reg.hld_obj.set_mac(
            vxlan_l2_single_port.NEW_TX_L3_AC_REG_MAC.hld_obj)
        self.topology.tx_l3_ac_ext.hld_obj.set_mac(
            vxlan_l2_single_port.NEW_TX_L3_AC_EXT_MAC.hld_obj)

        # enable ipv4 and ipv6 forwarding
        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, True)
        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_MC, True)
        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_MC, True)
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, True)
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_MC, True)
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_MC, True)

        # set up mac forwarding entry for l2 payload
        self.topology.tx_switch.hld_obj.set_mac_entry(
            vxlan_l2_single_port.L2_DST_MAC.hld_obj,
            self.topology.tx_l2_ac_port_def.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)
        self.topology.rx_switch.hld_obj.set_mac_entry(
            vxlan_l2_single_port.L2_DST_MAC.hld_obj,
            self.topology.rx_l2_ac_port.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        # create ecmp group

        self.unl_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.unl_ecmp_attached_members = [self.l3_port_impl.def_nh]
        for member in self.unl_ecmp_attached_members:
            self.unl_ecmp.add_member(member.hld_obj)

        # now let's create L2 VXLAN port
        if set_mode == tunnel_mode.DEFAULT:
            # call the old API
            self.vxlan_l2_port = self.device.create_vxlan_l2_service_port(
                vxlan_l2_single_port.VXLAN_L2_PORT_GID,
                vxlan_l2_single_port.VXLAN_SIP.hld_obj,
                vxlan_l2_single_port.VXLAN_DIP.hld_obj,
                self.topology.vrf.hld_obj)
            mode = sdk.la_ip_tunnel_mode_e_ENCAP_DECAP
        else:
            if set_mode == tunnel_mode.ENCAP_DECAP:
                mode = sdk.la_ip_tunnel_mode_e_ENCAP_DECAP
            elif set_mode == tunnel_mode.ENCAP_ONLY:
                mode = sdk.la_ip_tunnel_mode_e_ENCAP_ONLY
            elif set_mode == tunnel_mode.DECAP_ONLY:
                mode = sdk.la_ip_tunnel_mode_e_DECAP_ONLY
                self.vxlan_l2_port_dummy = self.device.create_vxlan_l2_service_port(
                    vxlan_l2_single_port.VXLAN_L2_PORT_GID + 0x100,
                    mode,
                    vxlan_l2_single_port.VXLAN_SIP2_PREFIX,
                    vxlan_l2_single_port.VXLAN_DIP2.hld_obj,
                    self.topology.vrf.hld_obj)

            self.vxlan_l2_port = self.device.create_vxlan_l2_service_port(
                vxlan_l2_single_port.VXLAN_L2_PORT_GID,
                mode,
                vxlan_l2_single_port.VXLAN_SIP_PREFIX,
                vxlan_l2_single_port.VXLAN_DIP.hld_obj,
                self.topology.vrf.hld_obj)

        self.vxlan_l2_port.set_l3_destination(self.l3_port_impl.def_nh.hld_obj)

        # set VNI the on the switch/BD
        if mode != sdk.la_ip_tunnel_mode_e_DECAP_ONLY:
            self.vxlan_l2_port.set_encap_vni(self.topology.rx_switch.hld_obj, 9999)
            self.vxlan_l2_port.set_encap_vni(self.topology.tx_switch.hld_obj, 10000)

            self.vxlan_encap_counter = self.device.create_counter(1)
            self.topology.rx_switch.hld_obj.set_vxlan_encap_counter(self.vxlan_encap_counter)

            self.tunnel_encap_counter = self.device.create_counter(1)
            self.vxlan_l2_port.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.tunnel_encap_counter)

        if mode != sdk.la_ip_tunnel_mode_e_ENCAP_ONLY:
            self.topology.rx_switch.hld_obj.set_decap_vni(9999)
            self.topology.tx_switch.hld_obj.set_decap_vni(10000)

            self.vxlan_decap_counter = self.device.create_counter(1)
            self.topology.rx_switch.hld_obj.set_vxlan_decap_counter(self.vxlan_decap_counter)

            self.tunnel_decap_counter = self.device.create_counter(1)
            self.vxlan_l2_port.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.tunnel_decap_counter)

        # set vxlan mac to forwarding table
        self.topology.rx_switch.hld_obj.set_mac_entry(
            vxlan_l2_single_port.VXLAN_DST_MAC.hld_obj,
            self.vxlan_l2_port,
            sdk.LA_MAC_AGING_TIME_NEVER)

        self.topology.tx_switch.hld_obj.set_mac_entry(
            vxlan_l2_single_port.VXLAN_DST_MAC.hld_obj,
            self.vxlan_l2_port,
            sdk.LA_MAC_AGING_TIME_NEVER)

        # set L2 filter group
        self.filter_group = self.device.create_filter_group()
        self.filter_group.set_filtering_mode(self.filter_group, sdk.la_filter_group.filtering_mode_e_DENY)
        self.vxlan_l2_port.set_filter_group(self.filter_group)

        vxlan_l2_single_port.TUNNEL_MODE = set_mode

        self.ingress_umc_group = self.device.create_ip_multicast_group(
            self.INGRESS_UMC_GROUP_GID, sdk.la_replication_paradigm_e_INGRESS)
        self.ingress_omc_group = self.device.create_ip_multicast_group(
            self.INGRESS_OMC_GROUP_GID, sdk.la_replication_paradigm_e_INGRESS)

        if set_l3_filter:
            # set filter group for L3
            self.filter_group_l3_ac = self.device.create_filter_group()
            self.filter_group_l3_ac.set_filtering_mode(self.filter_group_l3_ac, sdk.la_filter_group.filtering_mode_e_DENY)

            self.recycle_l3_ac_port.set_filter_group(self.filter_group_l3_ac)
            self.recycle_l3_ac_port_decap.set_filter_group(self.filter_group_l3_ac)

    def setup_ecmp(self):
        self.vxlan_l2_port.set_l3_destination(self.unl_ecmp)

    def single_port_destroy(self, set_mode=tunnel_mode.DEFAULT):
        self.topology.rx_switch.hld_obj.remove_mac_entry(
            vxlan_l2_single_port.VXLAN_DST_MAC.hld_obj)
        self.topology.tx_switch.hld_obj.remove_mac_entry(
            vxlan_l2_single_port.VXLAN_DST_MAC.hld_obj)
        if set_mode != tunnel_mode.DECAP_ONLY:
            self.vxlan_l2_port.clear_encap_vni(self.topology.rx_switch.hld_obj)
            self.vxlan_l2_port.clear_encap_vni(self.topology.tx_switch.hld_obj)
        if set_mode != tunnel_mode.ENCAP_ONLY:
            self.topology.rx_switch.hld_obj.clear_decap_vni()
            self.topology.tx_switch.hld_obj.clear_decap_vni()
        self.device.destroy(self.vxlan_l2_port)
        self.device.destroy(self.unl_ecmp)
        self.device.destroy(self.ingress_umc_group)
        self.device.destroy(self.ingress_omc_group)

    def create_overlay_l2_mc_group(self):

        self.mc_group = self.device.create_l2_multicast_group(
            vxlan_l2_single_port.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(self.mc_group)
        self.topology.tx_switch.hld_obj.set_flood_destination(self.mc_group)
        self.mc_group.add(self.topology.tx_l2_ac_port_ext.hld_obj,
                          self.topology.tx_svi_eth_port_ext.sys_port.hld_obj)
        self.mc_group.add(self.topology.tx_l2_ac_port_def.hld_obj,
                          self.topology.tx_svi_eth_port_def.sys_port.hld_obj)

    def destroy_overlay_l2_mc_group(self):

        self.mc_group.remove(self.topology.tx_l2_ac_port_ext.hld_obj)
        self.mc_group.remove(self.topology.tx_l2_ac_port_def.hld_obj)
        self.topology.tx_switch.hld_obj.set_flood_destination(None)
        self.device.destroy(self.mc_group)

    def setup_snoop(self):

        # setup inject port
        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            vxlan_l2_single_port.PI_SLICE,
            vxlan_l2_single_port.PI_IFG,
            vxlan_l2_single_port.PI_SP_GID,
            vxlan_l2_single_port.PI_PIF_FIRST,
            vxlan_l2_single_port.PUNT_INJECT_PORT_MAC_ADDR)

        self.punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.pi_port,
            vxlan_l2_single_port.HOST_MAC_ADDR,
            vxlan_l2_single_port.PUNT_VLAN)

        self.mirror_cmd = T.create_l2_mirror_command(
            self.device,
            vxlan_l2_single_port.MIRROR_CMD_INGRESS_GID,
            self.pi_port,
            vxlan_l2_single_port.HOST_MAC_ADDR,
            vxlan_l2_single_port.MIRROR_VLAN)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT)
        self.device.set_snoop_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT, 0, False, False, self.mirror_cmd)
        self.device.clear_trap_configuration(sdk.LA_EVENT_APP_IP_INACTIVITY)
        self.device.set_snoop_configuration(sdk.LA_EVENT_APP_IP_INACTIVITY, 0, False, False, self.mirror_cmd)

    def snoop_destroy(self):
        self.device.clear_snoop_configuration(sdk.LA_EVENT_ETHERNET_BCAST_PKT)
        self.device.clear_snoop_configuration(sdk.LA_EVENT_APP_IP_INACTIVITY)
        self.device.destroy(self.mirror_cmd)
        self.device.destroy(self.punt_dest)
        self.pi_port.destroy()

    def get_prefix_length(self):
        if self.underlay_ip_impl.BYTES_NUM_IN_ADDR == self.IPv6_ADDRESS_SIZE:
            length = 128
        if self.underlay_ip_impl.BYTES_NUM_IN_ADDR == self.IPv4_ADDRESS_SIZE:
            length = 32
        return length

    def l3vxlan_setup(self):
        # create dummy switch
        self.dummy_switch = T.switch(self, self.device, T.RX_SWITCH_GID + 0x100)
        # create the SVI port for the dummy switch
        self.dummy_svi = T.svi_port(
            self,
            self.device,
            T.RX_SVI_GID + 0x200,
            self.dummy_switch,
            self.topology.vrf,
            vxlan_l2_single_port.DUMMY_SVI_MAC)

        self.dummy_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.dummy_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        self.dummy_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        self.dummy_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        self.vxlan_l2_port.set_encap_vni(self.dummy_switch.hld_obj, 10001)
        # self.dummy_switch.hld_obj.set_decap_vni_profile(sdk.la_switch.vxlan_termination_mode_e_IGNORE_DMAC)

        self.dummy_switch.hld_obj.set_decap_vni(10001)

        self.vxlan_l3_encap_counter = self.device.create_counter(1)
        self.dummy_switch.hld_obj.set_vxlan_encap_counter(self.vxlan_l3_encap_counter)

        self.vxlan_l3_decap_counter = self.device.create_counter(1)
        self.dummy_switch.hld_obj.set_vxlan_decap_counter(self.vxlan_l3_decap_counter)

        self.dummy_switch.hld_obj.set_mac_entry(
            vxlan_l2_single_port.DUMMY_SVI_NH_MAC.hld_obj,
            self.vxlan_l2_port,
            sdk.LA_MAC_AGING_TIME_NEVER)

        # create nexthop on the SVI
        self.svi_nh = vxlan_next_hop(self.device, vxlan_l2_single_port.DUMMY_SVI_NH_MAC, self.dummy_svi, None)

        self.ovl_dip_prefix = self.underlay_ip_impl.build_prefix(self.OVL_DIP_ROUTE, length=24)
        self.underlay_ip_impl.add_route(self.topology.vrf, self.ovl_dip_prefix, self.svi_nh, self.PRIVATE_DATA)

        self.ovl_dip_prefix_1 = self.underlay_ip_impl.build_prefix(self.OVL_DIP_ROUTE_1, length=self.get_prefix_length())
        self.underlay_ip_impl.add_route(self.topology.vrf, self.ovl_dip_prefix_1, self.svi_nh, self.PRIVATE_DATA)

        self.ovl_sip_prefix = self.underlay_ip_impl.build_prefix(self.OVL_SIP_ROUTE, length=24)
        self.underlay_ip_impl.add_route(self.topology.vrf, self.ovl_sip_prefix, self.topology.nh_l3_ac_reg, self.PRIVATE_DATA)

        self.vxlan_sip_prefix = ip_test_base.ipv4_test_base.build_prefix(self.VXLAN_SIP, length=32)
        self.topology.global_vrf.hld_obj.add_ipv4_route(self.vxlan_sip_prefix, self.recycle_nh, self.PRIVATE_DATA, False)

    def l3vxlan_destroy(self):
        self.underlay_ip_impl.delete_route(self.topology.vrf, self.ovl_dip_prefix)
        self.underlay_ip_impl.delete_route(self.topology.vrf, self.ovl_dip_prefix_1)
        self.underlay_ip_impl.delete_route(self.topology.vrf, self.ovl_sip_prefix)
        self.topology.global_vrf.hld_obj.delete_ipv4_route(self.vxlan_sip_prefix)
        self.svi_nh.destroy()
        self.vxlan_l2_port.clear_encap_vni(self.dummy_switch.hld_obj)
        self.dummy_svi.destroy()
        self.dummy_switch.hld_obj.clear_decap_vni()
        self.dummy_switch.destroy()

    def sda_setup(self):
        # create ac profile for skipping da
        # create dummy switch
        self.dummy_switch = T.switch(self, self.device, T.RX_SWITCH_GID + 0x100)
        # create the SVI port for the dummy switch
        self.dummy_svi = T.svi_port(
            self,
            self.device,
            T.RX_SVI_GID + 0x200,
            self.dummy_switch,
            self.topology.vrf,
            vxlan_l2_single_port.DUMMY_SVI_MAC)

        self.dummy_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.dummy_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        self.dummy_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        self.dummy_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        self.vxlan_l2_port.set_encap_vni(self.dummy_switch.hld_obj, 10001)
        self.dummy_switch.hld_obj.set_decap_vni_profile(sdk.la_switch.vxlan_termination_mode_e_IGNORE_DMAC)
        self.dummy_switch.hld_obj.set_decap_vni(10001)

        # create nexthop on the SVI
        self.svi_nh = vxlan_next_hop(self.device, vxlan_l2_single_port.SDA_MAC, self.dummy_svi, self.vxlan_l2_port)

        # create ip route
        self.ovl_dip_prefix = self.underlay_ip_impl.build_prefix(self.OVL_DIP_ROUTE, length=24)
        self.underlay_ip_impl.add_route(self.topology.vrf, self.ovl_dip_prefix, self.svi_nh, self.PRIVATE_DATA)

        self.ovl_dip_prefix_1 = self.underlay_ip_impl.build_prefix(self.OVL_DIP_ROUTE_1, self.get_prefix_length())
        self.underlay_ip_impl.add_route(self.topology.vrf, self.ovl_dip_prefix_1, self.svi_nh, self.PRIVATE_DATA)

        self.ovl_sip_prefix = self.underlay_ip_impl.build_prefix(self.OVL_SIP_ROUTE, length=24)
        self.underlay_ip_impl.add_route(self.topology.vrf, self.ovl_sip_prefix, self.topology.nh_l3_ac_reg, self.PRIVATE_DATA)
        self.vxlan_sip_prefix = ip_test_base.ipv4_test_base.build_prefix(self.VXLAN_SIP, length=32)
        self.topology.global_vrf.hld_obj.add_ipv4_route(self.vxlan_sip_prefix, self.recycle_nh, self.PRIVATE_DATA, False)

    def sda_destroy(self):
        self.underlay_ip_impl.delete_route(self.topology.vrf, self.ovl_dip_prefix)
        self.underlay_ip_impl.delete_route(self.topology.vrf, self.ovl_dip_prefix_1)
        self.underlay_ip_impl.delete_route(self.topology.vrf, self.ovl_sip_prefix)
        self.topology.global_vrf.hld_obj.delete_ipv4_route(self.vxlan_sip_prefix)
        self.svi_nh.destroy()
        self.vxlan_l2_port.clear_encap_vni(self.dummy_switch.hld_obj)
        self.dummy_svi.destroy()
        self.dummy_switch.hld_obj.clear_decap_vni()
        self.dummy_switch.destroy()

    def setup_und_mcast_group(self):
        # underlay IP multicast
        self.und_mc_group = self.device.create_ip_multicast_group(self.UND_MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.und_mc_group.add(self.topology.tx_l3_ac_def.hld_obj, None, self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj)
        self.und_mc_group.add(self.recycle_l3_ac_port_decap, None, self.topology.recycle_ports[1].sys_port.hld_obj)
        if not vxlan_l2_single_port.IR:
            self.topology.vrf.hld_obj.add_ipv4_multicast_route(
                sdk.LA_IPV4_ANY_IP, self.UND_MC_GROUP_ADDR.hld_obj, self.und_mc_group, None, False, False, None)
        else:
            self.ingress_umc_group.add(self.und_mc_group)
            self.topology.vrf.hld_obj.add_ipv4_multicast_route(
                sdk.LA_IPV4_ANY_IP, self.UND_MC_GROUP_ADDR.hld_obj, self.ingress_umc_group, None, False, False, None)

    def destroy_und_mcast_group(self):
        self.und_mc_group.remove(self.topology.tx_l3_ac_def.hld_obj, None)
        self.und_mc_group.remove(self.recycle_l3_ac_port_decap, None)
        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.UND_MC_GROUP_ADDR.hld_obj)
        if vxlan_l2_single_port.IR:
            self.ingress_umc_group.remove(self.und_mc_group)
        self.device.destroy(self.und_mc_group)

    def l2_mcast_group_ovl(self, is_underlay = False):
        # create the overlay l2 mcast group
        self.l2mc_group = self.device.create_l2_multicast_group(self.L2MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.l2mrouter_group = self.device.create_l2_multicast_group(self.L2MC_GROUP_GID + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.l2snoop_group = self.device.create_l2_multicast_group(self.L2MC_GROUP_GID + 2, sdk.la_replication_paradigm_e_EGRESS)
        # add member
        self.l2mc_group.add(self.topology.tx_l2_ac_port_def.hld_obj, self.topology.tx_svi_eth_port_def.sys_port.hld_obj)
        self.l2mc_group.add(self.topology.tx_l2_ac_port_ext.hld_obj, self.topology.tx_svi_eth_port_ext.sys_port.hld_obj)

        self.l2snoop_group.add(self.topology.tx_l2_ac_port_def.hld_obj, self.topology.tx_svi_eth_port_def.sys_port.hld_obj)
        self.l2snoop_group.add(self.topology.tx_l2_ac_port_ext.hld_obj, self.topology.tx_svi_eth_port_ext.sys_port.hld_obj)
        if is_underlay:
            self.l2mc_group.add(self.vxlan_l2_port, self.recycle_nh, self.topology.recycle_ports[1].sys_port.hld_obj)
            self.l2mrouter_group.add(self.vxlan_l2_port, self.recycle_nh, self.topology.recycle_ports[1].sys_port.hld_obj)
            self.l2snoop_group.add(self.vxlan_l2_port, self.recycle_nh, self.topology.recycle_ports[1].sys_port.hld_obj)
        else:
            # For Decap, packet will be pruned on this.
            self.l2mc_group.add(self.vxlan_l2_port, self.l3_port_impl.def_nh.hld_obj,
                                self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj)
            self.l2mrouter_group.add(self.vxlan_l2_port, self.l3_port_impl.def_nh.hld_obj,
                                     self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj)
            self.l2snoop_group.add(self.vxlan_l2_port, self.l3_port_impl.def_nh.hld_obj,
                                   self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj)

        # set the flood destination
        self.topology.tx_switch.hld_obj.set_flood_destination(self.l2mc_group)

        self.topology.tx_switch.hld_obj.add_ipv4_multicast_route(self.L2_MC_GROUP_ADDR.hld_obj, self.l2snoop_group)
        if vxlan_l2_single_port.IR:
            self.topology.tx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
            self.ingress_omc_group.add(self.topology.tx_svi.hld_obj, self.l2snoop_group)
            self.topology.vrf.hld_obj.add_ipv4_multicast_route(
                sdk.LA_IPV4_ANY_IP,
                self.L2_MC_GROUP_ADDR.hld_obj,
                self.ingress_omc_group,
                None,
                False,
                False,
                None)

        if is_underlay:
            # create underlay ip mcast
            self.setup_und_mcast_group()

    def destroy_l2_mcast_group_ovl(self, is_underlay = False):

        self.l2mc_group.remove(self.topology.tx_l2_ac_port_def.hld_obj)
        self.l2mc_group.remove(self.topology.tx_l2_ac_port_ext.hld_obj)
        self.l2mc_group.remove(self.vxlan_l2_port)

        self.l2mrouter_group.remove(self.vxlan_l2_port)

        self.l2snoop_group.remove(self.topology.tx_l2_ac_port_def.hld_obj)
        self.l2snoop_group.remove(self.topology.tx_l2_ac_port_ext.hld_obj)
        self.l2snoop_group.remove(self.vxlan_l2_port)

        if vxlan_l2_single_port.IR:
            self.ingress_omc_group.remove(self.topology.tx_svi.hld_obj, self.l2snoop_group)
            self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.L2_MC_GROUP_ADDR.hld_obj)

        self.topology.tx_switch.hld_obj.set_flood_destination(None)

        self.device.destroy(self.l2mc_group)
        self.device.destroy(self.l2mrouter_group)
        self.topology.tx_switch.hld_obj.delete_ipv4_multicast_route(self.L2_MC_GROUP_ADDR.hld_obj)
        self.device.destroy(self.l2snoop_group)

        if is_underlay:
            self.destroy_und_mcast_group()

    def l3_mcast_group_ovl(self, is_underlay = False):
        # create the overlay IP mcast group
        self.l3mc_group = self.device.create_ip_multicast_group(self.L3MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        # add member
        self.l3mc_group.add(self.topology.tx_l3_ac_ext.hld_obj, None, self.topology.tx_l3_ac_eth_port_ext.sys_port.hld_obj)

        mc_group = self.l3mc_group
        if is_underlay:
            self.l3mc_group.add(None, self.vxlan_l2_port, self.recycle_nh, self.topology.recycle_ports[1].sys_port.hld_obj)
        else:
            # Needed for encap. For Decap, it should prune the pkt.
            self.l3mc_group.add(None, self.vxlan_l2_port, self.l3_port_impl.def_nh.hld_obj,
                                self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj)

        if vxlan_l2_single_port.IR:
            self.ingress_omc_group.add(self.l3mc_group)
            mc_group = self.ingress_omc_group

        # add mcast route
        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.L3MC_GROUP_ADDR.hld_obj, mc_group, None, False, False, None)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.L3MC_GROUP_ADDR_V6.hld_obj, mc_group, None, False, False, None)

        if is_underlay:
            # create underlay ip mcast
            self.setup_und_mcast_group()

    def destroy_l3_mcast_group_ovl(self, is_underlay = False):
        # Remove member
        self.l3mc_group.remove(self.topology.tx_l3_ac_ext.hld_obj, None)
        self.l3mc_group.remove(None, self.vxlan_l2_port)

        # Remove mcast route
        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.L3MC_GROUP_ADDR.hld_obj)
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(sdk.LA_IPV6_ANY_IP, self.L3MC_GROUP_ADDR_V6.hld_obj)

        # Remove the L2 mcast group
        if vxlan_l2_single_port.IR:
            self.ingress_omc_group.remove(self.l3mc_group)

        # Remove the IP mcast group
        self.device.destroy(self.l3mc_group)

        if is_underlay:
            self.destroy_und_mcast_group()

    def _test_vxlan_2_pass(self):
        # packet comes in at rx_l2_ac_port and goes out at rx_l2_ac_port1
        L2_RCY_INPUT_PACKET = \
            S.Ether(dst=vxlan_l2_single_port.RCY_DST_MAC.addr_str,
                    src=vxlan_l2_single_port.VXLAN_SRC_MAC.addr_str,
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP() / \
            S.TCP()

        L2_RCY_INPUT_PACKET, __ = U.enlarge_packet_to_min_length(L2_RCY_INPUT_PACKET)

        U.run_and_compare(self, self.device,
                          L2_RCY_INPUT_PACKET, T.RX_SLICE,
                          T.RX_IFG, T.FIRST_SERDES,
                          L2_RCY_INPUT_PACKET, T.RX_SLICE,
                          T.RX_IFG1, T.FIRST_SERDES1)

        # packet comes in at tx_l2_ac_port_reg

        VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(dst=vxlan_l2_single_port.VXLAN_DST_MAC.addr_str,
                    src=vxlan_l2_single_port.VXLAN_SRC_MAC.addr_str) / \
            S.IP() / \
            S.TCP()

        VXLAN_ENCAP_INPUT_PACKET, __ = U.enlarge_packet_to_min_length(VXLAN_ENCAP_INPUT_PACKET)
        VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL - 1) / \
            S.UDP(sport=18805,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10000) / \
            VXLAN_ENCAP_INPUT_PACKET

        U.run_and_compare(self, self.device,
                          VXLAN_ENCAP_INPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_SVI_REG,
                          VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, self.l3_port_impl.serdes_def)

    def _test_vxlan_l2_encap(self, proto=sdk.la_l3_protocol_e_IPV4_UC):
        # packet comes in at tx_l2_ac_port_reg
        if decor.is_pacific():
            if proto == sdk.la_l3_protocol_e_IPV4_UC:
                vxlan_sport = 25668
            else:
                vxlan_sport = 17413
        elif decor.is_gibraltar():
            if proto == sdk.la_l3_protocol_e_IPV4_UC:
                vxlan_sport = 31294
            else:
                vxlan_sport = 9560
        elif decor.is_asic4():
            load_bal_vector = sdk.la_lb_vector_t()
            if proto == sdk.la_l3_protocol_e_IPV4_UC:
                load_bal_vector.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV4_L4
                load_bal_vector.ipv4.src_port = self.VXLAN_L2_ENCAP_INPUT_PACKET_1[S.TCP].sport
                load_bal_vector.ipv4.dest_port = self.VXLAN_L2_ENCAP_INPUT_PACKET_1[S.TCP].dport
                load_bal_vector.ipv4.sip = T.ipv4_addr(self.VXLAN_L2_ENCAP_INPUT_PACKET_1[S.IP].src).to_num()
                load_bal_vector.ipv4.dip = T.ipv4_addr(self.VXLAN_L2_ENCAP_INPUT_PACKET_1[S.IP].dst).to_num()
                load_bal_vector.ipv4.protocol = self.VXLAN_L2_ENCAP_INPUT_PACKET_1[S.IP].proto
            else:
                load_bal_vector.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV6_L4
                load_bal_vector.ipv6.src_port = 20
                load_bal_vector.ipv6.dest_port = 80
                load_bal_vector.ipv6.sip = [1, 0, 0, 0]
                load_bal_vector.ipv6.dip = [1, 0, 0, 0]
                load_bal_vector.ipv6.next_header = 6  # TCP

            lb_vec_entry_list = []
            lb_vec_entry_list.append(load_bal_vector)

            vxlan_sport = get_vxlan_lb_hash(self.device, lb_vec_entry_list, stage=hldcli.RESOLUTION_STEP_STAGE2_ECMP)
        else:
            vxlan_sport = 0

        self.VXLAN_L2_ENCAP_INPUT_PACKET_1, __ = U.enlarge_packet_to_min_length(self.VXLAN_L2_ENCAP_INPUT_PACKET_1)
        VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10000) / \
            self.VXLAN_L2_ENCAP_INPUT_PACKET_1

        U.run_and_compare(self, self.device,
                          self.VXLAN_L2_ENCAP_INPUT_PACKET_1, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_SVI_REG,
                          VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, self.l3_port_impl.serdes_def)

        # packet comes in at rx_l2_ac_port

        self.VXLAN_L2_ENCAP_INPUT_PACKET_2, __ = U.enlarge_packet_to_min_length(self.VXLAN_L2_ENCAP_INPUT_PACKET_2)

        if decor.is_pacific():
            if proto == sdk.la_l3_protocol_e_IPV4_UC:
                vxlan_sport = 19175
            else:
                vxlan_sport = 27302
        elif decor.is_gibraltar():
            if proto == sdk.la_l3_protocol_e_IPV4_UC:
                vxlan_sport = 49665
            else:
                vxlan_sport = 40295
        elif decor.is_asic4():
            load_bal_vector = sdk.la_lb_vector_t()
            if proto == sdk.la_l3_protocol_e_IPV4_UC:
                load_bal_vector.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV4_L4
                load_bal_vector.ipv4.src_port = self.VXLAN_L2_ENCAP_INPUT_PACKET_2[S.TCP].sport
                load_bal_vector.ipv4.dest_port = self.VXLAN_L2_ENCAP_INPUT_PACKET_2[S.TCP].dport
                load_bal_vector.ipv4.sip = T.ipv4_addr(self.VXLAN_L2_ENCAP_INPUT_PACKET_2[S.IP].src).to_num()
                load_bal_vector.ipv4.dip = T.ipv4_addr(self.VXLAN_L2_ENCAP_INPUT_PACKET_2[S.IP].dst).to_num()
                load_bal_vector.ipv4.protocol = self.VXLAN_L2_ENCAP_INPUT_PACKET_2[S.IP].proto
            else:
                load_bal_vector.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV6_L4
                load_bal_vector.ipv6.src_port = 20
                load_bal_vector.ipv6.dest_port = 80
                load_bal_vector.ipv6.sip = [1, 0, 0, 0]
                load_bal_vector.ipv6.dip = [1, 0, 0, 0]
                load_bal_vector.ipv6.next_header = 6  # TCP

            lb_vec_entry_list = []
            lb_vec_entry_list.append(load_bal_vector)

            vxlan_sport = get_vxlan_lb_hash(self.device, lb_vec_entry_list, stage=hldcli.RESOLUTION_STEP_STAGE2_ECMP)
        else:
            vxlan_sport = 0

        VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=9999) / \
            self.VXLAN_L2_ENCAP_INPUT_PACKET_2

        self.output_p_counter = self.device.create_counter(1)
        self.topology.tx_l3_ac_def.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.output_p_counter)

        U.run_and_compare(self, self.device,
                          self.VXLAN_L2_ENCAP_INPUT_PACKET_2, T.RX_SLICE,
                          T.RX_IFG, T.FIRST_SERDES,
                          VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, self.l3_port_impl.serdes_def)
        packets, byte_count = self.vxlan_encap_counter.read(0, True, True)
        self.assertEqual(packets, 1)

        packets, byte_count = self.tunnel_encap_counter.read(0, True, True)
        self.assertEqual(packets, 2)

        packets, byte_count = self.output_p_counter.read(0, True, True)
        self.assertEqual(packets, 1)

        self.topology.tx_l3_ac_def.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, None)
        self.device.destroy(self.output_p_counter)

    def _test_vxlan_l2_mcast_encap_her(self):
        # packet comes in at tx_l2_ac_port_reg

        VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(dst=self.get_mc_sa_addr_str(self.L2_MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.VXLAN_SRC_MAC.addr_str) / \
            S.IP(dst=self.L2_MC_GROUP_ADDR.addr_str,
                 src='1.1.1.1',
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.TCP()

        if decor.is_gibraltar():
            vxlan_sport = 46302
        elif decor.is_asic4():
            load_bal_vector = sdk.la_lb_vector_t()
            load_bal_vector.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV4_L4
            load_bal_vector.ipv4.src_port = VXLAN_ENCAP_INPUT_PACKET[S.TCP].sport
            load_bal_vector.ipv4.dest_port = VXLAN_ENCAP_INPUT_PACKET[S.TCP].dport
            load_bal_vector.ipv4.sip = T.ipv4_addr(VXLAN_ENCAP_INPUT_PACKET[S.IP].src).to_num()
            load_bal_vector.ipv4.dip = T.ipv4_addr(VXLAN_ENCAP_INPUT_PACKET[S.IP].dst).to_num()
            load_bal_vector.ipv4.protocol = VXLAN_ENCAP_INPUT_PACKET[S.IP].proto

            lb_vec_entry_list = []
            lb_vec_entry_list.append(load_bal_vector)

            vxlan_sport = get_vxlan_lb_hash(self.device, lb_vec_entry_list, stage=hldcli.RESOLUTION_STEP_STAGE3_DSPA)
        else:
            vxlan_sport = 0

        VXLAN_ENCAP_INPUT_PACKET, __ = U.enlarge_packet_to_min_length(VXLAN_ENCAP_INPUT_PACKET)
        VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10000) / \
            VXLAN_ENCAP_INPUT_PACKET

        ingress_packet = {'data': VXLAN_ENCAP_INPUT_PACKET, 'slice': T.TX_SLICE_REG, 'ifg': T.TX_IFG_REG, 'pif': T.FIRST_SERDES_SVI}
        expected_packets = []
        expected_packets.append({'data': VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.l3_port_impl.serdes_def})
        expected_packets.append({'data': VXLAN_ENCAP_INPUT_PACKET, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_SVI})
        expected_packets.append({'data': VXLAN_ENCAP_INPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_SVI})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_vxlan_l2_mcast_encap_arp_her(self):
        # packet comes in at tx_l2_ac_port_reg
        VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(dst='ff:ff:ff:ff:ff:ff',
                    src=vxlan_l2_single_port.VXLAN_SRC_MAC.addr_str) / \
            S.ARP(op='who-has')

        if decor.is_gibraltar():
            vxlan_sport = 49086
        elif decor.is_asic4():
            load_bal_vector = sdk.la_lb_vector_t()
            load_bal_vector.type = sdk.LA_LB_VECTOR_ETHERNET_VLAN_TAG
            load_bal_vector.ethernet.da.flat = T.mac_addr(VXLAN_ENCAP_INPUT_PACKET[S.Ether].dst).to_num()
            load_bal_vector.ethernet.sa.flat = T.mac_addr(VXLAN_ENCAP_INPUT_PACKET[S.Ether].src).to_num()
            load_bal_vector.ethernet.vlan_id = T.RX_L3_AC_PORT_VID1

            lb_vec_entry_list = []
            lb_vec_entry_list.append(load_bal_vector)

            vxlan_sport = get_vxlan_lb_hash(self.device, lb_vec_entry_list, stage=hldcli.RESOLUTION_STEP_STAGE3_DSPA)
        else:
            vxlan_sport = 0

        VXLAN_ENCAP_INPUT_PACKET, __ = U.enlarge_packet_to_min_length(VXLAN_ENCAP_INPUT_PACKET)
        VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10000) / \
            VXLAN_ENCAP_INPUT_PACKET

        PUNT_PACKET = \
            S.Ether(dst=vxlan_l2_single_port.HOST_MAC_ADDR,
                    src=vxlan_l2_single_port.PUNT_INJECT_PORT_MAC_ADDR,
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0,
                    id=0,
                    vlan=vxlan_l2_single_port.MIRROR_VLAN,
                    type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                   code=vxlan_l2_single_port.MIRROR_CMD_INGRESS_GID,
                   source_sp=T.TX_SVI_SYS_PORT_REG_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.TX_L2_AC_PORT_REG_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                   destination_lp=sdk.LA_EVENT_ETHERNET_FIRST,
                   relay_id=T.TX_SWITCH_GID,
                   lpts_flow_type=0) / \
            VXLAN_ENCAP_INPUT_PACKET
        ingress_packet = {'data': VXLAN_ENCAP_INPUT_PACKET, 'slice': T.TX_SLICE_REG, 'ifg': T.TX_IFG_REG, 'pif': T.FIRST_SERDES_SVI}
        expected_packets = []
        expected_packets.append({'data': VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.l3_port_impl.serdes_def})
        expected_packets.append({'data': VXLAN_ENCAP_INPUT_PACKET, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_SVI})
        expected_packets.append({'data': VXLAN_ENCAP_INPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_SVI})
        expected_packets.append({'data': PUNT_PACKET,
                                 'slice': vxlan_l2_single_port.PI_SLICE,
                                 'ifg': vxlan_l2_single_port.PI_IFG,
                                 'pif': vxlan_l2_single_port.PI_PIF_FIRST})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_vxlan_l2_mcast_encap_ucast_her(self):
        # packet comes in at tx_l2_ac_port_reg

        if decor.is_gibraltar():
            IP_DST = '127.0.0.1'
            IP_SRC = IP_DST
        elif decor.is_asic4():
            IP_DST = '192.168.1.2'
            IP_SRC = '192.168.1.1'

        VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(dst='22:aa:34:bb:45:cc',
                    src=vxlan_l2_single_port.VXLAN_SRC_MAC.addr_str) / \
            S.IP(dst=IP_DST,
                 src=IP_SRC) / \
            S.TCP()

        if decor.is_gibraltar():
            vxlan_sport = 15761
        elif decor.is_asic4():
            load_bal_vector = sdk.la_lb_vector_t()
            load_bal_vector.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV4_L4
            load_bal_vector.ipv4.src_port = VXLAN_ENCAP_INPUT_PACKET[S.TCP].sport
            load_bal_vector.ipv4.dest_port = VXLAN_ENCAP_INPUT_PACKET[S.TCP].dport
            load_bal_vector.ipv4.sip = T.ipv4_addr(VXLAN_ENCAP_INPUT_PACKET[S.IP].src).to_num()
            load_bal_vector.ipv4.dip = T.ipv4_addr(VXLAN_ENCAP_INPUT_PACKET[S.IP].dst).to_num()
            load_bal_vector.ipv4.protocol = VXLAN_ENCAP_INPUT_PACKET[S.IP].proto

            lb_vec_entry_list = []
            lb_vec_entry_list.append(load_bal_vector)

            vxlan_sport = get_vxlan_lb_hash(self.device, lb_vec_entry_list, stage=hldcli.RESOLUTION_STEP_STAGE3_DSPA)
        else:
            vxlan_sport = 0

        VXLAN_ENCAP_INPUT_PACKET, __ = U.enlarge_packet_to_min_length(VXLAN_ENCAP_INPUT_PACKET)
        VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10000) / \
            VXLAN_ENCAP_INPUT_PACKET

        ingress_packet = {'data': VXLAN_ENCAP_INPUT_PACKET, 'slice': T.TX_SLICE_REG, 'ifg': T.TX_IFG_REG, 'pif': T.FIRST_SERDES_SVI}
        expected_packets = []
        expected_packets.append({'data': VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.l3_port_impl.serdes_def})
        expected_packets.append({'data': VXLAN_ENCAP_INPUT_PACKET, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_SVI})
        expected_packets.append({'data': VXLAN_ENCAP_INPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_SVI})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_vxlan_l2_mcast_encap_und(self):
        # packet comes in at tx_l2_ac_port_reg

        VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(dst=self.get_mc_sa_addr_str(self.L2_MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.VXLAN_SRC_MAC.addr_str) / \
            S.IP(dst=self.L2_MC_GROUP_ADDR.addr_str,
                 src='1.1.1.1',
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.TCP()

        if decor.is_gibraltar():
            vxlan_sport = 46302
        elif decor.is_asic4():
            load_bal_vector = sdk.la_lb_vector_t()
            load_bal_vector.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV4_L4
            load_bal_vector.ipv4.src_port = VXLAN_ENCAP_INPUT_PACKET[S.TCP].sport
            load_bal_vector.ipv4.dest_port = VXLAN_ENCAP_INPUT_PACKET[S.TCP].dport
            load_bal_vector.ipv4.sip = T.ipv4_addr(VXLAN_ENCAP_INPUT_PACKET[S.IP].src).to_num()
            load_bal_vector.ipv4.dip = T.ipv4_addr(VXLAN_ENCAP_INPUT_PACKET[S.IP].dst).to_num()
            load_bal_vector.ipv4.protocol = VXLAN_ENCAP_INPUT_PACKET[S.IP].proto

            lb_vec_entry_list = []
            lb_vec_entry_list.append(load_bal_vector)

            vxlan_sport = get_vxlan_lb_hash(self.device, lb_vec_entry_list, stage=hldcli.RESOLUTION_STEP_STAGE3_DSPA)
        else:
            vxlan_sport = 0

        VXLAN_ENCAP_INPUT_PACKET, __ = U.enlarge_packet_to_min_length(VXLAN_ENCAP_INPUT_PACKET)
        VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=self.get_mc_sa_addr_str(self.UND_MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL - 1) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10000) / \
            VXLAN_ENCAP_INPUT_PACKET

        ingress_packet = {'data': VXLAN_ENCAP_INPUT_PACKET, 'slice': T.TX_SLICE_REG, 'ifg': T.TX_IFG_REG, 'pif': T.FIRST_SERDES_SVI}
        expected_packets = []
        expected_packets.append({'data': VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3})
        expected_packets.append({'data': VXLAN_ENCAP_INPUT_PACKET, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_SVI})
        expected_packets.append({'data': VXLAN_ENCAP_INPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_SVI})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def get_mc_sa_addr_str(self, ip_addr):
        octets = ip_addr.addr_str.split('.')
        assert(len(octets) == 4)
        sa_addr_str = '01:00:5e'
        sa_addr_str += ':%02x' % (0x7f & int(octets[1]))
        for o in octets[2:]:
            sa_addr_str += ':%02x' % (int(o))
        return sa_addr_str

    def v6_get_mc_sa_addr_str(self, ip_addr):
        # https://tools.ietf.org/html/rfc2464#section-7
        shorts = ip_addr.addr_str.split(':')
        assert(len(shorts) == T.ipv6_addr.NUM_OF_SHORTS)
        sa_addr_str = '33:33'
        for s in shorts[-2:]:
            sl = int(s, 16) & 0xff
            sh = (int(s, 16) >> 8) & 0xff
            sa_addr_str += ':%02x:%02x' % (sh, sl)
        return sa_addr_str

    def _test_vxlan_l3_mcast_encap_her(self):
        # packet comes in at tx_l3_ac_reg and goes out at tx_l3_ac_def

        L3VXLAN_IPV4_PACKET = \
            S.IP(dst=self.L3MC_GROUP_ADDR.addr_str,
                 src='1.1.1.1',
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.TCP()
        L3VXLAN_IPV4_PACKET, __ = U.enlarge_packet_to_min_length(L3VXLAN_IPV4_PACKET, 68)

        L3VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=self.get_mc_sa_addr_str(self.L3MC_GROUP_ADDR)) / \
            L3VXLAN_IPV4_PACKET

        L3VXLAN_IPV4_PACKET.getlayer(0).ttl = 254
        L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1 = \
            S.Ether(src=vxlan_l2_single_port.NEW_TX_L3_AC_EXT_MAC.addr_str,
                    dst=self.get_mc_sa_addr_str(self.L3MC_GROUP_ADDR)) / \
            L3VXLAN_IPV4_PACKET

        if decor.is_gibraltar():
            vxlan_sport = 60119
        elif decor.is_asic4():
            load_bal_vector = sdk.la_lb_vector_t()

            load_bal_vector.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
            load_bal_vector.ipv4.src_port = L3VXLAN_IPV4_PACKET[S.TCP].sport
            load_bal_vector.ipv4.dest_port = L3VXLAN_IPV4_PACKET[S.TCP].dport
            load_bal_vector.ipv4.sip = T.ipv4_addr(L3VXLAN_IPV4_PACKET[S.IP].src).to_num()
            load_bal_vector.ipv4.dip = T.ipv4_addr(L3VXLAN_IPV4_PACKET[S.IP].dst).to_num()
            load_bal_vector.ipv4.protocol = L3VXLAN_IPV4_PACKET[S.IP].proto

            lb_vec_entry_list = []
            lb_vec_entry_list.append(load_bal_vector)

            vxlan_sport = get_vxlan_lb_hash(self.device, lb_vec_entry_list, stage=hldcli.RESOLUTION_STEP_STAGE3_DSPA)
        else:
            vxlan_sport = 0

        L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=self.get_mc_sa_addr_str(self.L3MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.DUMMY_SVI_MAC.addr_str) / \
            L3VXLAN_IPV4_PACKET

        ingress_packet = {
            'data': L3VXLAN_ENCAP_INPUT_PACKET,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': T.FIRST_SERDES_L3}

        expected_packets = []
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_L3})
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # IPv6 overlay mcast

        L3VXLAN_IPV6_PACKET = \
            S.IPv6(dst=self.L3MC_GROUP_ADDR_V6.addr_str,
                   src='2222:0db8:0a0b:12f0:0000:0000:0000:2222',
                   hlim=vxlan_base.OUTER_TTL) / \
            S.TCP()
        L3VXLAN_IPV6_PACKET, __ = U.enlarge_packet_to_min_length(L3VXLAN_IPV6_PACKET, 68)

        L3VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=self.v6_get_mc_sa_addr_str(self.L3MC_GROUP_ADDR_V6)) / \
            L3VXLAN_IPV6_PACKET

        L3VXLAN_IPV6_PACKET.getlayer(0).hlim = 254
        L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1 = \
            S.Ether(src=vxlan_l2_single_port.NEW_TX_L3_AC_EXT_MAC.addr_str,
                    dst=self.v6_get_mc_sa_addr_str(self.L3MC_GROUP_ADDR_V6)) / \
            L3VXLAN_IPV6_PACKET

        if decor.is_gibraltar():
            vxlan_sport = 16034
        elif decor.is_asic4():
            load_bal_vector = sdk.la_lb_vector_t()

            load_bal_vector.type = sdk.LA_LB_VECTOR_IPV6_TCP_UDP
            load_bal_vector.ipv4.src_port = 20
            load_bal_vector.ipv4.dest_port = 80
            load_bal_vector.ipv6.sip = [0x00002222, 0x00000000, 0x0a0b12f0, 0x22220db8]
            load_bal_vector.ipv6.dip = [0xffe8658f, 0x00000001, 0x00000000, 0xff010000]
            load_bal_vector.ipv6.next_header = 6  # TCP

            lb_vec_entry_list = []
            lb_vec_entry_list.append(load_bal_vector)

            vxlan_sport = get_vxlan_lb_hash(self.device, lb_vec_entry_list, stage=hldcli.RESOLUTION_STEP_STAGE3_DSPA)
        else:
            vxlan_sport = 0

        L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=self.v6_get_mc_sa_addr_str(self.L3MC_GROUP_ADDR_V6),
                    src=vxlan_l2_single_port.DUMMY_SVI_MAC.addr_str) / \
            L3VXLAN_IPV6_PACKET

        ingress_packet = {
            'data': L3VXLAN_ENCAP_INPUT_PACKET,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': T.FIRST_SERDES_L3}
        expected_packets = []
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_L3})
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_vxlan_l3_mcast_encap_und(self):
        # packet comes in at tx_l3_ac_reg and goes out at tx_l3_ac_def

        L3VXLAN_IPV4_PACKET = \
            S.IP(dst=self.L3MC_GROUP_ADDR.addr_str,
                 src='1.1.1.1',
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.TCP()
        L3VXLAN_IPV4_PACKET, __ = U.enlarge_packet_to_min_length(L3VXLAN_IPV4_PACKET, 68)

        L3VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=self.get_mc_sa_addr_str(self.L3MC_GROUP_ADDR)) / \
            L3VXLAN_IPV4_PACKET

        L3VXLAN_IPV4_PACKET.getlayer(0).ttl = 254
        L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1 = \
            S.Ether(src=vxlan_l2_single_port.NEW_TX_L3_AC_EXT_MAC.addr_str,
                    dst=self.get_mc_sa_addr_str(self.L3MC_GROUP_ADDR)) / \
            L3VXLAN_IPV4_PACKET

        L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=self.get_mc_sa_addr_str(self.UND_MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL - 1) / \
            S.UDP(sport=60119,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=self.get_mc_sa_addr_str(self.L3MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.DUMMY_SVI_MAC.addr_str) / \
            L3VXLAN_IPV4_PACKET

        ingress_packet = {
            'data': L3VXLAN_ENCAP_INPUT_PACKET,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': T.FIRST_SERDES_L3}
        expected_packets = []
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3})
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_L3})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # IPv6 overlay mcast

        L3VXLAN_IPV6_PACKET = \
            S.IPv6(dst=self.L3MC_GROUP_ADDR_V6.addr_str,
                   src='2222:0db8:0a0b:12f0:0000:0000:0000:2222',
                   hlim=vxlan_base.OUTER_TTL) / \
            S.TCP()
        L3VXLAN_IPV6_PACKET, __ = U.enlarge_packet_to_min_length(L3VXLAN_IPV6_PACKET, 68)

        L3VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=self.v6_get_mc_sa_addr_str(self.L3MC_GROUP_ADDR_V6)) / \
            L3VXLAN_IPV6_PACKET

        L3VXLAN_IPV6_PACKET.getlayer(0).hlim = 254
        L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1 = \
            S.Ether(src=vxlan_l2_single_port.NEW_TX_L3_AC_EXT_MAC.addr_str,
                    dst=self.v6_get_mc_sa_addr_str(self.L3MC_GROUP_ADDR_V6)) / \
            L3VXLAN_IPV6_PACKET

        L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=self.get_mc_sa_addr_str(self.UND_MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL - 1) / \
            S.UDP(sport=16034,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=self.v6_get_mc_sa_addr_str(self.L3MC_GROUP_ADDR_V6),
                    src=vxlan_l2_single_port.DUMMY_SVI_MAC.addr_str) / \
            L3VXLAN_IPV6_PACKET
        ingress_packet = {
            'data': L3VXLAN_ENCAP_INPUT_PACKET,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': T.FIRST_SERDES_L3}
        expected_packets = []
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3})
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_L3})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_vxlan_l3_mcast_encap_her_collapsed_mc(self):
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        # packet comes in at l2_ac_port and goes out at tx_l3_ac_def

        L3VXLAN_IPV4_PACKET = \
            S.IP(dst=self.L3MC_GROUP_ADDR.addr_str,
                 src='1.1.1.1',
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.TCP()
        L3VXLAN_IPV4_PACKET, __ = U.enlarge_packet_to_min_length(L3VXLAN_IPV4_PACKET, 68)

        L3VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=self.get_mc_sa_addr_str(self.L3MC_GROUP_ADDR),
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            L3VXLAN_IPV4_PACKET

        L3VXLAN_IPV4_PACKET.getlayer(0).ttl = 254
        L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1 = \
            S.Ether(src=vxlan_l2_single_port.NEW_TX_L3_AC_EXT_MAC.addr_str,
                    dst=self.get_mc_sa_addr_str(self.L3MC_GROUP_ADDR)) / \
            L3VXLAN_IPV4_PACKET

        if decor.is_gibraltar():
            vxlan_sport = 60119
        elif decor.is_asic4():
            load_bal_vector = sdk.la_lb_vector_t()

            load_bal_vector.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
            load_bal_vector.ipv4.src_port = L3VXLAN_IPV4_PACKET[S.TCP].sport
            load_bal_vector.ipv4.dest_port = L3VXLAN_IPV4_PACKET[S.TCP].dport
            load_bal_vector.ipv4.sip = T.ipv4_addr(L3VXLAN_IPV4_PACKET[S.IP].src).to_num()
            load_bal_vector.ipv4.dip = T.ipv4_addr(L3VXLAN_IPV4_PACKET[S.IP].dst).to_num()
            load_bal_vector.ipv4.protocol = L3VXLAN_IPV4_PACKET[S.IP].proto

            lb_vec_entry_list = []
            lb_vec_entry_list.append(load_bal_vector)

            vxlan_sport = get_vxlan_lb_hash(self.device, lb_vec_entry_list, stage=hldcli.RESOLUTION_STEP_STAGE3_DSPA)
        else:
            vxlan_sport = 0

        L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=self.get_mc_sa_addr_str(self.L3MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.DUMMY_SVI_MAC.addr_str) / \
            L3VXLAN_IPV4_PACKET

        ingress_packet = {'data': L3VXLAN_ENCAP_INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_L3})
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # IPv6 overlay mcast

        L3VXLAN_IPV6_PACKET = \
            S.IPv6(dst=self.L3MC_GROUP_ADDR_V6.addr_str,
                   src='2222:0db8:0a0b:12f0:0000:0000:0000:2222',
                   hlim=vxlan_base.OUTER_TTL) / \
            S.TCP()
        L3VXLAN_IPV6_PACKET, __ = U.enlarge_packet_to_min_length(L3VXLAN_IPV6_PACKET, 68)

        L3VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=self.v6_get_mc_sa_addr_str(self.L3MC_GROUP_ADDR_V6),
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            L3VXLAN_IPV6_PACKET

        L3VXLAN_IPV6_PACKET.getlayer(0).hlim = 254
        L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1 = \
            S.Ether(src=vxlan_l2_single_port.NEW_TX_L3_AC_EXT_MAC.addr_str,
                    dst=self.v6_get_mc_sa_addr_str(self.L3MC_GROUP_ADDR_V6)) / \
            L3VXLAN_IPV6_PACKET

        if decor.is_gibraltar():
            vxlan_sport = 16034
        elif decor.is_asic4():
            load_bal_vector = sdk.la_lb_vector_t()

            load_bal_vector.type = sdk.LA_LB_VECTOR_IPV6_TCP_UDP
            load_bal_vector.ipv6.src_port = 20
            load_bal_vector.ipv6.dest_port = 80
            load_bal_vector.ipv6.sip = [0x00002222, 0x00000000, 0x0a0b12f0, 0x22220db8]
            load_bal_vector.ipv6.dip = [0xffe8658f, 0x00000001, 0x00000000, 0xff010000]
            load_bal_vector.ipv6.next_header = 6  # TCP

            lb_vec_entry_list = []
            lb_vec_entry_list.append(load_bal_vector)

            vxlan_sport = get_vxlan_lb_hash(self.device, lb_vec_entry_list, stage=hldcli.RESOLUTION_STEP_STAGE3_DSPA)
        else:
            vxlan_sport = 0

        L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=self.v6_get_mc_sa_addr_str(self.L3MC_GROUP_ADDR_V6),
                    src=vxlan_l2_single_port.DUMMY_SVI_MAC.addr_str) / \
            L3VXLAN_IPV6_PACKET

        ingress_packet = {'data': L3VXLAN_ENCAP_INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_L3})
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_vxlan_l3_mcast_encap_und_collapsed_mc(self):
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        # packet comes in at l2_ac_port and goes out at tx_l3_ac_def

        L3VXLAN_IPV4_PACKET = \
            S.IP(dst=self.L3MC_GROUP_ADDR.addr_str,
                 src='1.1.1.1',
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.TCP()
        L3VXLAN_IPV4_PACKET, __ = U.enlarge_packet_to_min_length(L3VXLAN_IPV4_PACKET, 68)

        L3VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=self.get_mc_sa_addr_str(self.L3MC_GROUP_ADDR),
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            L3VXLAN_IPV4_PACKET

        L3VXLAN_IPV4_PACKET.getlayer(0).ttl = 254
        L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1 = \
            S.Ether(src=vxlan_l2_single_port.NEW_TX_L3_AC_EXT_MAC.addr_str,
                    dst=self.get_mc_sa_addr_str(self.L3MC_GROUP_ADDR)) / \
            L3VXLAN_IPV4_PACKET

        if decor.is_gibraltar():
            vxlan_sport = 60119
        elif decor.is_asic4():
            load_bal_vector = sdk.la_lb_vector_t()
            load_bal_vector.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
            load_bal_vector.ipv4.src_port = L3VXLAN_IPV4_PACKET[S.TCP].sport
            load_bal_vector.ipv4.dest_port = L3VXLAN_IPV4_PACKET[S.TCP].dport
            load_bal_vector.ipv4.sip = T.ipv4_addr(L3VXLAN_IPV4_PACKET[S.IP].src).to_num()
            load_bal_vector.ipv4.dip = T.ipv4_addr(L3VXLAN_IPV4_PACKET[S.IP].dst).to_num()
            load_bal_vector.ipv4.protocol = L3VXLAN_IPV4_PACKET[S.IP].proto

            lb_vec_entry_list = []
            lb_vec_entry_list.append(load_bal_vector)

            vxlan_sport = get_vxlan_lb_hash(self.device, lb_vec_entry_list, stage=hldcli.RESOLUTION_STEP_STAGE3_DSPA)
        else:
            vxlan_sport = 0

        L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=self.get_mc_sa_addr_str(self.UND_MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL - 1) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=self.get_mc_sa_addr_str(self.L3MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.DUMMY_SVI_MAC.addr_str) / \
            L3VXLAN_IPV4_PACKET

        ingress_packet = {'data': L3VXLAN_ENCAP_INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3})
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_L3})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # IPv6 overlay mcast

        L3VXLAN_IPV6_PACKET = \
            S.IPv6(dst=self.L3MC_GROUP_ADDR_V6.addr_str,
                   src='2222:0db8:0a0b:12f0:0000:0000:0000:2222',
                   hlim=vxlan_base.OUTER_TTL) / \
            S.TCP()
        L3VXLAN_IPV6_PACKET, __ = U.enlarge_packet_to_min_length(L3VXLAN_IPV6_PACKET, 68)

        L3VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=self.v6_get_mc_sa_addr_str(self.L3MC_GROUP_ADDR_V6),
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            L3VXLAN_IPV6_PACKET

        L3VXLAN_IPV6_PACKET.getlayer(0).hlim = 254
        L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1 = \
            S.Ether(src=vxlan_l2_single_port.NEW_TX_L3_AC_EXT_MAC.addr_str,
                    dst=self.v6_get_mc_sa_addr_str(self.L3MC_GROUP_ADDR_V6)) / \
            L3VXLAN_IPV6_PACKET

        if decor.is_gibraltar():
            vxlan_sport = 16034
        elif decor.is_asic4():
            load_bal_vector = sdk.la_lb_vector_t()
            load_bal_vector.type = sdk.LA_LB_VECTOR_IPV6_TCP_UDP
            load_bal_vector.ipv6.src_port = 20
            load_bal_vector.ipv6.dest_port = 80
            load_bal_vector.ipv6.sip = [0x00002222, 0x00000000, 0x0a0b12f0, 0x22220db8]
            load_bal_vector.ipv6.dip = [0xffe8658f, 0x00000001, 0x00000000, 0xff010000]
            load_bal_vector.ipv6.next_header = 6  # TCP

            lb_vec_entry_list = []
            lb_vec_entry_list.append(load_bal_vector)

            vxlan_sport = get_vxlan_lb_hash(self.device, lb_vec_entry_list, stage=hldcli.RESOLUTION_STEP_STAGE3_DSPA)
        else:
            vxlan_sport = 0

        L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=self.get_mc_sa_addr_str(self.UND_MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL - 1) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=self.v6_get_mc_sa_addr_str(self.L3MC_GROUP_ADDR_V6),
                    src=vxlan_l2_single_port.DUMMY_SVI_MAC.addr_str) / \
            L3VXLAN_IPV6_PACKET

        ingress_packet = {'data': L3VXLAN_ENCAP_INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3})
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_L3})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_vxlan_l2_mcast_decap_und_bcast(self):
        # packet comes in at tx_l3_ac_reg and goes out at tx_l3_ac_def

        L3VXLAN_IPV4_PACKET = \
            S.Ether(dst=vxlan_l2_single_port.L2_BCAST_MAC.addr_str,
                    src=vxlan_l2_single_port.L2_SRC_MAC.addr_str,
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=0) / \
            S.ARP(op='who-has')

        L3VXLAN_IPV4_PACKET, __ = U.enlarge_packet_to_min_length(L3VXLAN_IPV4_PACKET, 68)

        L3VXLAN_DECAP_INPUT_PACKET = \
            S.Ether(dst=self.get_mc_sa_addr_str(self.UND_MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.OUTER_SRC_MAC) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=self.UND_MC_GROUP_ADDR.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=28480,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10000) / \
            L3VXLAN_IPV4_PACKET

        L3VXLAN_DECAP_PUNT_INPUT_PACKET = \
            S.Ether(dst=self.get_mc_sa_addr_str(self.UND_MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.RESERVED_SMAC.addr_str,
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=1399) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=self.UND_MC_GROUP_ADDR.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL - 1) / \
            S.UDP(sport=28480,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10000) / \
            L3VXLAN_IPV4_PACKET

        PUNT_PACKET = \
            S.Ether(dst=vxlan_l2_single_port.HOST_MAC_ADDR,
                    src=vxlan_l2_single_port.PUNT_INJECT_PORT_MAC_ADDR,
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0,
                    id=0,
                    vlan=vxlan_l2_single_port.MIRROR_VLAN,
                    type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                   code=sdk.LA_EVENT_ETHERNET_ARP + self.MIRROR_GID_INGRESS_OFFSET,
                   source_sp=self.topology.recycle_ports[1].sys_port.hld_obj.get_gid(),
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=vxlan_l2_single_port.VXLAN_L2_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                   destination_lp=sdk.LA_EVENT_ETHERNET_FIRST,
                   relay_id=T.TX_SWITCH_GID,
                   lpts_flow_type=0) / \
            L3VXLAN_DECAP_PUNT_INPUT_PACKET

        L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET = L3VXLAN_IPV4_PACKET

        L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1 = \
            S.Ether(dst=self.get_mc_sa_addr_str(self.UND_MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=self.UND_MC_GROUP_ADDR.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL - 1) / \
            S.UDP(sport=28480,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10000) / \
            L3VXLAN_IPV4_PACKET

        L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET = L3VXLAN_IPV4_PACKET

        ingress_packet = {
            'data': L3VXLAN_DECAP_INPUT_PACKET,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': T.FIRST_SERDES_L3}
        expected_packets = []
        expected_packets.append({'data': L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_SVI})
        expected_packets.append({'data': L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_SVI})
        expected_packets.append({'data': PUNT_PACKET,
                                 'slice': vxlan_l2_single_port.PI_SLICE,
                                 'ifg': vxlan_l2_single_port.PI_IFG,
                                 'pif': vxlan_l2_single_port.PI_PIF_FIRST})
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_vxlan_l2_mcast_decap_und(self):
        # packet comes in at tx_l3_ac_reg and goes out at tx_l3_ac_def

        L3VXLAN_IPV4_PACKET = \
            S.IP(dst=self.L2_MC_GROUP_ADDR.addr_str,
                 src='1.1.1.1',
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.TCP()
        L3VXLAN_IPV4_PACKET, __ = U.enlarge_packet_to_min_length(L3VXLAN_IPV4_PACKET, 68)

        L3VXLAN_DECAP_INPUT_PACKET = \
            S.Ether(dst=self.get_mc_sa_addr_str(self.UND_MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.OUTER_SRC_MAC) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=self.UND_MC_GROUP_ADDR.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=28480,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10000) / \
            S.Ether(dst=self.get_mc_sa_addr_str(self.L2_MC_GROUP_ADDR),
                    src='00:22:33:44:55:66') / \
            L3VXLAN_IPV4_PACKET

        L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(src='00:22:33:44:55:66',
                    dst=self.get_mc_sa_addr_str(self.L2_MC_GROUP_ADDR)) / \
            L3VXLAN_IPV4_PACKET

        L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1 = \
            S.Ether(dst=self.get_mc_sa_addr_str(self.UND_MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=self.UND_MC_GROUP_ADDR.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL - 1) / \
            S.UDP(sport=28480,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10000) / \
            S.Ether(dst=self.get_mc_sa_addr_str(self.L2_MC_GROUP_ADDR),
                    src='00:22:33:44:55:66') / \
            L3VXLAN_IPV4_PACKET

        L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(src='00:22:33:44:55:66',
                    dst=self.get_mc_sa_addr_str(self.L2_MC_GROUP_ADDR)) / \
            L3VXLAN_IPV4_PACKET

        ingress_packet = {
            'data': L3VXLAN_DECAP_INPUT_PACKET,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': T.FIRST_SERDES_L3}
        expected_packets = []
        expected_packets.append({'data': L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_SVI})
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3})
        expected_packets.append({'data': L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_SVI})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_vxlan_l3_mcast_decap_her(self):

        L3VXLAN_IPV4_PACKET = \
            S.IP(dst=self.L3MC_GROUP_ADDR.addr_str,
                 src='1.1.1.1',
                 id=0,
                 flags=2,
                 ttl=vxlan_base.INNER_TTL) / \
            S.TCP()
        L3VXLAN_IPV4_PACKET, __ = U.enlarge_packet_to_min_length(L3VXLAN_IPV4_PACKET, 68)

        L3VXLAN_DECAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 src=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(dport=4789) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=self.get_mc_sa_addr_str(self.L3MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.DUMMY_SVI_NH_MAC.addr_str) / \
            L3VXLAN_IPV4_PACKET

        L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=self.get_mc_sa_addr_str(self.L3MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_EXT_MAC.addr_str) / \
            L3VXLAN_IPV4_PACKET

        L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET.getlayer(0).ttl = vxlan_base.INNER_TTL - 1

        ingress_packet = {
            'data': L3VXLAN_DECAP_INPUT_PACKET,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': T.FIRST_SERDES_L3}
        expected_packets = []
        expected_packets.append({'data': L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_L3})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_vxlan_l3_arp_decap_her(self):

        L3VXLAN_IPV4_PACKET = \
            S.Ether(dst=vxlan_l2_single_port.L2_BCAST_MAC.addr_str,
                    src=vxlan_l2_single_port.L2_SRC_MAC.addr_str,
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=0) / \
            S.ARP(op='who-has')

        L3VXLAN_IPV4_PACKET, __ = U.enlarge_packet_to_min_length(L3VXLAN_IPV4_PACKET, 68)

        L3VXLAN_DECAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_EXT_MAC.addr_str) / \
            S.IP(dst=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 src=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(dport=4789) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            L3VXLAN_IPV4_PACKET

        PUNT_PACKET = \
            S.Ether(dst=vxlan_l2_single_port.HOST_MAC_ADDR,
                    src=vxlan_l2_single_port.PUNT_INJECT_PORT_MAC_ADDR,
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0,
                    id=0,
                    vlan=vxlan_l2_single_port.MIRROR_VLAN,
                    type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                   code=sdk.LA_EVENT_ETHERNET_ARP,
                   source_sp=T.TX_L3_AC_SYS_PORT_EXT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=vxlan_l2_single_port.VXLAN_L2_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                   destination_lp=sdk.LA_EVENT_ETHERNET_FIRST,
                   relay_id=T.RX_SWITCH_GID + 0x100,
                   lpts_flow_type=0) / \
            L3VXLAN_DECAP_INPUT_PACKET

        ingress_packet = {
            'data': L3VXLAN_DECAP_INPUT_PACKET,
            'slice': T.TX_SLICE_EXT,
            'ifg': T.TX_IFG_EXT,
            'pif': T.FIRST_SERDES_L3}
        expected_packets = []
        # ARP broadcast is only sent to CPU and will not go out
        expected_packets.append({'data': PUNT_PACKET,
                                 'slice': vxlan_l2_single_port.PI_SLICE,
                                 'ifg': vxlan_l2_single_port.PI_IFG,
                                 'pif': vxlan_l2_single_port.PI_PIF_FIRST})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_vxlan_l3_mcast_decap_und(self):
        # packet comes in at tx_l3_ac_reg and goes out at tx_l3_ac_def

        L3VXLAN_IPV4_PACKET = \
            S.IP(dst=self.L3MC_GROUP_ADDR.addr_str,
                 src='1.1.1.1',
                 id=0,
                 flags=2,
                 ttl=vxlan_base.INNER_TTL) / \
            S.TCP()
        L3VXLAN_IPV4_PACKET, __ = U.enlarge_packet_to_min_length(L3VXLAN_IPV4_PACKET, 68)

        L3VXLAN_DECAP_INPUT_PACKET = \
            S.Ether(dst=self.get_mc_sa_addr_str(self.UND_MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.OUTER_SRC_MAC) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=self.UND_MC_GROUP_ADDR.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=28480,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=self.get_mc_sa_addr_str(self.L3MC_GROUP_ADDR),
                    src='00:22:33:44:55:66') / \
            L3VXLAN_IPV4_PACKET

        L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.NEW_TX_L3_AC_EXT_MAC.addr_str,
                    dst=self.get_mc_sa_addr_str(self.L3MC_GROUP_ADDR)) / \
            L3VXLAN_IPV4_PACKET

        L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET.getlayer(0).ttl = vxlan_base.INNER_TTL - 1

        L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1 = \
            S.Ether(dst=self.get_mc_sa_addr_str(self.UND_MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=self.UND_MC_GROUP_ADDR.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL - 1) / \
            S.UDP(sport=28480,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=self.get_mc_sa_addr_str(self.L3MC_GROUP_ADDR),
                    src='00:22:33:44:55:66') / \
            L3VXLAN_IPV4_PACKET

        ingress_packet = {
            'data': L3VXLAN_DECAP_INPUT_PACKET,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': T.FIRST_SERDES_L3}
        expected_packets = []
        expected_packets.append({'data': L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_L3})
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        L3VXLAN_IPV6_PACKET = \
            S.IPv6(dst=self.L3MC_GROUP_ADDR_V6.addr_str,
                   src='2001::1',
                   hlim=vxlan_base.INNER_TTL) / \
            S.TCP()
        L3VXLAN_IPV6_PACKET, __ = U.enlarge_packet_to_min_length(L3VXLAN_IPV6_PACKET, 68)

        L3VXLAN_DECAP_INPUT_PACKET = \
            S.Ether(dst=self.get_mc_sa_addr_str(self.UND_MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.OUTER_SRC_MAC) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=self.UND_MC_GROUP_ADDR.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=28480,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=self.v6_get_mc_sa_addr_str(self.L3MC_GROUP_ADDR_V6),
                    src='00:22:33:44:55:66') / \
            L3VXLAN_IPV6_PACKET

        L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.NEW_TX_L3_AC_EXT_MAC.addr_str,
                    dst=self.v6_get_mc_sa_addr_str(self.L3MC_GROUP_ADDR_V6)) / \
            L3VXLAN_IPV6_PACKET

        L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET.getlayer(0).hlim = vxlan_base.INNER_TTL - 1

        L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1 = \
            S.Ether(dst=self.get_mc_sa_addr_str(self.UND_MC_GROUP_ADDR),
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=self.UND_MC_GROUP_ADDR.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL - 1) / \
            S.UDP(sport=28480,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=self.v6_get_mc_sa_addr_str(self.L3MC_GROUP_ADDR_V6),
                    src='00:22:33:44:55:66') / \
            L3VXLAN_IPV6_PACKET

        ingress_packet = {
            'data': L3VXLAN_DECAP_INPUT_PACKET,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': T.FIRST_SERDES_L3}
        expected_packets = []
        expected_packets.append({'data': L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_L3})
        expected_packets.append({'data': L3VXLAN_ENCAP_EXPECTED_OUTPU_PACKET1, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_vxlan_l2_decap_bcast(self):
        # Broadcast
        # packet comes in at tx_l3_ac_def and goes out at tx_l2_ac_port_def
        self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, __ = U.enlarge_packet_to_min_length(
            self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, 68)

        VXLAN_DECAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(dst=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 src=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=6522,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10000) / \
            self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET

        src_lp = vxlan_l2_single_port.VXLAN_L2_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING

        PUNT_PACKET = \
            S.Ether(dst=vxlan_l2_single_port.HOST_MAC_ADDR,
                    src=vxlan_l2_single_port.PUNT_INJECT_PORT_MAC_ADDR,
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0,
                    id=0,
                    vlan=vxlan_l2_single_port.MIRROR_VLAN,
                    type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                   code=sdk.LA_EVENT_ETHERNET_ARP + self.MIRROR_GID_INGRESS_OFFSET,
                   source_sp=T.TX_L3_AC_SYS_PORT_DEF_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=src_lp,
                   destination_lp=sdk.LA_EVENT_ETHERNET_FIRST,
                   relay_id=T.TX_SWITCH_GID,
                   lpts_flow_type=0) / \
            VXLAN_DECAP_INPUT_PACKET

        ingress_packet = {'data': VXLAN_DECAP_INPUT_PACKET, 'slice': T.TX_SLICE_DEF, 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3}
        expected_packets = []
        expected_packets.append({'data': self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_SVI})
        expected_packets.append({'data': self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_SVI})
        expected_packets.append({'data': PUNT_PACKET,
                                 'slice': vxlan_l2_single_port.PI_SLICE,
                                 'ifg': vxlan_l2_single_port.PI_IFG,
                                 'pif': vxlan_l2_single_port.PI_PIF_FIRST})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_vxlan_l2_decap_ucast(self):
        # Unknown Unicast
        # packet comes in at tx_l3_ac_def and goes out at tx_l2_ac_port_def
        self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, __ = U.enlarge_packet_to_min_length(
            self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, 68)

        VXLAN_DECAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(dst=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 src=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=6522,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10000) / \
            self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET

        ingress_packet = {'data': VXLAN_DECAP_INPUT_PACKET, 'slice': T.TX_SLICE_DEF, 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3}
        expected_packets = []
        expected_packets.append({'data': self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_SVI})
        expected_packets.append({'data': self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_SVI})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_vxlan_l2_decap_mcast(self):
        # Unknown Multicast
        # packet comes in at tx_l3_ac_def and goes out at tx_l2_ac_port_def
        self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, __ = U.enlarge_packet_to_min_length(
            self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, 68)

        VXLAN_DECAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(dst=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 src=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=6522,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10000) / \
            self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET

        ingress_packet = {'data': VXLAN_DECAP_INPUT_PACKET, 'slice': T.TX_SLICE_DEF, 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3}
        expected_packets = []
        expected_packets.append({'data': self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_EXT,
                                 'ifg': T.TX_IFG_EXT, 'pif': T.FIRST_SERDES_SVI})
        expected_packets.append({'data': self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_SVI})
        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_vxlan_l2_decap(self):
        # packet comes in at tx_l3_ac_def and goes out at tx_l2_ac_port_def

        self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, __ = U.enlarge_packet_to_min_length(
            self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, 68)

        VXLAN_DECAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(dst=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 src=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=6522,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10000) / \
            self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET

        U.run_and_compare(self, self.device,
                          VXLAN_DECAP_INPUT_PACKET, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_SVI_DEF)

        self.input_p_counter = self.device.create_counter(1)
        self.topology.tx_l3_ac_def.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.input_p_counter)

        self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, __ = U.enlarge_packet_to_min_length(
            self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, 68)

        VXLAN_DECAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(dst=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 src=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=6522,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance',
                    vni=9999) / \
            self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET

        self.input_p_counter = self.device.create_counter(1)
        self.topology.tx_l3_ac_def.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.input_p_counter)

        U.run_and_compare(self, self.device,
                          VXLAN_DECAP_INPUT_PACKET, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        packets, byte_count = self.vxlan_decap_counter.read(0, True, True)
        self.assertEqual(packets, 1)

        #packets, byte_count = self.tunnel_decap_counter.read(0, True, True)
        #self.assertEqual(packets, 2)

        self.topology.tx_l3_ac_def.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, None)
        self.device.destroy(self.input_p_counter)

    def _test_vxlan_l3_encap(self):
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, True)
        # packet comes in at tx_l3_ac_reg and goes out at tx_l3_ac_def
        self.L3VXLAN_IP_PACKET.getlayer(0).dst = self.OVL_DIP_1
        if self.is_ipv6():
            self.L3VXLAN_IP_PACKET.getlayer(0).hlim = vxlan_base.INNER_TTL
        else:
            self.L3VXLAN_IP_PACKET.getlayer(0).ttl = vxlan_base.INNER_TTL

        self.L3VXLAN_IP_PACKET, __ = U.enlarge_packet_to_min_length(self.L3VXLAN_IP_PACKET, 68)
        self.vxlan_l2_port.set_ttl_inheritance_mode(sdk.la_ttl_inheritance_mode_e_PIPE)

        L3VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_REG_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        if self.is_ipv6():
            self.L3VXLAN_IP_PACKET.getlayer(0).hlim = vxlan_base.INNER_TTL - 1
        else:
            self.L3VXLAN_IP_PACKET.getlayer(0).ttl = vxlan_base.INNER_TTL - 1

        if decor.is_pacific():
            if self.is_ipv6():
                vxlan_sport = 17927
            else:
                vxlan_sport = 24328
        elif decor.is_gibraltar():
            if self.is_ipv6():
                vxlan_sport = 2203
            else:
                vxlan_sport = 4726
        elif decor.is_asic4():
            load_bal_vector = sdk.la_lb_vector_t()
            if self.is_ipv6():
                load_bal_vector.type = sdk.LA_LB_VECTOR_IPV6_TCP_UDP
                load_bal_vector.ipv4.src_port = 20
                load_bal_vector.ipv4.dest_port = 80
                load_bal_vector.ipv6.sip = [0x00002222, 0x00000000, 0x0a0b12f0, 0x22220db8]
                load_bal_vector.ipv6.dip = [0x00001111, 0x00000000, 0x0a0b12f0, 0x11120db8]
                load_bal_vector.ipv6.next_header = 6  # TCP
            else:
                load_bal_vector.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
                load_bal_vector.ipv4.src_port = self.L3VXLAN_IP_PACKET[S.TCP].sport
                load_bal_vector.ipv4.dest_port = self.L3VXLAN_IP_PACKET[S.TCP].dport
                load_bal_vector.ipv4.sip = T.ipv4_addr(self.L3VXLAN_IP_PACKET[S.IP].src).to_num()
                load_bal_vector.ipv4.dip = T.ipv4_addr(self.L3VXLAN_IP_PACKET[S.IP].dst).to_num()
                load_bal_vector.ipv4.protocol = self.L3VXLAN_IP_PACKET[S.IP].proto

            lb_vec_entry_list = []
            lb_vec_entry_list.append(load_bal_vector)

            vxlan_sport = get_vxlan_lb_hash(self.device, lb_vec_entry_list, stage=hldcli.RESOLUTION_STEP_STAGE2_ECMP)
        else:
            vxlan_sport = 0

        outer_ttl = vxlan_base.OUTER_TTL
        if self.vxlan_2_pass_test:
            outer_ttl = outer_ttl - 1

        L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=outer_ttl) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=vxlan_l2_single_port.DUMMY_SVI_NH_MAC.addr_str,
                    src=vxlan_l2_single_port.DUMMY_SVI_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET
        U.run_and_compare(self, self.device,
                          L3VXLAN_ENCAP_INPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        self.L3VXLAN_IP_PACKET.getlayer(0).dst = self.OVL_DIP
        self.vxlan_l2_port.set_ttl(vxlan_base.OUTER_TTL)

        if self.is_ipv6():
            self.L3VXLAN_IP_PACKET.getlayer(0).hlim = vxlan_base.INNER_TTL
        else:
            self.L3VXLAN_IP_PACKET.getlayer(0).ttl = vxlan_base.INNER_TTL

        L3VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_REG_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        if self.is_ipv6():
            self.L3VXLAN_IP_PACKET.getlayer(0).hlim = vxlan_base.INNER_TTL - 1
        else:
            self.L3VXLAN_IP_PACKET.getlayer(0).ttl = vxlan_base.INNER_TTL - 1

        if decor.is_pacific():
            if self.is_ipv6():
                vxlan_sport = 19249
            else:
                vxlan_sport = 43646
        elif decor.is_gibraltar():
            if self.is_ipv6():
                vxlan_sport = 1928
            else:
                vxlan_sport = 25153
        elif decor.is_asic4():
            load_bal_vector = sdk.la_lb_vector_t()
            if self.is_ipv6():
                load_bal_vector.type = sdk.LA_LB_VECTOR_IPV6_TCP_UDP
                load_bal_vector.ipv4.src_port = 20
                load_bal_vector.ipv4.dest_port = 80
                load_bal_vector.ipv6.sip = [0x00002222, 0x00000000, 0x0a0b12f0, 0x22220db8]
                load_bal_vector.ipv6.dip = [0x00001111, 0x00000000, 0x0a0b12f0, 0x11110db8]
                load_bal_vector.ipv6.next_header = 6  # TCP
            else:
                load_bal_vector.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
                load_bal_vector.ipv4.src_port = self.L3VXLAN_IP_PACKET[S.TCP].sport
                load_bal_vector.ipv4.dest_port = self.L3VXLAN_IP_PACKET[S.TCP].dport
                load_bal_vector.ipv4.sip = T.ipv4_addr(self.L3VXLAN_IP_PACKET[S.IP].src).to_num()
                load_bal_vector.ipv4.dip = T.ipv4_addr(self.L3VXLAN_IP_PACKET[S.IP].dst).to_num()
                load_bal_vector.ipv4.protocol = self.L3VXLAN_IP_PACKET[S.IP].proto

            lb_vec_entry_list = []
            lb_vec_entry_list.append(load_bal_vector)

            vxlan_sport = get_vxlan_lb_hash(self.device, lb_vec_entry_list, stage=hldcli.RESOLUTION_STEP_STAGE2_ECMP)
        else:
            vxlan_sport = 0

        outer_ttl = vxlan_base.INNER_TTL - 1
        if self.vxlan_2_pass_test:
            outer_ttl = outer_ttl - 1

        L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=outer_ttl) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=vxlan_l2_single_port.DUMMY_SVI_NH_MAC.addr_str,
                    src=vxlan_l2_single_port.DUMMY_SVI_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        self.output_p_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.topology.tx_l3_ac_def.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.output_p_counter)

        self.vxlan_l2_port.set_ttl_inheritance_mode(sdk.la_ttl_inheritance_mode_e_UNIFORM)

        U.run_and_compare(self, self.device,
                          L3VXLAN_ENCAP_INPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)
        packets, byte_count = self.vxlan_l3_encap_counter.read(0, True, True)
        self.assertEqual(packets, 2)

        packets, byte_count = self.tunnel_encap_counter.read(0, True, True)
        self.assertEqual(packets, 2)

        #packets, byte_count = self.output_p_counter.read(0, True, True)
        #self.assertEqual(packets, 1)

        self.topology.tx_l3_ac_def.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, None)
        self.device.destroy(self.output_p_counter)

    def _test_vxlan_l3_decap(self):
        # packet comes in at tx_l3_ac_def and goes out at tx_l3_ac_reg
        self.L3VXLAN_IP_PACKET.getlayer(0).src = self.OVL_DIP
        self.L3VXLAN_IP_PACKET.getlayer(0).dst = self.OVL_SIP
        self.L3VXLAN_IP_PACKET, __ = U.enlarge_packet_to_min_length(self.L3VXLAN_IP_PACKET, 68)

        L3VXLAN_DECAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_EXT_MAC.addr_str) / \
            S.IP(dst=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 src=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(dport=4789) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(src=vxlan_l2_single_port.DUMMY_SVI_NH_MAC.addr_str,
                    dst=vxlan_l2_single_port.DUMMY_SVI_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        if self.is_ipv6():
            self.L3VXLAN_IP_PACKET.getlayer(0).hlim = vxlan_base.INNER_TTL - 1
        else:
            self.L3VXLAN_IP_PACKET.getlayer(0).ttl = vxlan_base.INNER_TTL - 1

        L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_REG_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        self.input_p_counter1 = self.device.create_counter(1)
        self.input_p_counter2 = self.device.create_counter(1)

        self.topology.tx_l3_ac_ext.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.input_p_counter1)
        self.recycle_l3_ac_port.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.input_p_counter2)
        U.run_and_compare(self, self.device,
                          L3VXLAN_DECAP_INPUT_PACKET, T.TX_SLICE_EXT,
                          T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT,
                          L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        packets, byte_count = self.vxlan_l3_decap_counter.read(0, True, True)
        self.assertEqual(packets, 1)

        #packets, byte_count = self.tunnel_decap_counter.read(0, True, True)
        #self.assertEqual(packets, 1)

        self.topology.tx_l3_ac_ext.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, None)
        self.device.destroy(self.input_p_counter1)

        self.recycle_l3_ac_port.set_ingress_counter(sdk.la_counter_set.type_e_PORT, None)
        self.device.destroy(self.input_p_counter2)

    def _test_vxlan_sda_encap(self):
        # packet comes in at tx_l3_ac_reg and goes out at tx_l3_ac_def
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, True)
        self.L3VXLAN_IP_PACKET.getlayer(0).dst = self.OVL_DIP_1
        if self.is_ipv6():
            self.L3VXLAN_IP_PACKET.getlayer(0).hlim = vxlan_base.INNER_TTL
        else:
            self.L3VXLAN_IP_PACKET.getlayer(0).ttl = vxlan_base.INNER_TTL

        self.L3VXLAN_IP_PACKET, __ = U.enlarge_packet_to_min_length(self.L3VXLAN_IP_PACKET, 68)

        L3VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_REG_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        if self.is_ipv6():
            self.L3VXLAN_IP_PACKET.getlayer(0).hlim = vxlan_base.INNER_TTL - 1
        else:
            self.L3VXLAN_IP_PACKET.getlayer(0).ttl = vxlan_base.INNER_TTL - 1

        if decor.is_pacific():
            if self.is_ipv6():
                vxlan_sport = 17927
            else:
                vxlan_sport = 24328
        elif decor.is_gibraltar():
            if self.is_ipv6():
                vxlan_sport = 2203
            else:
                vxlan_sport = 4726
        elif decor.is_asic4():
            load_bal_vector = sdk.la_lb_vector_t()
            if self.is_ipv6():
                load_bal_vector.type = sdk.LA_LB_VECTOR_IPV6_TCP_UDP
                load_bal_vector.ipv4.src_port = 20
                load_bal_vector.ipv4.dest_port = 80
                load_bal_vector.ipv6.sip = [0x00002222, 0x00000000, 0x0a0b12f0, 0x22220db8]
                load_bal_vector.ipv6.dip = [0x00001111, 0x00000000, 0x0a0b12f0, 0x11120db8]
                load_bal_vector.ipv6.next_header = 6  # TCP
            else:
                load_bal_vector.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
                load_bal_vector.ipv4.src_port = self.L3VXLAN_IP_PACKET[S.TCP].sport
                load_bal_vector.ipv4.dest_port = self.L3VXLAN_IP_PACKET[S.TCP].dport
                load_bal_vector.ipv4.sip = T.ipv4_addr(self.L3VXLAN_IP_PACKET[S.IP].src).to_num()
                load_bal_vector.ipv4.dip = T.ipv4_addr(self.L3VXLAN_IP_PACKET[S.IP].dst).to_num()
                load_bal_vector.ipv4.protocol = self.L3VXLAN_IP_PACKET[S.IP].proto

            lb_vec_entry_list = []
            lb_vec_entry_list.append(load_bal_vector)

            vxlan_sport = get_vxlan_lb_hash(self.device, lb_vec_entry_list, stage=hldcli.RESOLUTION_STEP_STAGE2_ECMP)
        else:
            vxlan_sport = 0

        L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=vxlan_l2_single_port.SDA_MAC.addr_str,
                    src=vxlan_l2_single_port.DUMMY_SVI_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        U.run_and_compare(self, self.device,
                          L3VXLAN_ENCAP_INPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        self.L3VXLAN_IP_PACKET.getlayer(0).dst = self.OVL_DIP

        if self.is_ipv6():
            self.L3VXLAN_IP_PACKET.getlayer(0).hlim = vxlan_base.INNER_TTL
        else:
            self.L3VXLAN_IP_PACKET.getlayer(0).ttl = vxlan_base.INNER_TTL

        L3VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_REG_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        if self.is_ipv6():
            self.L3VXLAN_IP_PACKET.getlayer(0).hlim = vxlan_base.INNER_TTL - 1
        else:
            self.L3VXLAN_IP_PACKET.getlayer(0).ttl = vxlan_base.INNER_TTL - 1

        if decor.is_pacific():
            if self.is_ipv6():
                vxlan_sport = 19249
            else:
                vxlan_sport = 43646
        elif decor.is_gibraltar():
            if self.is_ipv6():
                vxlan_sport = 1928
            else:
                vxlan_sport = 25153
        elif decor.is_asic4():
            load_bal_vector = sdk.la_lb_vector_t()
            if self.is_ipv6():
                load_bal_vector.type = sdk.LA_LB_VECTOR_IPV6_TCP_UDP
                load_bal_vector.ipv4.src_port = 20
                load_bal_vector.ipv4.dest_port = 80
                load_bal_vector.ipv6.sip = [0x00002222, 0x00000000, 0x0a0b12f0, 0x22220db8]
                load_bal_vector.ipv6.dip = [0x00001111, 0x00000000, 0x0a0b12f0, 0x11110db8]
                load_bal_vector.ipv6.next_header = 6  # TCP
            else:
                load_bal_vector.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
                load_bal_vector.ipv4.src_port = self.L3VXLAN_IP_PACKET[S.TCP].sport
                load_bal_vector.ipv4.dest_port = self.L3VXLAN_IP_PACKET[S.TCP].dport
                load_bal_vector.ipv4.sip = T.ipv4_addr(self.L3VXLAN_IP_PACKET[S.IP].src).to_num()
                load_bal_vector.ipv4.dip = T.ipv4_addr(self.L3VXLAN_IP_PACKET[S.IP].dst).to_num()
                load_bal_vector.ipv4.protocol = self.L3VXLAN_IP_PACKET[S.IP].proto

            lb_vec_entry_list = []
            lb_vec_entry_list.append(load_bal_vector)

            vxlan_sport = get_vxlan_lb_hash(self.device, lb_vec_entry_list, stage=hldcli.RESOLUTION_STEP_STAGE2_ECMP)
        else:
            vxlan_sport = 0

        L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=vxlan_l2_single_port.SDA_MAC.addr_str,
                    src=vxlan_l2_single_port.DUMMY_SVI_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        U.run_and_compare(self, self.device,
                          L3VXLAN_ENCAP_INPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def _test_vxlan_sda_decap(self):
        # packet comes in at tx_l3_ac_def and goes out at tx_l3_ac_reg
        self.L3VXLAN_IP_PACKET.getlayer(0).src = self.OVL_DIP
        self.L3VXLAN_IP_PACKET.getlayer(0).dst = self.OVL_SIP

        self.L3VXLAN_IP_PACKET, __ = U.enlarge_packet_to_min_length(self.L3VXLAN_IP_PACKET, 68)

        L3VXLAN_DECAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_EXT_MAC.addr_str) / \
            S.IP(dst=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 src=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(dport=4789) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(src=vxlan_l2_single_port.DUMMY_SVI_NH_MAC.addr_str,
                    dst=vxlan_l2_single_port.SDA_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        if self.is_ipv6():
            self.L3VXLAN_IP_PACKET.getlayer(0).hlim = vxlan_base.INNER_TTL - 1
        else:
            self.L3VXLAN_IP_PACKET.getlayer(0).ttl = vxlan_base.INNER_TTL - 1

        L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_REG_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        U.run_and_compare(self, self.device,
                          L3VXLAN_DECAP_INPUT_PACKET, T.TX_SLICE_EXT,
                          T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT,
                          L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3)

    def _test_vxlan_sda_decap_with_ip_inactivity(self):
        # packet comes in at tx_l3_ac_def and goes out at tx_l3_ac_reg
        self.L3VXLAN_IP_PACKET.getlayer(0).src = self.OVL_DIP
        self.L3VXLAN_IP_PACKET.getlayer(0).dst = self.OVL_SIP
        self.L3VXLAN_IP_PACKET, __ = U.enlarge_packet_to_min_length(self.L3VXLAN_IP_PACKET, 68)

        L3VXLAN_DECAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_EXT_MAC.addr_str) / \
            S.IP(dst=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 src=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL) / \
            S.UDP(dport=4789) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(src=vxlan_l2_single_port.DUMMY_SVI_NH_MAC.addr_str,
                    dst=vxlan_l2_single_port.SDA_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        self.L3VXLAN_IP_PACKET.getlayer(0).ttl = vxlan_base.INNER_TTL - 1

        L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_REG_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        # set sda mode
        sda_mode = True
        self.device.set_sda_mode(sda_mode)
        read_sda_mode = self.device.get_sda_mode()
        self.assertEqual(sda_mode, read_sda_mode)

        SIP_V4 = T.ipv4_addr('21.1.1.1')
        DIP_V4 = T.ipv4_addr('208.209.210.211')
        self.SIP = SIP_V4
        self.DIP = DIP_V4
        self.prefix = sdk.la_ipv4_prefix_t()
        self.prefix.addr.s_addr = self.SIP.to_num()
        self.prefix.length = 17
        self.ip_version = sdk.la_ip_version_e_IPV4
        self.prefix_1 = sdk.la_ipv4_prefix_t()
        self.prefix_1.addr.s_addr = self.DIP.to_num()
        self.prefix_1.length = 17

        # add ip snooping entry
        self.device.add_source_ip_snooping_prefix(self.topology.vrf.hld_obj, self.prefix)
        ip_snooping_entries = self.device.get_source_ip_snooping_prefixes()
        self.assertEqual(1, len(ip_snooping_entries))

        # adding same entry one more time
        self.device.add_source_ip_snooping_prefix(self.topology.vrf.hld_obj, self.prefix)

        # Table size is 1, so adding one more entry should raise exception
        with self.assertRaises(sdk.NotFoundException):
            self.device.add_source_ip_snooping_prefix(self.topology.vrf.hld_obj, self.prefix_1)

        self.L3VXLAN_IP_PACKET.getlayer(0).ttl = vxlan_base.INNER_TTL

        L3VXLAN_DECAP_INPUT_PACKET_NEW = \
            S.Ether(src=vxlan_l2_single_port.RESERVED_SMAC.addr_str,
                    dst=vxlan_l2_single_port.OUTER_SRC_MAC,
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=0x567) / \
            S.IP(dst=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 src=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=vxlan_base.OUTER_TTL - 1) / \
            S.UDP(dport=4789) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(src=vxlan_l2_single_port.DUMMY_SVI_NH_MAC.addr_str,
                    dst=vxlan_l2_single_port.SDA_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        PUNT_PACKET = \
            S.Ether(dst=vxlan_l2_single_port.HOST_MAC_ADDR,
                    src=vxlan_l2_single_port.PUNT_INJECT_PORT_MAC_ADDR,
                    type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0,
                    id=0,
                    vlan=vxlan_l2_single_port.MIRROR_VLAN,
                    type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                   code=vxlan_l2_single_port.MIRROR_CMD_INGRESS_GID,
                   source_sp=T.RCY_SYS_PORT_GID_BASE - 1,  # recycle_system_port
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_GID + 0x100,  # recycle_l3_ac_port
                   destination_lp=T.TX_L3_AC_REG_GID,
                   relay_id=self.topology.vrf.hld_obj.get_gid(),
                   lpts_flow_type=0) / \
            L3VXLAN_DECAP_INPUT_PACKET_NEW

        in_packet_data = {
            'data': L3VXLAN_DECAP_INPUT_PACKET,
            'slice': T.TX_SLICE_EXT,
            'ifg': T.TX_IFG_EXT,
            'pif': T.FIRST_SERDES_L3_EXT}
        out_packet_data = {
            'data': L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': T.FIRST_SERDES_L3}
        punt_packet_data = {
            'data': PUNT_PACKET,
            'slice': vxlan_l2_single_port.PI_SLICE,
            'ifg': vxlan_l2_single_port.PI_IFG,
            'pif': vxlan_l2_single_port.PI_PIF_FIRST,
            'egress_mirror_pi_port_pkt': False}
        U.run_and_compare_list(self, self.device, in_packet_data, [out_packet_data, punt_packet_data])

    def _test_vxlan_get_api(self):
        remote_ip = self.vxlan_l2_port.get_remote_ip_addr()
        self.assertEqual(remote_ip.s_addr,
                         vxlan_l2_single_port.VXLAN_DIP.hld_obj.s_addr)

        local_ip = self.vxlan_l2_port.get_local_ip_addr()
        self.assertEqual(local_ip.s_addr,
                         vxlan_l2_single_port.VXLAN_SIP.hld_obj.s_addr)

        vrf = self.vxlan_l2_port.get_vrf()
        self.assertEqual(vrf.get_gid(), self.topology.vrf.hld_obj.get_gid())

        nh = self.vxlan_l2_port.get_l3_destination()
        self.assertEqual(nh.this,
                         self.l3_port_impl.def_nh.hld_obj.this)

        vni = self.vxlan_l2_port.get_encap_vni(self.topology.rx_switch.hld_obj)
        self.assertEqual(vni, 9999)
        vni = self.vxlan_l2_port.get_encap_vni(self.topology.tx_switch.hld_obj)
        self.assertEqual(vni, 10000)


class vxlan_snake_port(vxlan_base):

    SNAKE_SWITCH_ID_BASE = 0x100
    SNAKE_L3_PORT_MAC_BASE = '50:f5:f5:f5:f5:'
    SNAKE_LOCAL_IP_BASE = "40.1.1."
    SNAKE_REMOTE_IP_BASE = "40.1.1."
    SNAKE_VNI_BASE = 20000
    SNAKE_VLAN_BASE = 10
    SNAKE_L3_PORT_ID_BASE = 0x500
    SNAKE_VXLAN_PORT_ID_BASE = 0x300
    SNAKE_LOOP_SIZE = 4

    def snake_port_setup_l3_ac_port(self):
        self.snake_vxlan_underlay_port_db = dict()
        self.snake_l3_port_mac_db = dict()
        snake_l3_ac_port_id = vxlan_snake_port.SNAKE_L3_PORT_ID_BASE
        snake_l3_port_vid1 = vxlan_snake_port.SNAKE_VLAN_BASE
        for iloop in range(vxlan_snake_port.SNAKE_LOOP_SIZE):
            for oloop in range(vxlan_snake_port.SNAKE_LOOP_SIZE):
                # create the L3 AC port, it on the tx def port
                snake_l3_port_mac_str = \
                    vxlan_snake_port.SNAKE_L3_PORT_MAC_BASE + \
                    "%0.2x" % (iloop * vxlan_snake_port.SNAKE_LOOP_SIZE + oloop)
                self.snake_l3_port_mac_db[snake_l3_ac_port_id] = \
                    snake_l3_port_mac_str
                sanke_l3_port_mac = T.mac_addr(snake_l3_port_mac_str)
                snake_tag = sdk.la_vlan_tag_t()
                snake_tag.tpid = 0x8100
                snake_tag.tci.fields.pcp = 0
                snake_tag.tci.fields.dei = 0
                snake_tag.tci.fields.vid = snake_l3_port_vid1
                snake_l3_ac_port = \
                    T.l3_ac_port(self,
                                 self.device,
                                 snake_l3_ac_port_id,
                                 self.topology.tx_l3_ac_eth_port_def,
                                 self.topology.vrf,
                                 sanke_l3_port_mac,
                                 snake_l3_port_vid1,
                                 0)
                self.snake_vxlan_underlay_port_db[snake_l3_ac_port_id] = \
                    snake_l3_ac_port
                snake_l3_ac_port.hld_obj.set_egress_vlan_tag(snake_tag, sdk.LA_VLAN_TAG_UNTAGGED)
                snake_l3_ac_port.hld_obj.set_protocol_enabled(
                    sdk.la_l3_protocol_e_IPV4_UC, True)
                snake_l3_ac_port.hld_obj.set_protocol_enabled(
                    sdk.la_l3_protocol_e_IPV6_UC, True)
                self.snake_last_l3_ac_port_id = snake_l3_ac_port_id
                snake_l3_ac_port_id = snake_l3_ac_port_id + 1
                snake_l3_port_vid1 = snake_l3_port_vid1 + 1

    def snake_port_setup(self):
        self.snake_switch_db = dict()
        self.snake_local_ip_db = dict()
        self.snake_remote_ip_db = dict()
        self.snake_vxlan_port_db = dict()
        self.snake_vxlan_nh_db = dict()

        snake_switch_id = vxlan_snake_port.SNAKE_SWITCH_ID_BASE
        snake_vxlan_port_id = vxlan_snake_port.SNAKE_VXLAN_PORT_ID_BASE
        snake_l3_ac_port_id = vxlan_snake_port.SNAKE_L3_PORT_ID_BASE
        snake_nh_id = 0x200
        snake_l3_port_vid1 = vxlan_snake_port.SNAKE_VLAN_BASE
        snake_vni = vxlan_snake_port.SNAKE_VNI_BASE
        for iloop in range(vxlan_snake_port.SNAKE_LOOP_SIZE):
            snake_local_ip = vxlan_snake_port.SNAKE_LOCAL_IP_BASE + str(iloop)
            VXLAN_SNAKE_LOCAL_IP = T.ipv4_addr(snake_local_ip)
            for oloop in range(vxlan_snake_port.SNAKE_LOOP_SIZE):
                snake_remote_ip = vxlan_snake_port.SNAKE_REMOTE_IP_BASE + \
                    str(oloop)
                self.snake_local_ip_db[snake_vxlan_port_id] = snake_local_ip
                self.snake_remote_ip_db[snake_vxlan_port_id] = snake_remote_ip
                VXLAN_SNAKE_REMOTE_DIP = T.ipv4_addr(snake_remote_ip)
                # create a switch
                snake_switch = T.switch(self, self.device, snake_switch_id)
                self.snake_switch_db[snake_switch_id] = snake_switch
                snake_switch_id = snake_switch_id + 1
                sanke_l3_port_mac = T.mac_addr(self.snake_l3_port_mac_db[snake_l3_ac_port_id])
                snake_nh = T.next_hop(self, self.device, snake_nh_id,
                                      sanke_l3_port_mac, self.snake_vxlan_underlay_port_db[snake_l3_ac_port_id])
                self.snake_vxlan_nh_db[snake_nh_id] = snake_nh
                snake_nh_id = snake_nh_id + 1
                snake_l3_ac_port_id = snake_l3_ac_port_id + 1
                # create the VXLAN tunnel
                snake_vxlan_l2_port = \
                    self.device.create_vxlan_l2_service_port(
                        snake_vxlan_port_id,
                        VXLAN_SNAKE_LOCAL_IP.hld_obj,
                        VXLAN_SNAKE_REMOTE_DIP.hld_obj,
                        self.topology.vrf.hld_obj)
                snake_vxlan_l2_port.set_l3_destination(snake_nh.hld_obj)
                self.snake_vxlan_port_db[snake_vxlan_port_id] = \
                    snake_vxlan_l2_port
                snake_vxlan_port_id = snake_vxlan_port_id + 4
                # set vni on the switch
                snake_vxlan_l2_port.set_encap_vni(snake_switch.hld_obj, snake_vni)
                # snake_switch.hld_obj.set_encap_vni(snake_vni)
                snake_vni = snake_vni + 1
                # set up mac forwarding entry
                snake_switch.hld_obj.set_mac_entry(
                    vxlan_l2_single_port.VXLAN_DST_MAC.hld_obj,
                    snake_vxlan_l2_port,
                    sdk.LA_MAC_AGING_TIME_NEVER)

        snake_switch_id = vxlan_snake_port.SNAKE_SWITCH_ID_BASE
        snake_vni = vxlan_snake_port.SNAKE_VNI_BASE
        for iloop in range(vxlan_snake_port.SNAKE_LOOP_SIZE):
            for oloop in range(vxlan_snake_port.SNAKE_LOOP_SIZE):
                if snake_switch_id != vxlan_snake_port.SNAKE_SWITCH_ID_BASE:
                    snake_switch = self.snake_switch_db[snake_switch_id]
                    snake_switch.hld_obj.set_decap_vni(snake_vni - 1)
                snake_switch_id = snake_switch_id + 1
                snake_vni = snake_vni + 1
        self.sa_da_trap_configuration = self.device.get_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)

    def _test_snake_loop(self):

        snake_vlan = vxlan_snake_port.SNAKE_VLAN_BASE
        snake_vni = vxlan_snake_port.SNAKE_VNI_BASE
        snake_l3_ac_port_id = vxlan_snake_port.SNAKE_L3_PORT_ID_BASE
        snake_vxlan_port_id = vxlan_snake_port.SNAKE_VXLAN_PORT_ID_BASE
        # packet comes in at tx_l3_ac_def
        SNAKE_INNER_PACKET = \
            S.Ether(dst=vxlan_l2_single_port.VXLAN_DST_MAC.addr_str,
                    src=vxlan_l2_single_port.VXLAN_SRC_MAC.addr_str) / \
            S.IP(dst="2.2.2.2", src="1.1.1.1") / \
            S.TCP()

        for iloop in range(vxlan_snake_port.SNAKE_LOOP_SIZE):
            outer_src_ip = vxlan_snake_port.SNAKE_LOCAL_IP_BASE + str(iloop)
            for oloop in range(vxlan_snake_port.SNAKE_LOOP_SIZE):
                outer_dst_ip = vxlan_snake_port.SNAKE_REMOTE_IP_BASE + \
                    str(oloop)
                outer_mac = vxlan_snake_port.SNAKE_L3_PORT_MAC_BASE + \
                    "%0.2x" % (iloop * vxlan_snake_port.SNAKE_LOOP_SIZE + oloop)

                if snake_l3_ac_port_id == vxlan_snake_port.SNAKE_L3_PORT_ID_BASE:
                    SNAKE_INPUT_PACKET = \
                        S.Ether(src='60:f5:f5:f5:f5:00',
                                dst=outer_mac,
                                type=U.Ethertype.Dot1Q.value) / \
                        S.Dot1Q(vlan=snake_vlan) / \
                        S.IP(dst=outer_src_ip,
                             src=outer_dst_ip,
                             id=0,
                             flags=2,
                             ttl=3) / \
                        S.UDP(sport=6511,
                              dport=4789,
                              chksum=0) / \
                        P.VXLAN(flags='Instance', vni=snake_vni) / \
                        SNAKE_INNER_PACKET
                else:
                    # the input is previous output packet
                    SNAKE_INPUT_PACKET = SNAKE_EXPECTED_OUTPUT_PACKET

                if decor.is_pacific():
                    vxlan_sport = 42480
                elif decor.is_gibraltar():
                    vxlan_sport = 26245
                elif decor.is_asic4():
                    load_bal_vector = sdk.la_lb_vector_t()
                    load_bal_vector.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV4_L4
                    load_bal_vector.ipv4.src_port = SNAKE_INNER_PACKET[S.TCP].sport
                    load_bal_vector.ipv4.dest_port = SNAKE_INNER_PACKET[S.TCP].dport
                    load_bal_vector.ipv4.sip = T.ipv4_addr(SNAKE_INNER_PACKET[S.IP].src).to_num()
                    load_bal_vector.ipv4.dip = T.ipv4_addr(SNAKE_INNER_PACKET[S.IP].dst).to_num()
                    load_bal_vector.ipv4.protocol = SNAKE_INNER_PACKET[S.IP].proto

                    lb_vec_entry_list = []
                    lb_vec_entry_list.append(load_bal_vector)

                    vxlan_sport = get_vxlan_lb_hash(self.device, lb_vec_entry_list, stage=hldcli.RESOLUTION_STEP_STAGE2_ECMP)
                else:
                    vxlan_sport = 0

                SNAKE_EXPECTED_OUTPUT_PACKET = \
                    S.Ether(dst=self.snake_l3_port_mac_db[snake_l3_ac_port_id + 1],
                            src=self.snake_l3_port_mac_db[snake_l3_ac_port_id + 1],
                            type=U.Ethertype.Dot1Q.value) / \
                    S.Dot1Q(vlan=snake_vlan + 1) / \
                    S.IP(src=self.snake_local_ip_db[snake_vxlan_port_id + 4],
                         dst=self.snake_remote_ip_db[snake_vxlan_port_id + 4],
                         id=0,
                         flags=2,
                         ttl=vxlan_base.OUTER_TTL) / \
                    S.UDP(sport=vxlan_sport,
                          dport=4789,
                          chksum=0) / \
                    P.VXLAN(flags='Instance', vni=snake_vni + 1) / \
                    SNAKE_INNER_PACKET

                U.run_and_compare(self, self.device,
                                  SNAKE_INPUT_PACKET, T.TX_SLICE_DEF,
                                  T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                  SNAKE_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF,
                                  T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

                snake_vlan = snake_vlan + 1
                snake_vni = snake_vni + 1
                snake_l3_ac_port_id = snake_l3_ac_port_id + 1
                snake_vxlan_port_id = snake_vxlan_port_id + 4
                # the last port wont loopback
                if self.snake_last_l3_ac_port_id == snake_l3_ac_port_id:
                    break

    def snake_port_destroy(self):

        snake_switch_id = vxlan_snake_port.SNAKE_SWITCH_ID_BASE
        snake_vxlan_port_id = vxlan_snake_port.SNAKE_VXLAN_PORT_ID_BASE
        snake_nh_id = 0x200
        snake_l3_port_vid1 = vxlan_snake_port.SNAKE_VLAN_BASE
        snake_vni = vxlan_snake_port.SNAKE_VNI_BASE
        for iloop in range(vxlan_snake_port.SNAKE_LOOP_SIZE):
            snake_local_ip = vxlan_snake_port.SNAKE_LOCAL_IP_BASE + str(iloop)
            VXLAN_SNAKE_LOCAL_IP = T.ipv4_addr(snake_local_ip)
            for oloop in range(vxlan_snake_port.SNAKE_LOOP_SIZE):
                snake_remote_ip = vxlan_snake_port.SNAKE_REMOTE_IP_BASE + \
                    str(oloop)
                self.snake_local_ip_db[snake_vxlan_port_id] = snake_local_ip
                self.snake_remote_ip_db[snake_vxlan_port_id] = snake_remote_ip
                VXLAN_SNAKE_REMOTE_DIP = T.ipv4_addr(snake_remote_ip)

                # get the switch
                snake_switch = self.snake_switch_db[snake_switch_id]

                # remove  mac forwarding entry
                snake_switch.hld_obj.remove_mac_entry(
                    vxlan_l2_single_port.VXLAN_DST_MAC.hld_obj)

                # clear vni on the switch
                if snake_switch_id != vxlan_snake_port.SNAKE_SWITCH_ID_BASE:
                    snake_switch.hld_obj.clear_decap_vni()
                snake_vni = snake_vni + 1
                snake_switch_id = snake_switch_id + 1

                # destroy the VXLAN tunnel
                snake_vxlan_l2_port = \
                    self.snake_vxlan_port_db[snake_vxlan_port_id]
                snake_vxlan_l2_port.clear_encap_vni(snake_switch.hld_obj)
                self.device.destroy(snake_vxlan_l2_port)
                snake_vxlan_port_id = snake_vxlan_port_id + 4

                # destroy nh on the port
                snake_nh = self.snake_vxlan_nh_db[snake_nh_id]
                snake_nh.destroy()
                snake_nh_id = snake_nh_id + 1

                # destroy the switch
                snake_switch.destroy()
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR, *self.sa_da_trap_configuration)

    def snake_port_destroy_l3_ac_port(self):
        snake_l3_ac_port_id = vxlan_snake_port.SNAKE_L3_PORT_ID_BASE
        for iloop in range(vxlan_snake_port.SNAKE_LOOP_SIZE):
            snake_local_ip = vxlan_snake_port.SNAKE_LOCAL_IP_BASE + str(iloop)
            VXLAN_SNAKE_LOCAL_IP = T.ipv4_addr(snake_local_ip)
            for oloop in range(vxlan_snake_port.SNAKE_LOOP_SIZE):
                # destroy the L3 AC port
                snake_l3_ac_port = \
                    self.snake_vxlan_underlay_port_db[snake_l3_ac_port_id]
                snake_l3_ac_port.destroy()
                snake_l3_ac_port_id = snake_l3_ac_port_id + 1
