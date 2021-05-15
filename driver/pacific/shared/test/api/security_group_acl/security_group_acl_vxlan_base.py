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

from enum import Enum
import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import packet_test_defs as P
import sim_utils
import ip_test_base
import time
import nplapicli as nplapi
import decor

CHAR_BIT = 8
BYTES_NUM_IN_ADDR = 16


class command_type(Enum):
    NOP = 0
    PERMIT = 1
    DROP = 2
    MONITOR = 3


def apply_v6_prefix_mask(q0, q1, prefix_length):
    dqw_addr = q1 << 64 | q0
    mask = ~((1 << (CHAR_BIT * BYTES_NUM_IN_ADDR - prefix_length)) - 1)
    dqw_addr = dqw_addr & mask
    masked_q0 = dqw_addr & ((1 << 64) - 1)
    masked_q1 = dqw_addr >> 64
    return masked_q0, masked_q1


def build_v6_prefix(dip, length):
    prefix = sdk.la_ipv6_prefix_t()
    q0 = sdk.get_ipv6_addr_q0(dip.hld_obj)
    q1 = sdk.get_ipv6_addr_q1(dip.hld_obj)
    masked_q0, masked_q1 = apply_v6_prefix_mask(q0, q1, length)
    sdk.set_ipv6_addr(prefix.addr, masked_q0, masked_q1)
    prefix.length = length
    return prefix


class security_group_acl_vxlan_base(unittest.TestCase):
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    TTL = 255
    INNER_TTL = 200
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    OUTPUT_VID = 0xac

    @staticmethod
    def device_config_func(device, state):
        device.set_int_property(sdk.la_device_property_e_SGACL_MAX_CELL_COUNTERS, 1024)

    def setUp(self):

        self.maxDiff = None  # Show whole strings on failures (unittest variable)
        self.device = U.sim_utils.create_device(1, slice_modes=sim_utils.STANDALONE_DEV,
                                                device_config_func=security_group_acl_vxlan_base.device_config_func)

        self.topology = T.topology(self, self.device)

        self.topology.tx_l3_ac_eth_port_def.hld_obj.set_service_mapping_type(sdk.la_ethernet_port.service_mapping_type_e_SMALL)

        self.l3_port_impl = T.ip_l3_ac_base(self.topology)

        self.add_default_route()

        self.sgacl_key_profile = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_SGACL, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_SECURITY_GROUP, 0)
        self.sgacl_command_profile = self.device.create_acl_command_profile(sdk.LA_SGACL_COMMAND)

    def tearDown(self):
        self.device.tearDown()

    def add_default_route(self):
        prefix = self.underlay_ip_impl.get_default_prefix()
        self.underlay_ip_impl.add_route(self.topology.vrf, prefix,
                                        self.l3_port_impl.def_nh,
                                        security_group_acl_vxlan_base.PRIVATE_DATA_DEFAULT)
        self.has_default_route = True

    def destroy_default_route(self):
        if self.has_default_route:
            prefix = self.underlay_ip_impl.get_default_prefix()
            self.underlay_ip_impl.delete_route(self.topology.vrf, prefix)
            self.has_default_route = False

    def setup_recycle_port(self):
        for slice in [1, 3, 5]:
            print("slice=", slice)
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


class vxlan_l2_single_port(security_group_acl_vxlan_base):
    IPv4_ADDRESS_SIZE = T.ipv4_addr.NUM_OF_BYTES
    IPv6_ADDRESS_SIZE = T.ipv6_addr.NUM_OF_BYTES
    NEW_TX_L3_AC_DEF_MAC = T.mac_addr('50:52:53:54:55:56')
    NEW_TX_L3_AC_REG_MAC = T.mac_addr('60:62:63:64:65:66')
    NEW_TX_L3_AC_EXT_MAC = T.mac_addr('70:72:73:74:75:76')
    VXLAN_L2_PORT_GID = 0x250
    VXLAN_SIP = T.ipv4_addr('12.10.12.11')
    VXLAN_DIP = T.ipv4_addr('12.1.95.250')
    VXLAN_SRC_MAC = T.mac_addr('06:12:34:56:78:9a')
    VXLAN_DST_MAC = T.mac_addr('08:bc:de:23:45:67')
    L2_SRC_MAC = T.mac_addr('02:11:22:33:44:55')
    L2_DST_MAC = T.mac_addr('04:66:77:88:99:aa')
    DUMMY_SVI_MAC = T.mac_addr('30:32:33:34:35:36')
    DUMMY_SVI_NH_GID = 0x123
    DUMMY_SVI_NH_MAC = T.mac_addr('20:22:23:24:25:26')
    OUTER_SRC_MAC = '00:11:22:33:44:55'
    SDA_MAC = T.mac_addr('10:12:13:14:15:16')
    RECYCLE_PORT_MAC = T.mac_addr('00:11:22:33:44:55')
    OUTER_SRC_MAC = '00:11:22:33:44:55'
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
    PI_SLICE = 3
    PI_IFG = 1
    PI_PIF_FIRST = 8
    PUNT_VLAN = 0xA13
    MIRROR_CMD_GID = 9
    MIRROR_VLAN = 0xA12

    def create_recycle_ac_port(self):
        self.recycle_eth_port = self.device.create_ethernet_port(
            self.topology.recycle_ports[1].sys_port.hld_obj,
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

        self.recycle_nh = self.device.create_next_hop(
            T.NH_L3_AC_REG_GID + 0x100,
            vxlan_l2_single_port.RECYCLE_PORT_MAC.hld_obj,
            self.recycle_l3_ac_port,
            sdk.la_next_hop.nh_type_e_NORMAL)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)

        # Set the vlan for the tx side for l3 ac
        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0x8100
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = 0x567

        self.recycle_l3_ac_port.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

    def destroy_recycle_ac_port(self):
        self.device.destroy(self.recycle_nh)
        self.device.destroy(self.recycle_l3_ac_port)
        self.device.destroy(self.recycle_l2_ac_port)
        self.device.destroy(self.recycle_eth_port)

    def create_recycle_ac_port_spa(self):
        print("system port gid is ", self.topology.recycle_ports[5].sys_port.hld_obj.get_gid())
        self.recycle_spa_port = self.device.create_spa_port(1)
        self.recycle_spa_port.add(self.topology.recycle_ports[1].sys_port.hld_obj)
        self.recycle_spa_port.set_member_transmit_enabled(self.topology.recycle_ports[1].sys_port.hld_obj, True)
        self.recycle_spa_port.add(self.topology.recycle_ports[3].sys_port.hld_obj)
        self.recycle_spa_port.set_member_transmit_enabled(self.topology.recycle_ports[3].sys_port.hld_obj, True)
        self.recycle_spa_port.add(self.topology.recycle_ports[5].sys_port.hld_obj)
        self.recycle_spa_port.set_member_transmit_enabled(self.topology.recycle_ports[5].sys_port.hld_obj, True)

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

        self.recycle_nh = self.device.create_next_hop(
            T.NH_L3_AC_REG_GID + 0x100,
            vxlan_l2_single_port.RECYCLE_PORT_MAC.hld_obj,
            self.recycle_l3_ac_port,
            sdk.la_next_hop.nh_type_e_NORMAL)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)

        # Set the vlan for the tx side for l3 ac
        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0x8100
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = 0x567

        self.recycle_l3_ac_port.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

    def setup_vxlan_2_pass(self):
        self.vxlan_l2_port.set_l3_destination(self.recycle_nh)

    def single_port_setup(self):
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
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)

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

        # now let's creat L2 VXLAN port
        self.vxlan_l2_port = self.device.create_vxlan_l2_service_port(
            vxlan_l2_single_port.VXLAN_L2_PORT_GID,
            vxlan_l2_single_port.VXLAN_SIP.hld_obj,
            vxlan_l2_single_port.VXLAN_DIP.hld_obj,
            self.topology.vrf.hld_obj)
        self.vxlan_l2_port.set_l3_destination(self.l3_port_impl.def_nh.hld_obj)

        # set VNI the on the switch/BD
        self.vxlan_l2_port.set_encap_vni(self.topology.rx_switch.hld_obj, 9999)
        self.topology.rx_switch.hld_obj.set_decap_vni(9999)
        self.vxlan_l2_port.set_encap_vni(self.topology.tx_switch.hld_obj, 10000)
        self.topology.tx_switch.hld_obj.set_decap_vni(10000)

        self.vxlan_decap_counter = self.device.create_counter(1)
        self.topology.rx_switch.hld_obj.set_vxlan_decap_counter(self.vxlan_decap_counter)

        self.vxlan_encap_counter = self.device.create_counter(1)
        self.topology.rx_switch.hld_obj.set_vxlan_encap_counter(self.vxlan_encap_counter)

        self.tunnel_decap_counter = self.device.create_counter(1)
        self.vxlan_l2_port.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.tunnel_decap_counter)

        self.tunnel_encap_counter = self.device.create_counter(1)
        self.vxlan_l2_port.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.tunnel_encap_counter)

        # set vxlan mac to forwarding table
        self.topology.rx_switch.hld_obj.set_mac_entry(
            vxlan_l2_single_port.VXLAN_DST_MAC.hld_obj,
            self.vxlan_l2_port,
            sdk.LA_MAC_AGING_TIME_NEVER)

        self.topology.tx_switch.hld_obj.set_mac_entry(
            vxlan_l2_single_port.VXLAN_DST_MAC.hld_obj,
            self.vxlan_l2_port,
            sdk.LA_MAC_AGING_TIME_NEVER)

    def setup_ecmp(self):
        self.vxlan_l2_port.set_l3_destination(self.unl_ecmp)

    def single_port_destroy(self):
        self.topology.rx_switch.hld_obj.remove_mac_entry(
            vxlan_l2_single_port.VXLAN_DST_MAC.hld_obj)
        self.topology.tx_switch.hld_obj.remove_mac_entry(
            vxlan_l2_single_port.VXLAN_DST_MAC.hld_obj)
        self.vxlan_l2_port.clear_encap_vni(self.topology.rx_switch.hld_obj)
        self.topology.rx_switch.hld_obj.clear_decap_vni()
        self.vxlan_l2_port.clear_encap_vni(self.topology.tx_switch.hld_obj)
        self.topology.tx_switch.hld_obj.clear_decap_vni()
        self.device.destroy(self.vxlan_l2_port)
        self.device.destroy(self.unl_ecmp)

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

        self.vxlan_l2_port.set_encap_vni(self.dummy_switch.hld_obj, 10001)
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
        self.dummy_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

        self.vxlan_l2_port.set_encap_vni(self.dummy_switch.hld_obj, 10001)
        self.dummy_switch.hld_obj.set_decap_vni_profile(sdk.la_switch.vxlan_termination_mode_e_IGNORE_DMAC)
        self.dummy_switch.hld_obj.set_decap_vni(10001)

        # create nexthop on the SVI
        self.svi_nh = vxlan_next_hop(self.device, vxlan_l2_single_port.SDA_MAC, self.dummy_svi, self.vxlan_l2_port)

        # create ip route
        self.ovl_sip_prefix = self.underlay_ip_impl.build_prefix(self.OVL_SIP_ROUTE, length=24)
        self.underlay_ip_impl.add_route(self.topology.vrf, self.ovl_sip_prefix, self.svi_nh, self.PRIVATE_DATA)

        self.ovl_dip_prefix_1 = self.underlay_ip_impl.build_prefix(self.OVL_DIP_ROUTE_1, self.get_prefix_length())
        self.underlay_ip_impl.add_route(self.topology.vrf, self.ovl_dip_prefix_1, self.svi_nh, self.PRIVATE_DATA)

        self.ovl_dip_prefix = self.underlay_ip_impl.build_prefix(self.OVL_DIP_ROUTE, length=24)
        self.underlay_ip_impl.add_route(self.topology.vrf, self.ovl_dip_prefix, self.topology.nh_l3_ac_reg, self.PRIVATE_DATA)

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

    def set_l2_sgacl(self, monitor=False, drop=False, is_ipv4=True, is_encap=True):
        if monitor:
            self.command = command_type(command_type.MONITOR)
        elif drop:
            self.command = command_type(command_type.DROP)
        else:
            self.command = command_type(command_type.PERMIT)

        if is_ipv4:
            self.ipvx = 'v4'
            SIP = T.ipv4_addr(self.OVL_SIPv4)
            DIP = T.ipv4_addr(self.OVL_DIPv4)
            self.source_host_prefix = sdk.la_ipv4_prefix_t()
            self.source_host_prefix.addr.s_addr = SIP.to_num()
            self.source_host_prefix.length = 32
            self.source_subnet_prefix = sdk.la_ipv4_prefix_t()
            self.source_subnet_prefix.length = 24
            self.source_subnet_prefix.addr.s_addr = SIP.to_num() & 0xffffff00
            self.destination_host_prefix = sdk.la_ipv4_prefix_t()
            self.destination_host_prefix.addr.s_addr = DIP.to_num()
            self.destination_host_prefix.length = 32
            self.destination_subnet_prefix = sdk.la_ipv4_prefix_t()
            self.destination_subnet_prefix.length = 24
            self.destination_subnet_prefix.addr.s_addr = DIP.to_num() & 0xffffff00
            self.ip_version = sdk.la_ip_version_e_IPV4
        else:
            self.ipvx = 'v6'
            SIP = T.ipv6_addr(self.OVL_SIPv6)
            DIP = T.ipv6_addr(self.OVL_DIPv6)
            self.source_host_prefix = build_v6_prefix(SIP, 128)
            self.source_subnet_prefix = build_v6_prefix(SIP, 64)
            self.destination_host_prefix = build_v6_prefix(DIP, 128)
            self.destination_subnet_prefix = build_v6_prefix(DIP, 64)
            self.ip_version = sdk.la_ip_version_e_IPV6

        self.sgacl_counter = self.device.create_counter(2)

        self.device.set_sda_mode(True)
        sgt = 100
        dgt = 200

        if is_encap:
            self.topology.global_vrf.hld_obj.add_security_group_tag(self.source_host_prefix, sgt)
        else:
            # For Decap, we want to check honouring packet SGT, so program a random sgt here.
            self.topology.global_vrf.hld_obj.add_security_group_tag(self.source_host_prefix, 0xaa)

        self.topology.global_vrf.hld_obj.add_security_group_tag(self.destination_host_prefix, dgt)

        ''' Creating sgt/dgt cell and monitor mode.'''
        self.cell = self.device.create_security_group_cell(sgt, dgt, self.ip_version)

        if self.command == command_type.MONITOR:
            allow_drop = False
        else:
            allow_drop = True

        self.cell.set_monitor_mode(allow_drop)
        read_allow_drop = self.cell.get_monitor_mode()
        self.assertEqual(allow_drop, read_allow_drop)

        self.sgacl = self.device.create_acl(self.sgacl_key_profile, self.sgacl_command_profile)
        self.assertNotEqual(self.sgacl, None)
        count = self.sgacl.get_count()
        self.assertEqual(count, 0)

        ''' Add ace to SGACL. '''
        cmd = []
        sgacl_action = sdk.la_acl_command_action()
        sgacl_action.type = sdk.la_acl_cmd_type_e_SGACL
        if self.command == command_type.PERMIT:
            sgacl_action.data.drop = False
        else:
            sgacl_action.data.drop = True

        cmd.append(sgacl_action)

        k = []
        k_all = []
        f = sdk.la_acl_field()

        f.type = sdk.la_acl_field_type_e_PROTOCOL
        f.val.protocol = sdk.la_l4_protocol_e_TCP
        f.mask.protocol = 0xff

        if is_encap:
            f.type = sdk.la_acl_field_type_e_SGACL_BINCODE
            f.val.sgacl_bincode = 0x1
            f.mask.sgacl_bincode = 0x1
        else:
            f.type = sdk.la_acl_field_type_e_SGACL_BINCODE
            f.val.sgacl_bincode = 0x2
            f.mask.sgacl_bincode = 0x2

        k.append(f)
        k_all.append(f)

        count_pre = self.sgacl.get_count()
        self.sgacl.insert(0, k, cmd)
        count_post = self.sgacl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        ''' Set SGACL on the cell. '''
        self.cell.set_acl(self.sgacl)
        if is_encap:
            self.cell.set_bincode(1)
        else:
            self.cell.set_bincode(2)

        self.topology.tx_switch.hld_obj.set_security_group_policy_enforcement(True)
        self.topology.rx_switch.hld_obj.set_security_group_policy_enforcement(True)

        ''' Enable Group Policy Encap on VXLAN Tunnel. '''
        self.vxlan_l2_port.set_group_policy_encap(True)

        ''' Enable Enforecment on the DSP. '''
        enable = True
        self.tx_svi_eth_port = self.topology.tx_svi_eth_port_def.hld_obj
        self.tx_svi_eth_port.set_security_group_policy_enforcement(enable)
        read_enable = self.tx_svi_eth_port.get_security_group_policy_enforcement()
        self.assertEqual(enable, read_enable)

        self.eth_port = self.topology.rx_eth_port.hld_obj
        self.eth_port.set_security_group_policy_enforcement(enable)
        read_enable = self.eth_port.get_security_group_policy_enforcement()
        self.assertEqual(enable, read_enable)

        self.tx_l3_eth_port = self.topology.tx_l3_ac_eth_port_def.hld_obj
        self.tx_l3_eth_port.set_security_group_policy_enforcement(enable)
        read_enable = self.tx_l3_eth_port.get_security_group_policy_enforcement()
        self.assertEqual(enable, read_enable)

        ''' Attach counter to Cell '''
        self.cell.set_counter(self.sgacl_counter)

    def set_l3_sgacl(self, monitor=False, drop=False, is_ipv4=True, is_encap=True):
        if monitor:
            self.command = command_type(command_type.MONITOR)
        elif drop:
            self.command = command_type(command_type.DROP)
        else:
            self.command = command_type(command_type.PERMIT)

        if is_ipv4:
            self.ipvx = 'v4'
            SIP = T.ipv4_addr(self.OVL_SIPv4)
            if is_encap:
                DIP = T.ipv4_addr(self.OVL_DIPv4_1)
            else:
                DIP = T.ipv4_addr(self.OVL_DIPv4)
            self.source_host_prefix = sdk.la_ipv4_prefix_t()
            self.source_host_prefix.addr.s_addr = SIP.to_num()
            self.source_host_prefix.length = 32
            self.source_subnet_prefix = sdk.la_ipv4_prefix_t()
            self.source_subnet_prefix.length = 24
            self.source_subnet_prefix.addr.s_addr = SIP.to_num() & 0xffffff00
            self.destination_host_prefix = sdk.la_ipv4_prefix_t()
            self.destination_host_prefix.addr.s_addr = DIP.to_num()
            self.destination_host_prefix.length = 32
            self.destination_subnet_prefix = sdk.la_ipv4_prefix_t()
            self.destination_subnet_prefix.length = 24
            self.destination_subnet_prefix.addr.s_addr = DIP.to_num() & 0xffffff00
            self.ip_version = sdk.la_ip_version_e_IPV4
        else:
            self.ipvx = 'v6'
            SIP = T.ipv6_addr(self.OVL_SIPv6)
            if is_encap:
                DIP = T.ipv6_addr(self.OVL_DIPv6_1)
            else:
                DIP = T.ipv6_addr(self.OVL_DIPv6)
            self.source_host_prefix = build_v6_prefix(SIP, 128)
            self.source_subnet_prefix = build_v6_prefix(SIP, 64)
            self.destination_host_prefix = build_v6_prefix(DIP, 128)
            self.destination_subnet_prefix = build_v6_prefix(DIP, 64)
            self.ip_version = sdk.la_ip_version_e_IPV6

        self.sgacl_counter = self.device.create_counter(2)

        self.device.set_sda_mode(True)
        sgt = 100
        dgt = 101

        if is_encap:
            self.topology.vrf.hld_obj.add_security_group_tag(self.source_host_prefix, sgt)
        else:
            self.topology.vrf.hld_obj.add_security_group_tag(self.source_host_prefix, 0xaa)

        self.topology.vrf.hld_obj.add_security_group_tag(self.destination_host_prefix, dgt)
        ''' Creating sgt/dgt cell and monitor mode.'''
        self.cell = self.device.create_security_group_cell(sgt, dgt, self.ip_version)

        if self.command == command_type.MONITOR:
            allow_drop = False
        else:
            allow_drop = True

        self.cell.set_monitor_mode(allow_drop)
        read_allow_drop = self.cell.get_monitor_mode()
        self.assertEqual(allow_drop, read_allow_drop)

        self.sgacl = self.device.create_acl(self.sgacl_key_profile, self.sgacl_command_profile)
        self.assertNotEqual(self.sgacl, None)
        count = self.sgacl.get_count()
        self.assertEqual(count, 0)

        ''' Add ace to SGACL. '''
        cmd = []
        sgacl_action = sdk.la_acl_command_action()
        sgacl_action.type = sdk.la_acl_cmd_type_e_SGACL
        if self.command == command_type.PERMIT:
            sgacl_action.data.drop = False
        else:
            sgacl_action.data.drop = True

        cmd.append(sgacl_action)

        k = []
        k_all = []
        f = sdk.la_acl_field()

        f.type = sdk.la_acl_field_type_e_PROTOCOL
        f.val.protocol = sdk.la_l4_protocol_e_TCP
        f.mask.protocol = 0xff

        if is_encap:
            f.type = sdk.la_acl_field_type_e_SGACL_BINCODE
            f.val.sgacl_bincode = 0x1
            f.mask.sgacl_bincode = 0x1
        else:
            f.type = sdk.la_acl_field_type_e_SGACL_BINCODE
            f.val.sgacl_bincode = 0x2
            f.mask.sgacl_bincode = 0x2

        k.append(f)
        k_all.append(f)

        count_pre = self.sgacl.get_count()
        self.sgacl.insert(0, k, cmd)
        count_post = self.sgacl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        ''' Set SGACL on the cell. '''
        self.cell.set_acl(self.sgacl)
        if is_encap:
            self.cell.set_bincode(1)
        else:
            self.cell.set_bincode(2)

        ''' Enable Group Policy Encap on VXLAN Tunnel. '''
        self.vxlan_l2_port.set_group_policy_encap(True)

        ''' Enable Enforecment on the DSP. '''
        enable = True
        if is_encap:
            self.tx_eth_port = self.topology.tx_l3_ac_eth_port_def.hld_obj
        else:
            self.tx_eth_port = self.topology.tx_l3_ac_eth_port_reg.hld_obj

        self.tx_eth_port.set_security_group_policy_enforcement(enable)
        read_enable = self.tx_eth_port.get_security_group_policy_enforcement()
        self.assertEqual(enable, read_enable)

        ''' Attach counter to Cell '''
        self.cell.set_counter(self.sgacl_counter)

    def destroy_sgacl(self):
        # Clear the acl
        self.cell.clear_acl()
        self.device.destroy(self.sgacl)
        self.cell.set_counter(None)
        self.device.destroy(self.sgacl_counter)
        self.device.destroy(self.cell)

    def verify_cell_counter(self):
        if self.command == command_type.PERMIT:
            packet_count, byte_count = self.sgacl_counter.read(0, True, True)
        else:
            packet_count, byte_count = self.sgacl_counter.read(1, True, True)

        self.assertEqual(packet_count, 1)

    def _test_vxlan_l2_encap(self, proto=sdk.la_l3_protocol_e_IPV4_UC):
        # packet comes in at tx_l2_ac_port_reg
        if decor.is_pacific():
            if proto == sdk.la_l3_protocol_e_IPV4_UC:
                vxlan_sport = 55703
            else:
                vxlan_sport = 50053
        elif decor.is_gibraltar():
            if proto == sdk.la_l3_protocol_e_IPV4_UC:
                vxlan_sport = 53668
            else:
                vxlan_sport = 48267
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
                 ttl=security_group_acl_vxlan_base.TTL) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance+G', vni=10000, reserved=0x64) / \
            self.VXLAN_L2_ENCAP_INPUT_PACKET_1

        if self.command == command_type.DROP:
            U.run_and_drop(self, self.device,
                           self.VXLAN_L2_ENCAP_INPUT_PACKET_1, T.TX_SLICE_REG,
                           T.TX_IFG_REG, T.FIRST_SERDES_SVI)
        else:
            U.run_and_compare(self, self.device,
                              self.VXLAN_L2_ENCAP_INPUT_PACKET_1, T.TX_SLICE_REG,
                              T.TX_IFG_REG, T.FIRST_SERDES_SVI,
                              VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF,
                              T.TX_IFG_DEF, T.FIRST_SERDES_L3)

        self.verify_cell_counter()

        # packet comes in at rx_l2_ac_port

        self.VXLAN_L2_ENCAP_INPUT_PACKET_2, __ = U.enlarge_packet_to_min_length(self.VXLAN_L2_ENCAP_INPUT_PACKET_2)

        if decor.is_pacific():
            if proto == sdk.la_l3_protocol_e_IPV4_UC:
                vxlan_sport = 31145
            else:
                vxlan_sport = 58662
        elif decor.is_gibraltar():
            if proto == sdk.la_l3_protocol_e_IPV4_UC:
                vxlan_sport = 27035
            else:
                vxlan_sport = 1204
        else:
            vxlan_sport = 0

        VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=security_group_acl_vxlan_base.TTL) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance+G', vni=9999, reserved=0x64) / \
            self.VXLAN_L2_ENCAP_INPUT_PACKET_2

        self.output_p_counter = self.device.create_counter(1)
        self.topology.tx_l3_ac_def.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.output_p_counter)

        if self.command == command_type.DROP:
            U.run_and_drop(self, self.device,
                           self.VXLAN_L2_ENCAP_INPUT_PACKET_2, T.RX_SLICE,
                           T.RX_IFG, T.FIRST_SERDES)
        else:
            U.run_and_compare(self, self.device,
                              self.VXLAN_L2_ENCAP_INPUT_PACKET_2, T.RX_SLICE,
                              T.RX_IFG, T.FIRST_SERDES,
                              VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF,
                              T.TX_IFG_DEF, T.FIRST_SERDES_L3)

            packets, byte_count = self.vxlan_encap_counter.read(0, True, True)
            self.assertEqual(packets, 1)

            packets, byte_count = self.tunnel_encap_counter.read(0, True, True)
            self.assertEqual(packets, 2)

            packets, byte_count = self.output_p_counter.read(0, True, True)
            self.assertEqual(packets, 1)

        self.verify_cell_counter()

        self.topology.tx_l3_ac_def.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, None)
        self.device.destroy(self.output_p_counter)

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
                 ttl=security_group_acl_vxlan_base.TTL) / \
            S.UDP(sport=6522,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance+G', vni=10000, reserved=0x64) / \
            self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET

        if self.command == command_type.DROP:
            U.run_and_drop(self, self.device,
                           VXLAN_DECAP_INPUT_PACKET, T.TX_SLICE_DEF,
                           T.TX_IFG_DEF, T.FIRST_SERDES_L3)
        else:
            U.run_and_compare(self, self.device,
                              VXLAN_DECAP_INPUT_PACKET, T.TX_SLICE_DEF,
                              T.TX_IFG_DEF, T.FIRST_SERDES_L3,
                              self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF,
                              T.TX_IFG_DEF, T.FIRST_SERDES_SVI)

        self.verify_cell_counter()

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
                 ttl=security_group_acl_vxlan_base.TTL) / \
            S.UDP(sport=6522,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance+G',
                    vni=9999,
                    reserved=0x64) / \
            self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET

        self.input_p_counter = self.device.create_counter(1)
        self.topology.tx_l3_ac_def.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.input_p_counter)

        if self.command == command_type.DROP:
            U.run_and_drop(self, self.device,
                           VXLAN_DECAP_INPUT_PACKET, T.TX_SLICE_DEF,
                           T.TX_IFG_DEF, T.FIRST_SERDES_L3)
        else:
            U.run_and_compare(self, self.device,
                              VXLAN_DECAP_INPUT_PACKET, T.TX_SLICE_DEF,
                              T.TX_IFG_DEF, T.FIRST_SERDES_L3,
                              self.VXLAN_L2_DECAP_EXPECTED_OUTPUT_PACKET,
                              T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

            packets, byte_count = self.tunnel_decap_counter.read(0, True, True)
            self.assertEqual(packets, 2)

        self.verify_cell_counter()

        self.topology.tx_l3_ac_def.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, None)
        self.device.destroy(self.input_p_counter)

    def _test_vxlan_l3_encap(self):
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, True)
        # packet comes in at tx_l3_ac_reg and goes out at tx_l3_ac_def
        self.L3VXLAN_IP_PACKET.getlayer(0).dst = self.OVL_DIPv4_1
        if self.underlay_ip_impl.BYTES_NUM_IN_ADDR == self.IPv6_ADDRESS_SIZE:
            self.L3VXLAN_IP_PACKET.getlayer(0).hlim = security_group_acl_vxlan_base.TTL
        else:
            self.L3VXLAN_IP_PACKET.getlayer(0).ttl = security_group_acl_vxlan_base.TTL

        self.L3VXLAN_IP_PACKET, __ = U.enlarge_packet_to_min_length(self.L3VXLAN_IP_PACKET, 68)
        self.vxlan_l2_port.set_ttl_inheritance_mode(sdk.la_ttl_inheritance_mode_e_PIPE)
        self.vxlan_l2_port.set_ttl(128 + 1)

        L3VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_REG_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        if self.underlay_ip_impl.BYTES_NUM_IN_ADDR == self.IPv6_ADDRESS_SIZE:
            self.L3VXLAN_IP_PACKET.getlayer(0).hlim = 254
        else:
            self.L3VXLAN_IP_PACKET.getlayer(0).ttl = 254

        if decor.is_pacific():
            vxlan_sport = 32428
        elif decor.is_gibraltar():
            vxlan_sport = 4726
        else:
            vxlan_sport = 0

        # 1st Packet

        L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=128) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance+G', vni=10001, reserved=0x64) / \
            S.Ether(dst=vxlan_l2_single_port.DUMMY_SVI_NH_MAC.addr_str,
                    src=vxlan_l2_single_port.DUMMY_SVI_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        U.run_and_compare(self, self.device,
                          L3VXLAN_ENCAP_INPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3,
                          L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3)

        # 2nd Packet

        self.L3VXLAN_IP_PACKET.getlayer(0).dst = self.OVL_DIP
        self.vxlan_l2_port.set_ttl(security_group_acl_vxlan_base.TTL)

        if self.underlay_ip_impl.BYTES_NUM_IN_ADDR == self.IPv6_ADDRESS_SIZE:
            self.L3VXLAN_IP_PACKET.getlayer(0).hlim = security_group_acl_vxlan_base.TTL
        else:
            self.L3VXLAN_IP_PACKET.getlayer(0).ttl = security_group_acl_vxlan_base.TTL

        L3VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_REG_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        if self.underlay_ip_impl.BYTES_NUM_IN_ADDR == self.IPv6_ADDRESS_SIZE:
            self.L3VXLAN_IP_PACKET.getlayer(0).hlim = 254
        else:
            self.L3VXLAN_IP_PACKET.getlayer(0).ttl = 254

        if decor.is_pacific():
            vxlan_sport = 35802
        elif decor.is_gibraltar():
            vxlan_sport = 25153
        else:
            vxlan_sport = 0

        L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=253) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance+G', vni=10001, reserved=0x64) / \
            S.Ether(dst=vxlan_l2_single_port.DUMMY_SVI_NH_MAC.addr_str,
                    src=vxlan_l2_single_port.DUMMY_SVI_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        self.output_p_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.topology.tx_l3_ac_def.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.output_p_counter)

        self.vxlan_l2_port.set_ttl_inheritance_mode(sdk.la_ttl_inheritance_mode_e_UNIFORM)

        U.run_and_compare(self, self.device,
                          L3VXLAN_ENCAP_INPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3,
                          L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3)

        packets, byte_count = self.vxlan_l3_encap_counter.read(0, True, True)
        self.assertEqual(packets, 2)

        packets, byte_count = self.tunnel_encap_counter.read(0, True, True)
        self.assertEqual(packets, 2)

        packets, byte_count = self.output_p_counter.read(0, True, True)
        self.assertEqual(packets, 1)

        self.topology.tx_l3_ac_def.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, None)
        self.device.destroy(self.output_p_counter)

    def _test_vxlan_sda_encap(self):
        # packet comes in at tx_l3_ac_reg and goes out at tx_l3_ac_def
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, True)

        if self.underlay_ip_impl.BYTES_NUM_IN_ADDR == self.IPv6_ADDRESS_SIZE:
            self.L3VXLAN_IP_PACKET.getlayer(0).hlim = security_group_acl_vxlan_base.TTL
        else:
            self.L3VXLAN_IP_PACKET.getlayer(0).ttl = security_group_acl_vxlan_base.TTL

        self.L3VXLAN_IP_PACKET, __ = U.enlarge_packet_to_min_length(self.L3VXLAN_IP_PACKET, 68)

        L3VXLAN_ENCAP_INPUT_PACKET = \
            S.Ether(src=vxlan_l2_single_port.OUTER_SRC_MAC,
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_REG_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        if self.underlay_ip_impl.BYTES_NUM_IN_ADDR == self.IPv6_ADDRESS_SIZE:
            self.L3VXLAN_IP_PACKET.getlayer(0).hlim = 254
            vxlan_sport = 2203
        else:
            self.L3VXLAN_IP_PACKET.getlayer(0).ttl = 254
            vxlan_sport = 4726

        L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=security_group_acl_vxlan_base.TTL) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance', vni=10001) / \
            S.Ether(dst=vxlan_l2_single_port.SDA_MAC.addr_str,
                    src=vxlan_l2_single_port.DUMMY_SVI_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        L3VXLAN_G_ENCAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 dst=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=security_group_acl_vxlan_base.TTL) / \
            S.UDP(sport=vxlan_sport,
                  dport=4789,
                  chksum=0) / \
            P.VXLAN(flags='Instance+G', vni=10001, reserved=0x64) / \
            S.Ether(dst=vxlan_l2_single_port.SDA_MAC.addr_str,
                    src=vxlan_l2_single_port.DUMMY_SVI_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        group_policy_enabled = self.vxlan_l2_port.get_group_policy_encap()

        if group_policy_enabled:
            L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET = L3VXLAN_G_ENCAP_EXPECTED_OUTPUT_PACKET

        if self.command == command_type.DROP:
            U.run_and_drop(self, self.device,
                           L3VXLAN_ENCAP_INPUT_PACKET, T.TX_SLICE_REG,
                           T.TX_IFG_REG, T.FIRST_SERDES_L3)
        else:
            U.run_and_compare(self, self.device,
                              L3VXLAN_ENCAP_INPUT_PACKET, T.TX_SLICE_REG,
                              T.TX_IFG_REG, T.FIRST_SERDES_L3,
                              L3VXLAN_ENCAP_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF,
                              T.TX_IFG_DEF, T.FIRST_SERDES_L3)

        if group_policy_enabled:
            self.verify_cell_counter()

    def _test_vxlan_sda_decap(self):
        # packet comes in at tx_l3_ac_ext and goes out at tx_l3_ac_reg
        self.L3VXLAN_IP_PACKET, __ = U.enlarge_packet_to_min_length(self.L3VXLAN_IP_PACKET, 68)

        L3VXLAN_DECAP_INPUT_PACKET = \
            S.Ether(src='00:11:22:33:44:55',
                    dst=vxlan_l2_single_port.NEW_TX_L3_AC_EXT_MAC.addr_str) / \
            S.IP(dst=vxlan_l2_single_port.VXLAN_SIP.addr_str,
                 src=vxlan_l2_single_port.VXLAN_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=security_group_acl_vxlan_base.TTL) / \
            S.UDP(dport=4789) / \
            P.VXLAN(flags='Instance+G', vni=10001, reserved=0x64) / \
            S.Ether(src=vxlan_l2_single_port.DUMMY_SVI_NH_MAC.addr_str,
                    dst=vxlan_l2_single_port.SDA_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        if self.underlay_ip_impl.BYTES_NUM_IN_ADDR == self.IPv6_ADDRESS_SIZE:
            self.L3VXLAN_IP_PACKET.getlayer(0).hlim = 254
        else:
            self.L3VXLAN_IP_PACKET.getlayer(0).ttl = 254

        L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=vxlan_l2_single_port.NEW_TX_L3_AC_REG_MAC.addr_str) / \
            self.L3VXLAN_IP_PACKET

        if self.command == command_type.DROP:
            U.run_and_drop(self, self.device,
                           L3VXLAN_DECAP_INPUT_PACKET, T.TX_SLICE_EXT,
                           T.TX_IFG_EXT, T.FIRST_SERDES_L3)
        else:
            U.run_and_compare(self, self.device,
                              L3VXLAN_DECAP_INPUT_PACKET, T.TX_SLICE_EXT,
                              T.TX_IFG_EXT, T.FIRST_SERDES_L3,
                              L3VXLAN_DECAP_EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                              T.TX_IFG_REG, T.FIRST_SERDES_L3)

        self.verify_cell_counter()

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
