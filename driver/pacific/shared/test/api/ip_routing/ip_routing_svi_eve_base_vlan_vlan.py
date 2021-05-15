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

from packet_test_utils import *
from scapy.all import *
from leaba import sdk
from ip_routing_base import *
import unittest
import sim_utils
import topology as T
import scapy.all as S
import packet_test_utils as U
import ip_test_base


class ip_routing_svi_eve_base_vlan_vlan(ip_routing_base):
    l3_port_impl_class = T.ip_svi_base

    FIRST_SERDES_SPA = 6
    LAST_SERDES_SPA = 7
    SVI_VLAN_1 = 20
    SVI_VLAN_2 = 21
    SVI1_VLAN_1 = 30
    SVI1_VLAN_2 = 31
    SVI2_VLAN_1 = 40
    SVI2_VLAN_2 = 41
    RX_SWITCH_ACCESS_PORT_ID = 4097
    RX_SWITCH1_ACCESS_PORT_ID = 4098
    RX_SWITCH_TRUNK_PORT_ID = 2000
    RX_SWITCH1_TRUNK_PORT_ID = 5000
    RX_SWITCH2_TRUNK_PORT_ID = 5001
    RX_SVI_MAC2 = T.mac_addr('10:17:18:19:1a:1c')
    SVI_HOST_MAC = T.mac_addr('00:11:22:33:44:02')
    SVI_SUBNET_LENGTH = 24
    SVI1_HOST_MAC = T.mac_addr('00:11:22:33:44:03')
    SVI1_SUBNET_LENGTH = 24
    SVI_TRUNK_HOST_MAC = T.mac_addr('00:11:22:33:44:05')
    SVI1_TRUNK_HOST_MAC = T.mac_addr('00:11:22:33:44:04')
    SVI2_TRUNK_HOST_MAC = T.mac_addr('00:11:22:33:44:06')
    RX_SWITCH_ACCESS_SPA_PORT_ID = 2004
    RX_SWITCH1_ACCESS_SPA_PORT_ID = 2005
    RX_SWITCH_TRUNK_SPA_PORT_ID = 2006
    RX_SWITCH1_TRUNK_SPA_PORT_ID = 2007
    SERDES8 = 8
    SERDES9 = 9
    SERDES10 = 10
    SERDES11 = 11
    SERDES12 = 12
    SERDES13 = 13
    NH_MAC = SVI1_HOST_MAC
    NH_GID = 0x300
    NH1_MAC = SVI_HOST_MAC
    NH1_GID = 0x301
    NH2_MAC = SVI2_TRUNK_HOST_MAC
    NH2_GID = 0x302
    PRIVATE_DATA = 0x1234567890abcdef

    def set_svi_tag(self, svi_port, vlan1, vlan2):
        tag1 = sdk.la_vlan_tag_t()
        tag2 = sdk.la_vlan_tag_t()
        tag1.tpid = 0x88a8
        tag1.tci.fields.pcp = 0
        tag1.tci.fields.dei = 0
        tag1.tci.fields.vid = vlan1
        tag2.tpid = 0x8100
        tag2.tci.fields.pcp = 0
        tag2.tci.fields.dei = 0
        tag2.tci.fields.vid = vlan2

        svi_port.hld_obj.set_egress_vlan_tag(tag1, tag2)

        tag1.tci.fields.vid = 0
        tag2.tci.fields.vid = 0
        (tag1, tag2) = svi_port.hld_obj.get_egress_vlan_tag()
        self.assertEqual(vlan1, tag1.tci.fields.vid)
        self.assertEqual(vlan2, tag2.tci.fields.vid)

    def set_svi_subnet(self, svi_port, ip_addr, length):
        subnet = self.ip_impl.build_prefix(ip_addr, length)
        self.ip_impl.add_subnet(svi_port, subnet)

    def setup_ip_routing_svi_eve(self):
        # 1. provision rx_svi to be double vlan
        #self.set_svi_tag(self.topology.rx_svi, self.SVI_VLAN_1, self.SVI_VLAN_2)
        self.set_svi_subnet(self.topology.rx_svi, self.SVI_HOST_IP_ADDR, self.SVI_SUBNET_LENGTH)
        self.rx_svi_ec = self.device.create_counter(1)
        self.topology.rx_svi.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.rx_svi_ec)

        # 2. provision rx_svi1 to be double vlan
        #self.set_svi_tag(self.topology.rx_svi1, self.SVI1_VLAN_1, self.SVI1_VLAN_2)
        self.set_svi_subnet(self.topology.rx_svi1, self.SVI1_HOST_IP_ADDR, self.SVI1_SUBNET_LENGTH)
        self.rx_svi1_ec = self.device.create_counter(1)
        self.topology.rx_svi1.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.rx_svi1_ec)

        self.create_non_native_vlan()

        # 3. create l2 service port on the rx_switch
        self.rx_switch_access_port = T.l2_ac_port(self, self.device,
                                                  self.RX_SWITCH_ACCESS_PORT_ID,
                                                  None,
                                                  self.topology.rx_switch,
                                                  self.topology.rx_eth_port,
                                                  T.RX_MAC,
                                                  egress_feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)

        # create ingress and egress counters for rx_switch_access_port
        self.inc1 = self.device.create_counter(1)
        self.l2_ec1 = self.device.create_counter(1)
        self.rx_switch_access_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.inc1)
        self.rx_switch_access_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l2_ec1)

        # set mac forwarding entry
        self.topology.rx_switch.hld_obj.set_mac_entry(
            self.SVI_HOST_MAC.hld_obj,
            self.rx_switch_access_port.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        # set tagging mode as strip (no tag when packet is sent out on this port)
        self.topology.rx_eth_port.hld_obj.set_svi_egress_tag_mode(sdk.la_ethernet_port.svi_egress_tag_mode_e_STRIP)
        svi_tag_mode = self.topology.rx_eth_port.hld_obj.get_svi_egress_tag_mode()
        self.assertEqual(sdk.la_ethernet_port.svi_egress_tag_mode_e_STRIP, svi_tag_mode)

        # 4. create l2 service port on the rx_switch1
        self.rx_switch1_access_port = T.l2_ac_port(self, self.device,
                                                   self.RX_SWITCH1_ACCESS_PORT_ID,
                                                   None,
                                                   self.topology.rx_switch1,
                                                   self.topology.rx_eth_port1,
                                                   T.RX_MAC,
                                                   egress_feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)

        # create ingress and egress counter for rx_switch1_access_port
        self.inc2 = self.device.create_counter(1)
        self.l2_ec2 = self.device.create_counter(1)
        self.rx_switch1_access_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.inc2)
        self.rx_switch1_access_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l2_ec2)

        # set mac forwarding entry
        self.topology.rx_switch1.hld_obj.set_mac_entry(
            self.SVI1_HOST_MAC.hld_obj,
            self.rx_switch1_access_port.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        # set tagging mode as strip
        self.topology.rx_eth_port1.hld_obj.set_svi_egress_tag_mode(sdk.la_ethernet_port.svi_egress_tag_mode_e_STRIP)
        svi_tag_mode = self.topology.rx_eth_port1.hld_obj.get_svi_egress_tag_mode()
        self.assertEqual(sdk.la_ethernet_port.svi_egress_tag_mode_e_STRIP, svi_tag_mode)

        # 5. provision the trunk port on rx switch
        self.rx_switch_trunk_port = T.l2_ac_port(self, self.device,
                                                 self.RX_SWITCH_TRUNK_PORT_ID,
                                                 None,
                                                 self.topology.rx_switch,
                                                 self.topology.tx_svi_eth_port_def,
                                                 T.RX_MAC,
                                                 self.SVI_VLAN_1,
                                                 self.SVI_VLAN_2)
        self.rx_switch_trunk_port.hld_obj.set_egress_feature_mode(sdk.la_l2_service_port.egress_feature_mode_e_L2)

        self.inc3 = self.device.create_counter(1)
        self.l2_ec3 = self.device.create_counter(1)
        self.rx_switch_trunk_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.inc3)
        self.rx_switch_trunk_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l2_ec3)

        # set mac forwarding entry
        self.topology.rx_switch.hld_obj.set_mac_entry(
            self.SVI_TRUNK_HOST_MAC.hld_obj,
            self.rx_switch_trunk_port.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        # set eve for rx_switch_trunk_port
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 2
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.SVLAN.value
        eve.tag0.tci.fields.vid = self.SVI_VLAN_1
        eve.tag1.tpid = Ethertype.Dot1Q.value
        eve.tag1.tci.fields.vid = self.SVI_VLAN_2
        self.rx_switch_trunk_port.hld_obj.set_egress_vlan_edit_command(eve)

        # set tagging mode for trunk as keep
        self.topology.tx_svi_eth_port_def.hld_obj.set_svi_egress_tag_mode(sdk.la_ethernet_port.svi_egress_tag_mode_e_KEEP)
        svi_tag_mode = self.topology.tx_svi_eth_port_def.hld_obj.get_svi_egress_tag_mode()
        self.assertEqual(sdk.la_ethernet_port.svi_egress_tag_mode_e_KEEP, svi_tag_mode)

        # 6. provision the trunk port on rx switch1
        self.rx_switch1_trunk_port = T.l2_ac_port(self, self.device,
                                                  self.RX_SWITCH1_TRUNK_PORT_ID,
                                                  None,
                                                  self.topology.rx_switch1,
                                                  self.topology.tx_svi_eth_port_reg,
                                                  T.RX_MAC,
                                                  self.SVI1_VLAN_1,
                                                  self.SVI1_VLAN_2)
        self.rx_switch1_trunk_port.hld_obj.set_egress_feature_mode(sdk.la_l2_service_port.egress_feature_mode_e_L2)

        # create ingress and egress counters for rx_switch1_trunk_port
        self.inc4 = self.device.create_counter(1)
        self.l2_ec4 = self.device.create_counter(1)
        self.rx_switch1_trunk_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.inc4)
        self.rx_switch1_trunk_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l2_ec4)

        # set mac forwarding entry
        self.topology.rx_switch1.hld_obj.set_mac_entry(
            self.SVI1_TRUNK_HOST_MAC.hld_obj,
            self.rx_switch1_trunk_port.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        # set eve for rx_switch1_trunk_port
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 2
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.SVLAN.value
        eve.tag0.tci.fields.vid = self.SVI1_VLAN_1
        eve.tag1.tpid = Ethertype.Dot1Q.value
        eve.tag1.tci.fields.vid = self.SVI1_VLAN_2

        self.rx_switch1_trunk_port.hld_obj.set_egress_vlan_edit_command(eve)

        # set tagging moode for trunk as keep
        self.topology.tx_svi_eth_port_reg.hld_obj.set_svi_egress_tag_mode(sdk.la_ethernet_port.svi_egress_tag_mode_e_KEEP)
        svi_tag_mode = self.topology.tx_svi_eth_port_reg.hld_obj.get_svi_egress_tag_mode()
        self.assertEqual(sdk.la_ethernet_port.svi_egress_tag_mode_e_KEEP, svi_tag_mode)

    def setup_ip_routing_svi_eve_spa(self):
        # provision rx_svi
        self.set_svi_tag(self.topology.rx_svi, self.SVI_VLAN_1, self.SVI_VLAN_2)
        self.set_svi_subnet(self.topology.rx_svi, self.SVI_HOST_IP_ADDR, self.SVI_SUBNET_LENGTH)
        self.rx_svi_ec = self.device.create_counter(1)
        self.topology.rx_svi.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.rx_svi_ec)

        # provision rx_svi1
        #self.set_svi_tag(self.topology.rx_svi1, self.SVI1_VLAN)
        self.set_svi_subnet(self.topology.rx_svi1, self.SVI1_HOST_IP_ADDR, self.SVI1_SUBNET_LENGTH)
        self.rx_svi1_ec = self.device.create_counter(1)
        self.topology.rx_svi1.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.rx_svi1_ec)

        self.create_non_native_vlan()

        # 1. create access spa port in rx_switch
        self.spa_mac_port1 = T.mac_port(self, self.device, T.TX_SLICE_REG, T.TX_IFG_REG,
                                        self.FIRST_SERDES_SPA, self.LAST_SERDES_SPA, None)
        self.spa_mac_port1.activate()
        self.spa_sys_port1 = T.system_port(self, self.device, 0x100, self.spa_mac_port1)

        self.spa_mac_port11 = T.mac_port(self, self.device, T.TX_SLICE_DEF, T.TX_IFG_DEF,
                                         self.FIRST_SERDES_SPA, self.LAST_SERDES_SPA, None)
        self.spa_mac_port11.activate()
        self.spa_sys_port11 = T.system_port(self, self.device, 0x110, self.spa_mac_port11)

        # create spa port
        self.svi_spa_port1 = T.spa_port(self, self.device, 0x100)

        # add member
        self.svi_spa_port1.add(self.spa_sys_port1)
        self.svi_spa_port1.hld_obj.set_member_transmit_enabled(self.spa_sys_port1.hld_obj, True)
        # self.svi_spa_port1.add(self.spa_sys_port11)
        #self.svi_spa_port1.hld_obj.set_member_transmit_enabled(self.spa_sys_port11.hld_obj, True)

        # create ethernet port
        self.svi_spa_ethernet_port1 = T.sa_ethernet_port(self, self.device, self.svi_spa_port1, None)

        # create L2 AC access port
        self.rx_switch_access_spa_port = T.l2_ac_port(self, self.device,
                                                      self.RX_SWITCH_ACCESS_SPA_PORT_ID,
                                                      None,
                                                      self.topology.rx_switch,
                                                      self.svi_spa_ethernet_port1,
                                                      T.RX_MAC)

        # set mac forwarding entry
        self.topology.rx_switch.hld_obj.set_mac_entry(
            self.SVI_HOST_MAC.hld_obj,
            self.rx_switch_access_spa_port.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        # create ingress and egress counters for rx_switch_access_spa_port
        self.inc1 = self.device.create_counter(1)
        self.ec1 = self.device.create_counter(1)
        self.rx_switch_access_spa_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.inc1)
        self.rx_switch_access_spa_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.ec1)

        # 2. create trunk spa port in rx_switch
        self.spa_mac_port2 = T.mac_port(self, self.device, T.TX_SLICE_REG, T.TX_IFG_REG,
                                        self.SERDES8, self.SERDES9, None)
        self.spa_mac_port2.activate()
        self.spa_sys_port2 = T.system_port(self, self.device, 0x101, self.spa_mac_port2)

        self.spa_mac_port21 = T.mac_port(self, self.device, T.TX_SLICE_DEF, T.TX_IFG_DEF,
                                         self.SERDES8, self.SERDES9, None)
        self.spa_mac_port21.activate()
        self.spa_sys_port21 = T.system_port(self, self.device, 0x111, self.spa_mac_port21)

        # create spa port
        self.svi_spa_port2 = T.spa_port(self, self.device, 0x334)

        # add member
        self.svi_spa_port2.add(self.spa_sys_port2)
        self.svi_spa_port2.hld_obj.set_member_transmit_enabled(self.spa_sys_port2.hld_obj, True)
        self.svi_spa_port2.add(self.spa_sys_port21)
        self.svi_spa_port2.hld_obj.set_member_transmit_enabled(self.spa_sys_port21.hld_obj, True)

        # create ethernet port
        self.svi_spa_ethernet_port2 = T.sa_ethernet_port(self, self.device, self.svi_spa_port2, None)

        # create L2 AC port
        self.rx_switch_trunk_spa_port = T.l2_ac_port(self, self.device,
                                                     self.RX_SWITCH_TRUNK_SPA_PORT_ID,
                                                     None,
                                                     self.topology.rx_switch,
                                                     self.svi_spa_ethernet_port2,
                                                     T.RX_MAC,
                                                     self.SVI_VLAN_1)

        # set eve for rx_switch_trunk_port
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = self.SVI_VLAN_1
        self.rx_switch_trunk_spa_port.hld_obj.set_egress_vlan_edit_command(eve)

        # set mac forwarding entry
        self.topology.rx_switch.hld_obj.set_mac_entry(
            self.SVI_TRUNK_HOST_MAC.hld_obj,
            self.rx_switch_trunk_spa_port.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        # create ingress and egress counter for rx_switch_trunk_spa_port
        self.inc2 = self.device.create_counter(1)
        self.ec2 = self.device.create_counter(1)
        self.rx_switch_trunk_spa_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.inc2)
        self.rx_switch_trunk_spa_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.ec2)

        # 3. create access spa port in rx_switch1
        self.spa_mac_port3 = T.mac_port(self, self.device, T.TX_SLICE_DEF, T.TX_IFG_DEF,
                                        self.SERDES10, self.SERDES11, None)
        self.spa_mac_port3.activate()
        self.spa_sys_port3 = T.system_port(self, self.device, 0x102, self.spa_mac_port3)

        self.spa_mac_port31 = T.mac_port(self, self.device, T.TX_SLICE_REG, T.TX_IFG_REG,
                                         self.SERDES10, self.SERDES11, None)
        self.spa_mac_port31.activate()
        self.spa_sys_port31 = T.system_port(self, self.device, 0x112, self.spa_mac_port31)

        # create spa port
        self.svi_spa_port3 = T.spa_port(self, self.device, 0x335)

        # add member
        self.svi_spa_port3.add(self.spa_sys_port3)
        self.svi_spa_port3.hld_obj.set_member_transmit_enabled(self.spa_sys_port3.hld_obj, True)
        self.svi_spa_port3.add(self.spa_sys_port31)
        self.svi_spa_port3.hld_obj.set_member_transmit_enabled(self.spa_sys_port31.hld_obj, True)

        # create ethernet port
        self.svi_spa_ethernet_port3 = T.sa_ethernet_port(self, self.device, self.svi_spa_port3, None)

        # create L2 AC access port
        self.rx_switch1_access_spa_port = T.l2_ac_port(self, self.device,
                                                       self.RX_SWITCH1_ACCESS_SPA_PORT_ID,
                                                       None,
                                                       self.topology.rx_switch1,
                                                       self.svi_spa_ethernet_port3,
                                                       T.RX_MAC)

        # set mac forwarding entry
        self.topology.rx_switch1.hld_obj.set_mac_entry(
            self.SVI1_HOST_MAC.hld_obj,
            self.rx_switch1_access_spa_port.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        # create ingress and egress counters for rx_switch1_access_spa_port
        self.inc3 = self.device.create_counter(1)
        self.ec3 = self.device.create_counter(1)
        self.rx_switch1_access_spa_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.inc3)
        self.rx_switch1_access_spa_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.ec3)

        # 4. create trunk spa port in rx_switch1
        self.spa_mac_port4 = T.mac_port(self, self.device, T.TX_SLICE_DEF, T.TX_IFG_DEF,
                                        self.SERDES12, self.SERDES13, None)
        self.spa_mac_port4.activate()
        self.spa_sys_port4 = T.system_port(self, self.device, 0x103, self.spa_mac_port4)

        self.spa_mac_port41 = T.mac_port(self, self.device, T.TX_SLICE_DEF, T.TX_IFG_DEF, 14, 15, None)
        self.spa_mac_port41.activate()
        self.spa_sys_port41 = T.system_port(self, self.device, 0x113, self.spa_mac_port41)

        # create spa port
        self.svi_spa_port4 = T.spa_port(self, self.device, 0x336)

        # add member
        self.svi_spa_port4.add(self.spa_sys_port4)
        self.svi_spa_port4.hld_obj.set_member_transmit_enabled(self.spa_sys_port4.hld_obj, True)
        self.svi_spa_port4.add(self.spa_sys_port41)
        self.svi_spa_port4.hld_obj.set_member_transmit_enabled(self.spa_sys_port41.hld_obj, True)

        # create ethernet port
        self.svi_spa_ethernet_port4 = T.sa_ethernet_port(self, self.device, self.svi_spa_port4, None)

        # create L2 AC port
        self.rx_switch1_trunk_spa_port = T.l2_ac_port(self, self.device,
                                                      self.RX_SWITCH1_TRUNK_SPA_PORT_ID,
                                                      None,
                                                      self.topology.rx_switch1,
                                                      self.svi_spa_ethernet_port4,
                                                      T.RX_MAC,
                                                      self.SVI1_VLAN_1)

        # set eve for rx_switch1_trunk_port
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = self.SVI1_VLAN_1
        self.rx_switch1_trunk_spa_port.hld_obj.set_egress_vlan_edit_command(eve)

        # set mac forwarding entry
        self.topology.rx_switch1.hld_obj.set_mac_entry(
            self.SVI1_TRUNK_HOST_MAC.hld_obj,
            self.rx_switch1_trunk_spa_port.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        # create ingress and egress counter for rx_switch_trunk_spa_port
        self.inc4 = self.device.create_counter(1)
        self.ec4 = self.device.create_counter(1)
        self.rx_switch1_trunk_spa_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.inc4)
        self.rx_switch1_trunk_spa_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.ec4)

    def create_non_native_vlan(self):
        self.rx_switch2 = T.switch(self, self.device, 0xa01)
        self.rx_svi2 = T.svi_port(self, self.device, 0x713, self.rx_switch2, self.topology.vrf, self.RX_SVI_MAC2)
        self.rx_svi2.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.rx_svi2.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        #self.set_svi_tag(self.rx_svi2, self.SVI2_VLAN_1, self.SVI2_VLAN_2)
        self.set_svi_subnet(self.rx_svi2, self.SVI2_TRUNK_HOST_IP_ADDR, self.SVI1_SUBNET_LENGTH)
        self.rx_svi2_ec = self.device.create_counter(1)
        self.rx_svi2.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.rx_svi2_ec)
        self.create_non_native_l2_ac_port()

    def create_non_native_l2_ac_port(self):
        # create non native l2_dlp for the same trunk port
        self.rx_switch2_trunk_port = T.l2_ac_port(self, self.device,
                                                  self.RX_SWITCH2_TRUNK_PORT_ID,
                                                  None,
                                                  self.rx_switch2,
                                                  self.topology.tx_svi_eth_port_def,
                                                  T.RX_MAC,
                                                  self.SVI2_VLAN_1,
                                                  self.SVI2_VLAN_2,
                                                  egress_feature_mode = sdk.la_l2_service_port.egress_feature_mode_e_L3)

        # set mac forwarding entry
        self.rx_switch2.hld_obj.set_mac_entry(
            self.SVI2_TRUNK_HOST_MAC.hld_obj,
            self.rx_switch2_trunk_port.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        # set eve for rx_switch2_trunk_port
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 2
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.SVLAN.value
        eve.tag0.tci.fields.vid = self.SVI2_VLAN_1
        eve.tag1.tpid = Ethertype.Dot1Q.value
        eve.tag1.tci.fields.vid = self.SVI2_VLAN_2
        self.rx_switch2_trunk_port.hld_obj.set_egress_vlan_edit_command(eve)

    def add_hosts(self):
        self.ip_impl.add_host(self.topology.rx_svi, self.SVI_HOST_IP_ADDR, self.SVI_HOST_MAC)
        self.ip_impl.add_host(self.topology.rx_svi1, self.SVI1_HOST_IP_ADDR, self.SVI1_HOST_MAC)
        self.ip_impl.add_host(self.topology.rx_svi, self.SVI_TRUNK_HOST_IP_ADDR, self.SVI_TRUNK_HOST_MAC)
        self.ip_impl.add_host(self.topology.rx_svi1, self.SVI1_TRUNK_HOST_IP_ADDR, self.SVI1_TRUNK_HOST_MAC)
        self.ip_impl.add_host(self.rx_svi2, self.SVI2_TRUNK_HOST_IP_ADDR, self.SVI2_TRUNK_HOST_MAC)

    def delete_svi_subnet(self, svi_port, ip_addr, length):
        subnet = self.ip_impl.build_prefix(ip_addr, length)
        self.ip_impl.delete_subnet(svi_port, subnet)

    def delete_hosts(self):
        self.ip_impl.delete_host(self.topology.rx_svi, self.SVI_HOST_IP_ADDR)
        self.ip_impl.delete_host(self.topology.rx_svi, self.SVI_TRUNK_HOST_IP_ADDR)
        self.ip_impl.delete_host(self.topology.rx_svi1, self.SVI1_HOST_IP_ADDR)
        self.ip_impl.delete_host(self.topology.rx_svi1, self.SVI1_TRUNK_HOST_IP_ADDR)
        self.ip_impl.delete_host(self.rx_svi2, self.SVI2_TRUNK_HOST_IP_ADDR)

    def delete_svi_subnets(self):
        self.delete_svi_subnet(self.topology.rx_svi, self.SVI_HOST_IP_ADDR, self.SVI_SUBNET_LENGTH)
        self.delete_svi_subnet(self.topology.rx_svi1, self.SVI1_HOST_IP_ADDR, self.SVI1_SUBNET_LENGTH)
        self.delete_svi_subnet(self.rx_svi2, self.SVI2_TRUNK_HOST_IP_ADDR, self.SVI1_SUBNET_LENGTH)

    def create_next_hop(self):
        self.delete_svi_subnets()
        self.next_hop = T.next_hop(self, self.device, self.NH_GID, self.NH_MAC, self.topology.rx_svi1)
        self.subnet = self.ip_impl.build_prefix(self.SVI1_HOST_IP_ADDR, length=16)
        self.ip_impl.add_route(self.topology.vrf, self.subnet, self.next_hop, self.PRIVATE_DATA)

    def move_nh_mac_from_access_to_trunk(self, access_port, trunk_port):
        self.topology.rx_switch1.hld_obj.set_mac_entry(
            self.SVI1_HOST_MAC.hld_obj,
            trunk_port,
            # self.rx_switch1_trunk_spa_port.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        # update eve for rx_switch1_trunk_port
        # eve in l2 port should be honored on outgoing packet (not the eve of svi)
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 2
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.SVLAN.value
        eve.tag0.tci.fields.vid = self.SVI1_VLAN_1
        eve.tag1.tpid = Ethertype.Dot1Q.value
        eve.tag1.tci.fields.vid = self.SVI1_VLAN_2

    def create_next_hop1(self):
        self.delete_svi_subnets()
        self.next_hop1 = T.next_hop(self, self.device, self.NH1_GID, self.NH1_MAC, self.topology.rx_svi)
        self.subnet = self.ip_impl.build_prefix(self.SVI_HOST_IP_ADDR, length=16)
        self.ip_impl.add_route(self.topology.vrf, self.subnet, self.next_hop1, self.PRIVATE_DATA)

    def move_nh1_mac_from_access_to_trunk(self, access_port, trunk_port):
        self.topology.rx_switch.hld_obj.set_mac_entry(
            self.SVI_HOST_MAC.hld_obj,
            trunk_port,
            sdk.LA_MAC_AGING_TIME_NEVER)

    def create_next_hop2(self):
        self.delete_svi_subnets()
        self.next_hop2 = T.next_hop(self, self.device, self.NH2_GID, self.NH2_MAC, self.rx_svi2)
        self.subnet = self.ip_impl.build_prefix(self.SVI2_TRUNK_HOST_IP_ADDR, length=16)
        self.ip_impl.add_route(self.topology.vrf, self.subnet, self.next_hop2, self.PRIVATE_DATA)

    def add_delayed_member_for_trunk_spa(self):
        self.spa_mac_port22 = T.mac_port(self, self.device, T.RX_SLICE, T.TX_IFG_DEF, 8, 9, None)
        self.spa_mac_port22.activate()
        self.spa_sys_port22 = T.system_port(self, self.device, 0x114, self.spa_mac_port22)
        self.svi_spa_port2.add(self.spa_sys_port22)
        self.svi_spa_port2.hld_obj.set_member_transmit_enabled(self.spa_sys_port22.hld_obj, True)
        self.svi_spa_port2.remove(self.spa_sys_port2)
        self.svi_spa_port2.remove(self.spa_sys_port21)

    def run_and_compare_spa(
            self,
            spa_port,
            input_packet,
            input_slice,
            input_ifg,
            input_serdes,
            out_packet,
            num_tags):

        lb_vec = sdk.la_lb_vector_t()

        dip = T.ipv4_addr(input_packet[S.IP].dst)
        sip = T.ipv4_addr(input_packet[S.IP].src)
        lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
        lb_vec.ipv4.sip = sip.hld_obj.s_addr
        lb_vec.ipv4.dip = dip.hld_obj.s_addr
        lb_vec.ipv4.protocol = input_packet[S.IP].proto
        lb_vec.ipv4.src_port = input_packet[S.TCP].sport
        lb_vec.ipv4.dest_port = input_packet[S.TCP].dport

        lb_vec_entry_list = []
        lb_vec_entry_list.append(lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(spa_port.hld_obj, lb_vec_entry_list)

        # For Debug
        #display_forwarding_load_balance_chain(spa_port.hld_obj, out_dest_chain)

        self.assertEqual(out_dest_chain[-1].type(), sdk.la_object.object_type_e_SYSTEM_PORT)

        out_dsp = out_dest_chain[-1].downcast()
        U.run_and_compare(self, self.device,
                          input_packet, input_slice, input_ifg, input_serdes,
                          out_packet, out_dsp.get_slice(), out_dsp.get_ifg(), out_dsp.get_base_serdes())
