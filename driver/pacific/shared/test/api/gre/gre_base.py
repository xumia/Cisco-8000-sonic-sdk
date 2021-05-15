#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import packet_test_utils as U
import scapy.all as S
import sim_utils
import nplapicli as nplapi
import topology as T
import packet_test_defs as P
import ip_test_base
from sdk_test_case_base import *
import mtu.mtu_test_utils as MTU
import smart_slices_choise as ssch
import decor


class gre_base(sdk_test_case_base):
    PAYLOAD_SIZE = 60
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    TTL = 255
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    OUTPUT_VID = 0xac

    NUM_OF_NH = 10
    NH_GID_BASE = 0x613
    NH_DST_MAC_BASE = T.mac_addr('11:11:11:11:11:00')

    GRE_PORT_GID = 0x901
    GRE_PORT_GID1 = 0x902
    GRE_PORT_GID2 = 0x903
    GRE_PORT_GID3 = 0x904
    IP_OVER_IP_PORT_GID = 0x810
    GRE_TUNNEL_DESTINATION_GID = 0x674
    GRE_TUNNEL_DESTINATION_GID1 = 0x675

    GRE_SIP = T.ipv4_addr('12.10.12.11')
    GRE_SIP1 = T.ipv4_addr('14.10.12.11')
    GRE_DIP = T.ipv4_addr('12.1.95.250')
    GRE_DIP1 = T.ipv4_addr('14.1.95.250')
    GRE_SIP2 = T.ipv4_addr('16.10.12.11')
    GRE_DIP2 = T.ipv4_addr('16.1.95.250')

    NEW_TX_L3_AC_DEF_MAC = T.mac_addr('50:52:53:54:55:56')
    FORUS_PREFIX = T.ipv4_addr('24.1.1.1')

    PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
    HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
    PUNT_VLAN = 0xA13
    SYS_PORT_GID_BASE = 23
    PI_SP_GID = SYS_PORT_GID_BASE + 2
    PI_SP_GID_HEX = 0x25
    PI_SLICE = T.get_device_slice(3)
    PI_IFG = T.get_device_ifg(1)
    PI_PIF_FIRST = T.get_device_first_serdes(8)
    MIRROR_GID = 2
    MIRROR_CMD_INGRESS_OFFSET = 32
    MIRROR_CMD_EGRESS_OFFSET = 0
    MIRROR_CMD_INGRESS_GID = MIRROR_GID + MIRROR_CMD_INGRESS_OFFSET
    MIRROR_CMD_EGRESS_GID = MIRROR_GID + MIRROR_CMD_EGRESS_OFFSET

    MIRROR_VID = 1

    OVL_IP_PACKET_DMAC = NEW_TX_L3_AC_DEF_MAC.addr_str
    OVL_IP_PACKET_SMAC = '40:11:22:33:44:55'
    UNL_IP_PACKET_SMAC = '00:11:22:33:44:55'

    UNL_IP_PACKET_SMAC = '00:11:22:33:44:55'
    FORUS_IP_PACKET_DIP = '24.1.1.1'

    NON_TUNNEL_SIP     = '17.17.17.17'

    # Forwarding headers
    IN_DSCP = sdk.la_ip_dscp()
    IN_DSCP.value = 0

    IN_TOS = sdk.la_ip_tos()
    IN_TOS.fields.ecn = 0
    IN_TOS.fields.dscp = 0

    # Intermediate tags
    TAG_IP_DSCP = sdk.la_ip_dscp()
    TAG_IP_DSCP.value = 60

    # Egress QoS fields
    # Forwarding headers
    OUT_DSCP = sdk.la_ip_dscp()
    OUT_DSCP.value = 63

    # Encapsulating headers
    OUT_PCPDEI = sdk.la_vlan_pcpdei()
    OUT_PCPDEI.fields.pcp = 5
    OUT_PCPDEI.fields.dei = 1

    OUT_TOS = sdk.la_ip_tos()
    OUT_TOS.fields.ecn = 0
    OUT_TOS.fields.dscp = 5

    TUNNEL_ENCAP_TOS = sdk.la_ip_tos()
    TUNNEL_ENCAP_TOS.fields.ecn = 0
    TUNNEL_ENCAP_TOS.fields.dscp = 7

    QOS_GROUPID = 1

    # Prepare remarking of IN_DSCP -> OUT_DSCP
    encap_qos_values = sdk.encapsulating_headers_qos_values()
    encap_qos_values.pcpdei = OUT_PCPDEI
    encap_qos_values.tos = OUT_TOS

    gre_tunnel2 = None
    gre_tunnel3 = None

    # Source Based Forwarding Test Modes
    SBF_TEST_DISABLED = 0
    SBF_TEST_ENABLED = 1
    SBF_TEST_ENABLED_WITH_MPLS = 2

    SBF_MPLS_LABEL = 0xabc

    def setUp(self):
        super().setUp()
        ssch.rechoose_PI_slices(self, self.device)
        self.ip_impl = ip_test_base.ipv4_test_base
        self.ipv6_impl = ip_test_base.ipv6_test_base
        self.l3_port_impl = T.ip_l3_ac_base(self.topology)

       # punt
        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.PI_SLICE,
            self.PI_IFG,
            self.PI_SP_GID,
            self.PI_PIF_FIRST,
            self.PUNT_INJECT_PORT_MAC_ADDR)

        self.punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.pi_port,
            self.HOST_MAC_ADDR,
            self.PUNT_VLAN)

        self.punt_relay_id = 0 if self.device.get_ll_device().is_pacific() else T.VRF2_GID

        # lpts
        lpts = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV4)
        self.assertNotEqual(lpts, None)

        result = sdk.la_lpts_result()

        k1 = sdk.la_lpts_key()
        k1.val.ipv4.protocol = 89
        k1.mask.ipv4.protocol = sdk.la_l4_protocol_e_RESERVED

        result.flow_type = 11
        result.punt_code = 121
        result.tc = 1
        result.dest = self.punt_dest
        result.meter = T.create_meter_set(self, self.device, is_statistical=True, set_size=1)
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True, set_size=1)

        lpts.append(k1, result)

        count = lpts.get_count()
        self.assertEqual(count, 1)

        lpts = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV6)
        self.assertNotEqual(lpts, None)

        result = sdk.la_lpts_result()

        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        k1.val.ipv6.protocol = 89
        k1.mask.ipv6.protocol = sdk.la_l4_protocol_e_RESERVED

        result.flow_type = 11
        result.punt_code = 121
        result.tc = 1
        result.dest = self.punt_dest
        result.meter = T.create_meter_set(self, self.device, is_statistical=True, set_size=1)
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True, set_size=1)

        lpts.append(k1, result)

        count = lpts.get_count()
        self.assertEqual(count, 1)

        lpts = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV6)
        self.assertNotEqual(lpts, None)

        count = lpts.get_count()
        self.assertEqual(count, 0)

        k3 = sdk.la_lpts_key()
        k3.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        k3.val.ipv6.protocol = 89
        k3.mask.ipv6.protocol = sdk.la_l4_protocol_e_RESERVED

        result = sdk.la_lpts_result()
        result.flow_type = 11
        result.punt_code = 121
        result.tc = 0
        result.dest = self.punt_dest
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)

        lpts.append(k3, result)
        count = lpts.get_count()
        self.assertEqual(count, 1)

        # enable ipv4 forwarding
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_ext.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)

        # enable ipv6 forwarding
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, True)
        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, True)
        self.topology.tx_l3_ac_ext.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, True)

        # make the l3 port address unicast mac address
        self.topology.tx_l3_ac_def.hld_obj.set_mac(
            self.NEW_TX_L3_AC_DEF_MAC.hld_obj)

        # put tx_l3_ac_def in vrf2
        self.topology.tx_l3_ac_def.hld_obj.set_vrf(self.topology.vrf2.hld_obj)

        # set counters on ingress interface
        self.ingress_port_counter = self.device.create_counter(1)
        self.topology.tx_l3_ac_reg.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.ingress_port_counter)
        self.egress_port_counter_reg = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        self.topology.tx_l3_ac_reg.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.egress_port_counter_reg)

        self.egress_port_counter = self.device.create_counter(1)
        self.topology.tx_l3_ac_def.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.egress_port_counter)

        self.add_default_route()

        self.source_based_forwarding = self.SBF_TEST_DISABLED

        # Mirror command
        self.mirror_cmd = T.create_l2_mirror_command(
            self.device,
            self.MIRROR_CMD_INGRESS_GID,
            self.pi_port,
            self.HOST_MAC_ADDR,
            self.MIRROR_VID)

        # Clear trap and set snoop -> packet will go out and another packet with punt header will be generated.
        priority = 0
        self.orig_trap_config = self.device.get_trap_configuration(sdk.LA_EVENT_L3_INGRESS_MONITOR)
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_INGRESS_MONITOR)
        self.device.set_snoop_configuration(sdk.LA_EVENT_L3_INGRESS_MONITOR, priority, False, False, self.mirror_cmd)

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix,
                               self.l3_port_impl.def_nh,
                               self.PRIVATE_DATA_DEFAULT)
        prefix_v6 = self.ipv6_impl.get_default_prefix()
        self.ipv6_impl.add_route(self.topology.vrf, prefix_v6,
                                 self.l3_port_impl.def_nh,
                                 self.PRIVATE_DATA_DEFAULT)
        self.has_default_route = True

    def destroy_default_route(self):
        if self.has_default_route:
            prefix = self.ip_impl.get_default_prefix()
            self.ip_impl.delete_route(self.topology.vrf, prefix)
            prefix_v6 = self.ipv6_impl.get_default_prefix()
            self.ipv6_impl.delete_route(self.topology.vrf, prefix_v6)
            self.has_default_route = False

    def ip_over_ip_tunnel_port_setup(self, gid, mode, unl_vrf, sip, dip, vrf):

        tunnel_dest = self.ip_impl.build_prefix(sip, length=32)
        # now let's creat ip_over_ip_tunnel port
        ip_over_ip_tunnel = T.ip_over_ip_tunnel_port(self, self.device,
                                                     gid,
                                                     unl_vrf,
                                                     tunnel_dest,
                                                     dip,
                                                     vrf,
                                                     mode)

        ip_over_ip_tunnel.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        ip_over_ip_tunnel.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

        return ip_over_ip_tunnel

    def gre_port_setup(self, gid, mode, unl_vrf, sip, dip, vrf, per_proto_counter=False):

        # now let's creat gre port
        gre_tunnel = self.device.create_gre_port(
            gid,
            mode,
            unl_vrf.hld_obj,
            sip.hld_obj,
            dip.hld_obj,
            vrf.hld_obj,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)

        # set the counter
        if (per_proto_counter):
            self.l3_egress_counter = self.device.create_counter(sdk.la_l3_protocol_e_LAST)
        else:
            self.l3_egress_counter = self.device.create_counter(1)
        self.l3_ingress_counter = self.device.create_counter(1)
        gre_tunnel.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l3_egress_counter)
        gre_tunnel.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.l3_ingress_counter)

        # set TTL to PIPE mode
        gre_tunnel.set_ttl_inheritance_mode(sdk.la_gre_port.la_ttl_inheritance_mode_e_PIPE)

        # enable ipv4 on gre port
        gre_tunnel.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        # enable ipv6 on gre port
        gre_tunnel.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        return gre_tunnel

    def gre_port_single_underlay_path_SBF(self, is_per_proto=False):
        self.gre_port_single_underlay_path(sdk.la_ip_tunnel_mode_e_ENCAP_DECAP, is_per_proto)

        self.mpls_label_present = True if self.source_based_forwarding == self.SBF_TEST_ENABLED_WITH_MPLS else False
        self.label = sdk.la_mpls_label()
        self.label.label = self.SBF_MPLS_LABEL

        # set source based forwarding destination and label
        self.topology.tx_l3_ac_def.hld_obj.set_source_based_forwarding(self.gre_destination, self.mpls_label_present, self.label)
        # try to set the same destination and label again to ensure no errors
        self.topology.tx_l3_ac_def.hld_obj.set_source_based_forwarding(self.gre_destination, self.mpls_label_present, self.label)

        destination_out, mpls_label_present_out, mpls_label_out = self.topology.tx_l3_ac_def.hld_obj.get_source_based_forwarding()

        self.assertEqual(mpls_label_present_out, self.mpls_label_present)
        self.assertEqual(mpls_label_out.label, self.label.label)
        self.assertEqual(destination_out.oid(), self.gre_destination.oid())
        self.assertEqual(destination_out.type(), sdk.la_object.object_type_e_IP_TUNNEL_DESTINATION)

    def ip_over_ip_tunnel_port_multi_underlay_path(self, mode=sdk.la_ip_tunnel_mode_e_ENCAP_ONLY):
        self.ip_over_ip_tunnel = self.ip_over_ip_tunnel_port_setup(self.GRE_PORT_GID, mode, self.topology.vrf,
                                                                   self.GRE_SIP, self.GRE_DIP, self.topology.vrf2)
        self.ip_over_ip_tunnel1 = self.ip_over_ip_tunnel_port_setup(self.GRE_PORT_GID1, mode, self.topology.vrf,
                                                                    self.GRE_SIP1, self.GRE_DIP1, self.topology.vrf2)
        # create underlay ecmp group
        self.unl_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.unl_ecmp_attached_members = [self.topology.nh_l3_ac_reg, self.topology.nh_l3_ac_ext]
        for member in self.unl_ecmp_attached_members:
            self.unl_ecmp.add_member(member.hld_obj)

        self.ip_over_ip_tunnel_destination = self.device.create_ip_tunnel_destination(
            self.GRE_TUNNEL_DESTINATION_GID,
            self.ip_over_ip_tunnel.hld_obj,
            self.unl_ecmp)

        self.ip_over_ip_tunnel_destination1 = self.device.create_ip_tunnel_destination(
            self.GRE_TUNNEL_DESTINATION_GID1,
            self.ip_over_ip_tunnel1.hld_obj,
            self.unl_ecmp)

        self.ip_over_ip_tunnel_port_create_ovl_ecmp()

        self.setup_as_multi_underlay_path = True

    def gre_port_multi_underlay_path(self, mode=sdk.la_ip_tunnel_mode_e_ENCAP_DECAP):
        self.gre_tunnel = self.gre_port_setup(self.GRE_PORT_GID, mode, self.topology.vrf,
                                              self.GRE_SIP, self.GRE_DIP, self.topology.vrf2)
        self.gre_tunnel1 = self.gre_port_setup(self.GRE_PORT_GID1, mode, self.topology.vrf,
                                               self.GRE_SIP1, self.GRE_DIP1, self.topology.vrf2)
        # create underlay ecmp group
        self.unl_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.unl_ecmp_attached_members = [self.topology.nh_l3_ac_reg, self.topology.nh_l3_ac_ext]
        for member in self.unl_ecmp_attached_members:
            self.unl_ecmp.add_member(member.hld_obj)

        self.gre_destination = self.device.create_ip_tunnel_destination(
            self.GRE_TUNNEL_DESTINATION_GID,
            self.gre_tunnel,
            self.unl_ecmp)

        self.gre_destination1 = self.device.create_ip_tunnel_destination(
            self.GRE_TUNNEL_DESTINATION_GID1,
            self.gre_tunnel1,
            self.unl_ecmp)

        self.gre_port_create_ovl_ecmp()

        self.setup_as_multi_underlay_path = True

    def gre_port_multi_underlay_path_SBF(self):
        self.gre_port_multi_underlay_path()

        self.mpls_label_present = True if self.source_based_forwarding == self.SBF_TEST_ENABLED_WITH_MPLS else False
        self.label = sdk.la_mpls_label()
        self.label.label = self.SBF_MPLS_LABEL

        # Test successive settings to ensure last one takes effect
        self.topology.tx_l3_ac_def.hld_obj.set_source_based_forwarding(self.gre_destination, False, self.label)
        self.topology.tx_l3_ac_def.hld_obj.set_source_based_forwarding(self.gre_destination1, False, self.label)
        self.topology.tx_l3_ac_def.hld_obj.set_source_based_forwarding(self.ovl_ecmp, self.mpls_label_present, self.label)

        destination_out, mpls_label_present_out, mpls_label_out = self.topology.tx_l3_ac_def.hld_obj.get_source_based_forwarding()

        self.assertEqual(mpls_label_present_out, self.mpls_label_present)
        self.assertEqual(mpls_label_out.label, self.label.label)
        self.assertEqual(destination_out.oid(), self.ovl_ecmp.oid())
        self.assertEqual(destination_out.type(), sdk.la_object.object_type_e_ECMP_GROUP)

    def destroy_source_based_forwarding(self):
        if self.source_based_forwarding != self.SBF_TEST_DISABLED:
            self.topology.tx_l3_ac_def.hld_obj.clear_source_based_forwarding()
            # Clearing more than once should not error out
            self.topology.tx_l3_ac_def.hld_obj.clear_source_based_forwarding()

    def destroy_gre_qos_profile(self):
        if hasattr(self, 'ingress_qos_profile'):
            self.ingress_qos_profile.destroy()
        if hasattr(self, 'egress_qos_profile'):
            self.egress_qos_profile.destroy()
        if hasattr(self, 'ingress_qos_counter'):
            self.device.destroy(self.ingress_qos_counter)

    def _test_gre_port_getter(self):
        # test get function for ip tunnel destination
        dest = self.device.get_ip_tunnel_destination_by_gid(self.GRE_TUNNEL_DESTINATION_GID)
        self.assertEqual(dest.get_gid(), self.GRE_TUNNEL_DESTINATION_GID)
        self.assertEqual(dest.type(), sdk.la_object.object_type_e_IP_TUNNEL_DESTINATION)
        ip_tunnel = dest.get_ip_tunnel_port()
        self.assertEqual(ip_tunnel.get_gid(), self.GRE_PORT_GID)
        self.assertEqual(ip_tunnel.type(), sdk.la_object.object_type_e_GRE_PORT)
        unl_dest = dest.get_underlay_destination()
        unl_nh = unl_dest.downcast()
        self.assertEqual(unl_nh.get_gid(), T.NH_L3_AC_REG_GID)
        self.assertEqual(unl_nh.type(), sdk.la_object.object_type_e_NEXT_HOP)

        # test get function for gre port
        gre_port_ret = self.device.get_gre_port_by_gid(self.GRE_PORT_GID)
        self.assertEqual(gre_port_ret.get_gid(), self.GRE_PORT_GID)
        self.assertEqual(gre_port_ret.type(), sdk.la_object.object_type_e_GRE_PORT)
        underlay_vrf = gre_port_ret.get_underlay_vrf()
        self.assertEqual(underlay_vrf.get_gid(), T.VRF_GID)
        overlay_vrf = gre_port_ret.get_overlay_vrf()
        self.assertEqual(overlay_vrf.get_gid(), T.VRF2_GID)
        local_ip_addr = gre_port_ret.get_local_ip_addr()
        self.assertEqual(local_ip_addr.s_addr, self.GRE_SIP.hld_obj.s_addr)
        remote_ip_addr = gre_port_ret.get_remote_ip_addr()
        self.assertEqual(remote_ip_addr.s_addr, self.GRE_DIP.hld_obj.s_addr)
        ingress_qos_profile = gre_port_ret.get_ingress_qos_profile()
        self.assertEqual(ingress_qos_profile.this, self.topology.ingress_qos_profile_def.hld_obj.this)
        egress_qos_profile = gre_port_ret.get_egress_qos_profile()
        self.assertEqual(egress_qos_profile.this, self.topology.egress_qos_profile_def.hld_obj.this)
        ingress_counter = gre_port_ret.get_ingress_counter(sdk.la_counter_set.type_e_PORT)
        self.assertEqual(ingress_counter.this, self.l3_ingress_counter.this)
        egress_counter = gre_port_ret.get_egress_counter(sdk.la_counter_set.type_e_PORT)
        self.assertEqual(egress_counter.this, self.l3_egress_counter.this)
        ttl_mode = gre_port_ret.get_ttl_inheritance_mode()
        self.assertEqual(ttl_mode, sdk.la_gre_port.la_ttl_inheritance_mode_e_PIPE)
        lp_attribute_inheritance_mode = gre_port_ret.get_lp_attribute_inheritance_mode()
        self.assertEqual(lp_attribute_inheritance_mode, sdk.la_lp_attribute_inheritance_mode_e_PORT)
        encap_qos_mode = gre_port_ret.get_encap_qos_mode()
        self.assertEqual(encap_qos_mode, sdk.la_tunnel_encap_qos_mode_e_UNIFORM)
        gre_port_ret.set_tunnel_termination_type(sdk.la_gre_port.tunnel_termination_type_e_P2MP)
        term_type = gre_port_ret.get_tunnel_termination_type()
        self.assertEqual(term_type, sdk.la_gre_port.tunnel_termination_type_e_P2MP)
        gre_port_ret.set_tunnel_termination_type(sdk.la_gre_port.tunnel_termination_type_e_P2P)
        term_type = gre_port_ret.get_tunnel_termination_type()
        self.assertEqual(term_type, sdk.la_gre_port.tunnel_termination_type_e_P2P)

    def _test_gre_port_decap_acl_outer_header(self):
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        # ACL match on the Outer Header
        DIP = self.GRE_SIP
        k = []
        f = sdk.la_acl_field()
        f.type = sdk.la_acl_field_type_e_IPV4_DIP
        f.val.ipv4_dip.s_addr = DIP.to_num()
        f.mask.ipv4_dip.s_addr = 0xffffffff
        k.append(f)

        commands = []
        action = sdk.la_acl_command_action()
        action.type = sdk.la_acl_action_type_e_DROP
        action.data.drop = True
        commands.append(action)

        acl1.append(k, commands)

        ipv4_acls = []
        ipv4_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.tx_l3_ac_reg.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_ACL_OVL_INPUT_IP / \
            S.TCP()

        self.input_packet, __ = U.enlarge_packet_to_min_length(input_packet_base)

        U.run_and_drop(self, self.device,
                       self.input_packet, T.TX_SLICE_REG,
                       T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.topology.tx_l3_ac_reg.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    def _test_gre_encap_qos(self):
        '''
        When the tunnel's encap_qos_mode is UNIFORM (by default)
        and we set tunnel's lp_attribute_inheritance_mode to TUNNEL,
        the GRE outer IP DSCP should be determined by the tunnel's egress_qos_profile marking
        '''

        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        self.assertEqual(self.gre_tunnel.get_lp_attribute_inheritance_mode(),
                         sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)

        # test setting DSCP by qos tag mapping
        self.topology.ingress_qos_profile_def.hld_obj.set_qos_tag_mapping_dscp(
            sdk.la_ip_version_e_IPV4, self.IN_DSCP, self.TAG_IP_DSCP)
        self.topology.ingress_qos_profile_def.hld_obj.set_qos_tag_mapping_dscp(
            sdk.la_ip_version_e_IPV6, self.IN_DSCP, self.TAG_IP_DSCP)

        gre_egress_qos_profile = T.egress_qos_profile(self, self.device, sdk.la_egress_qos_marking_source_e_QOS_TAG)
        gre_egress_qos_profile.hld_obj.set_qos_tag_mapping_dscp(
            self.TAG_IP_DSCP, self.OUT_DSCP, self.encap_qos_values)
        self.gre_tunnel.set_egress_qos_profile(gre_egress_qos_profile.hld_obj)

        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            self.ENCAP_QOS_OVL_INPUT_IP / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=self.GRE_DIP.addr_str,
                 src=self.GRE_SIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255,
                 tos=self.OUT_TOS.flat) / \
            self.GRE_HEADER / \
            self.ENCAP_QOS_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.gre_tunnel.set_egress_qos_profile(
            self.topology.egress_qos_profile_def.hld_obj)
        gre_egress_qos_profile.destroy()

        # test setting DSCP by qos groupscapy.all
        # Update qos profiles
        self.ingress_qos_profile = T.ingress_qos_profile(self, self.device)
        self.ingress_qos_profile.hld_obj.set_qos_tag_mapping_enabled(True)
        self.ingress_qos_profile.hld_obj.set_qos_group_mapping(sdk.la_ip_version_e_IPV4, self.IN_DSCP, self.QOS_GROUPID)
        self.ingress_qos_profile.hld_obj.set_qos_group_mapping(sdk.la_ip_version_e_IPV6, self.IN_DSCP, self.QOS_GROUPID)

        self.egress_qos_profile = T.egress_qos_profile(self, self.device, sdk.la_egress_qos_marking_source_e_QOS_GROUP)
        self.egress_qos_profile.hld_obj.set_qos_group_mapping_dscp(self.QOS_GROUPID, self.OUT_DSCP, self.encap_qos_values)

        self.topology.tx_l3_ac_def.hld_obj.set_ingress_qos_profile(
            self.ingress_qos_profile.hld_obj)
        self.gre_tunnel.set_egress_qos_profile(self.egress_qos_profile.hld_obj)

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=self.GRE_DIP.addr_str,
                 src=self.GRE_SIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255,
                 tos=self.OUT_TOS.flat) / \
            self.GRE_HEADER / \
            self.ENCAP_QOS_OVL_EXPECTED_IP_2 / \
            S.TCP()

        __, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.topology.tx_l3_ac_def.hld_obj.set_ingress_qos_profile(
            self.topology.ingress_qos_profile_def.hld_obj)

    def _test_gre_encap_qos2(self):
        '''
        When the tunnel's encap_qos_mode is UNIFORM (by default)
        and we set tunnel's lp_attribute_inheritance_mode to PORT,
        the GRE outer IP DSCP should be determined by tx L3 port's egress_qos_profile marking
        '''

        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

        # test setting DSCP by qos tag mapping
        l3_ingress_qos_profile = T.ingress_qos_profile(self, self.device)
        l3_ingress_qos_profile.hld_obj.set_qos_tag_mapping_enabled(True)
        l3_ingress_qos_profile.hld_obj.set_qos_tag_mapping_dscp(
            sdk.la_ip_version_e_IPV4, self.IN_DSCP, self.TAG_IP_DSCP)
        l3_ingress_qos_profile.hld_obj.set_qos_tag_mapping_dscp(
            sdk.la_ip_version_e_IPV6, self.IN_DSCP, self.TAG_IP_DSCP)

        l3_egress_qos_profile = T.egress_qos_profile(self, self.device, sdk.la_egress_qos_marking_source_e_QOS_TAG)
        l3_egress_qos_profile.hld_obj.set_qos_tag_mapping_dscp(
            self.TAG_IP_DSCP, self.OUT_DSCP, self.encap_qos_values)

        self.topology.tx_l3_ac_def.hld_obj.set_ingress_qos_profile(l3_ingress_qos_profile.hld_obj)
        self.topology.tx_l3_ac_reg.hld_obj.set_egress_qos_profile(l3_egress_qos_profile.hld_obj)

        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            self.ENCAP_QOS_OVL_INPUT_IP / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=self.GRE_DIP.addr_str,
                 src=self.GRE_SIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255,
                 tos=self.OUT_TOS.flat) / \
            self.GRE_HEADER / \
            self.ENCAP_QOS_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.topology.tx_l3_ac_def.hld_obj.set_ingress_qos_profile(
            self.topology.ingress_qos_profile_def.hld_obj)
        self.topology.tx_l3_ac_reg.hld_obj.set_egress_qos_profile(
            self.topology.egress_qos_profile_def.hld_obj)
        l3_ingress_qos_profile.destroy()
        l3_egress_qos_profile.destroy()

        # test setting DSCP by qos groupscapy.all
        l3_ingress_qos_profile = T.ingress_qos_profile(self, self.device)
        l3_ingress_qos_profile.hld_obj.set_qos_tag_mapping_enabled(True)
        l3_ingress_qos_profile.hld_obj.set_qos_group_mapping(sdk.la_ip_version_e_IPV4, self.IN_DSCP, self.QOS_GROUPID)
        l3_ingress_qos_profile.hld_obj.set_qos_group_mapping(sdk.la_ip_version_e_IPV6, self.IN_DSCP, self.QOS_GROUPID)

        l3_egress_qos_profile = T.egress_qos_profile(self, self.device, sdk.la_egress_qos_marking_source_e_QOS_GROUP)
        l3_egress_qos_profile.hld_obj.set_qos_group_mapping_dscp(self.QOS_GROUPID, self.OUT_DSCP, self.encap_qos_values)

        self.topology.tx_l3_ac_def.hld_obj.set_ingress_qos_profile(l3_ingress_qos_profile.hld_obj)
        self.topology.tx_l3_ac_reg.hld_obj.set_egress_qos_profile(l3_egress_qos_profile.hld_obj)

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=self.GRE_DIP.addr_str,
                 src=self.GRE_SIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255,
                 tos=self.OUT_TOS.flat) / \
            self.GRE_HEADER / \
            self.ENCAP_QOS_OVL_EXPECTED_IP_2 / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.topology.tx_l3_ac_def.hld_obj.set_ingress_qos_profile(
            self.topology.ingress_qos_profile_def.hld_obj)
        self.topology.tx_l3_ac_reg.hld_obj.set_egress_qos_profile(
            self.topology.egress_qos_profile_def.hld_obj)
        l3_ingress_qos_profile.destroy()
        l3_egress_qos_profile.destroy()

    def _test_gre_encap_tunnel_qos(self):
        '''
        When the tunnel's encap_qos_mode is set to PIPE,
        the GRE outer IP DSCP should be solely derived from the tunnel's encap_tos.
        '''

        self.gre_tunnel.set_encap_qos_mode(sdk.la_tunnel_encap_qos_mode_e_PIPE)
        self.gre_tunnel.set_encap_tos(self.TUNNEL_ENCAP_TOS)
        tunnel_encap_tos = sdk.la_ip_tos()
        self.gre_tunnel.get_encap_tos(tunnel_encap_tos)
        self.assertEqual(tunnel_encap_tos.flat, self.TUNNEL_ENCAP_TOS.flat)

        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            self.ENCAP_QOS_OVL_INPUT_IP / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=self.GRE_DIP.addr_str,
                 src=self.GRE_SIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255,
                 tos=self.TUNNEL_ENCAP_TOS.flat) / \
            self.GRE_HEADER / \
            self.ENCAP_QOS_OVL_EXPECTED_IP_2 / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        # test setting DSCP by qos tag mapping
        self.topology.ingress_qos_profile_def.hld_obj.set_qos_tag_mapping_dscp(self.IN_DSCP, self.TAG_IP_DSCP)
        self.topology.egress_qos_profile_def.hld_obj.set_qos_tag_mapping_dscp(
            self.TAG_IP_DSCP, self.OUT_DSCP, self.encap_qos_values)

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=self.GRE_DIP.addr_str,
                 src=self.GRE_SIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255,
                 tos=self.TUNNEL_ENCAP_TOS.flat) / \
            self.GRE_HEADER / \
            self.ENCAP_QOS_OVL_EXPECTED_IP / \
            S.TCP()
        _, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

    def _test_gre_port_decap_ttl(self):
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        self.gre_tunnel.set_ttl_inheritance_mode(sdk.la_gre_port.la_ttl_inheritance_mode_e_PIPE)
        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_OVL_INPUT_IP / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            self.PORT_DECAP_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        expected_packet_base_no_ttl_decr = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            self.PORT_DECAP_OVL_EXPECTED_IP_NO_TTL_DECR / \
            S.TCP()

        self.input_packet, self.expected_packet_no_ttl_decr = U.pad_input_and_output_packets(
            input_packet_base, expected_packet_base_no_ttl_decr)

        # set no ttl decr on the device verify ttl remains same in inner Header.
        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_GRE, False)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet_no_ttl_decr, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        # reset to default. verify ttl is decremented
        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_GRE, True)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        # change the TTL mode
        self.gre_tunnel.set_ttl_inheritance_mode(sdk.la_gre_port.la_ttl_inheritance_mode_e_UNIFORM)
        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_OVL_INPUT_IP / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            self.PORT_DECAP_OVL_TTL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def _test_gre_port_decap(self, port_inheritance=True, test_counters=False):
        if (port_inheritance):
            self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        else:
            self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_OVL_INPUT_IP / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            self.PORT_DECAP_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        expected_packet_base_no_ttl_decr = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            self.PORT_DECAP_OVL_EXPECTED_IP_NO_TTL_DECR / \
            S.TCP()

        self.input_packet, self.expected_packet_no_ttl_decr = U.pad_input_and_output_packets(
            input_packet_base, expected_packet_base_no_ttl_decr)

        # set no ttl decr on the device verify ttl remains same in inner Header.
        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_GRE, False)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet_no_ttl_decr, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        # reset to default. verify ttl is decremented
        self.device.set_decap_ttl_decrement_enabled(sdk.la_ip_tunnel_type_e_GRE, True)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        # change the underlay_vrf
        self.gre_tunnel.set_underlay_vrf(self.topology.global_vrf.hld_obj)
        self.topology.tx_l3_ac_reg.hld_obj.set_vrf(self.topology.global_vrf.hld_obj)
        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        # change remote ip address
        self.gre_tunnel.set_remote_ip_address(self.GRE_DIP1.hld_obj)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP1.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_OVL_INPUT_IP / \
            S.TCP()

        self.input_packet, __ = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        # change the local ip address
        self.gre_tunnel.set_local_ip_address(self.GRE_SIP1.hld_obj)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP1.addr_str,
                 src=self.GRE_DIP1.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_OVL_INPUT_IP / \
            S.TCP()

        self.input_packet, __ = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        if decor.is_asic5():
            expected_pkt_count = 6
        else:
            expected_pkt_count = 7
            # change the overlay vrf
            self.gre_tunnel.set_overlay_vrf(self.topology.vrf.hld_obj)
            self.topology.tx_l3_ac_def.hld_obj.set_vrf(self.topology.vrf.hld_obj)

            U.run_and_compare(self, self.device,
                              self.input_packet, T.TX_SLICE_REG,
                              T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                              self.expected_packet, T.TX_SLICE_DEF,
                              T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        packets, byte_count = self.l3_ingress_counter.read(0, True, True)
        self.assertEqual(packets, expected_pkt_count)

        if test_counters:
            # This works on SIM but fails on HW - uncomment after HW fix
            # packets1, byte_count1 = self.ingress_port_counter.read(0, True, True)
            # self.assertEqual(packets1, 7)

            packets2, byte_count2 = self.egress_port_counter.read(0, True, True)
            self.assertEqual(packets2, expected_pkt_count)

    def __test_gre_port_decap_sflow(self, is_snoop_expected):
        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_OVL_INPUT_IP / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            self.PORT_DECAP_OVL_EXPECTED_IP / \
            S.TCP()

        input_packet, expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        is_ipv4 = isinstance(self.PORT_DECAP_OVL_INPUT_IP, type(S.IP()))
        if is_ipv4:
            act_next_header = sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4
            act_fwd_header_type = sdk.la_packet_types.LA_HEADER_TYPE_IPV4
        else:
            act_next_header = sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV6
            act_fwd_header_type = sdk.la_packet_types.LA_HEADER_TYPE_IPV6

        snoop_packet = Ether(dst=self.HOST_MAC_ADDR, src=self.PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=self.MIRROR_VID, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=act_next_header, fwd_header_type=act_fwd_header_type,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=self.MIRROR_CMD_INGRESS_GID,
                   source_sp=T.TX_L3_AC_SYS_PORT_REG_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=self.GRE_PORT_GID, destination_lp=T.TX_L3_AC_DEF_GID,
                   relay_id=T.VRF2_GID, lpts_flow_type=0
                   ) / \
            input_packet

        ingress_packet = {'data': input_packet, 'slice': T.TX_SLICE_REG, 'ifg': T.TX_IFG_REG, 'pif': T.FIRST_SERDES_L3}
        expected_packets = [{'data': expected_packet, 'slice': T.TX_SLICE_DEF, 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3}]
        if is_snoop_expected:
            expected_packets.append({'data': snoop_packet, 'slice': self.PI_SLICE, 'ifg': self.PI_IFG, 'pif': self.PI_PIF_FIRST})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def _test_gre_port_decap_sflow(self):

        orig_sflow_enabled = self.gre_tunnel.get_ingress_sflow_enabled()
        orig_inheritance_mode = self.gre_tunnel.get_lp_attribute_inheritance_mode()
        orig_port_sflow_enabled = self.topology.tx_l3_ac_reg.hld_obj.get_ingress_sflow_enabled()

        # Check netflow at tunnel
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)

        self.gre_tunnel.set_ingress_sflow_enabled(True)
        self.topology.tx_l3_ac_reg.hld_obj.set_ingress_sflow_enabled(False)
        self.__test_gre_port_decap_sflow(is_snoop_expected=True)

        # Check netflow at logical port
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

        self.gre_tunnel.set_ingress_sflow_enabled(False)
        self.topology.tx_l3_ac_reg.hld_obj.set_ingress_sflow_enabled(True)
        self.__test_gre_port_decap_sflow(is_snoop_expected=True)

        self.gre_tunnel.set_ingress_sflow_enabled(True)
        self.topology.tx_l3_ac_reg.hld_obj.set_ingress_sflow_enabled(False)
        self.__test_gre_port_decap_sflow(is_snoop_expected=False)

        # Cleanup
        self.gre_tunnel.set_lp_attribute_inheritance_mode(orig_inheritance_mode)
        self.gre_tunnel.set_ingress_sflow_enabled(orig_sflow_enabled)
        self.topology.tx_l3_ac_reg.hld_obj.set_ingress_sflow_enabled(orig_port_sflow_enabled)

    def _test_gre_port_decap_p2mp_termination(self):
        self.gre_tunnel.set_tunnel_termination_type(sdk.la_gre_port.tunnel_termination_type_e_P2MP)
        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_OVL_INPUT_IP / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            self.PORT_DECAP_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        # change the underlay_vrf
        self.gre_tunnel.set_underlay_vrf(self.topology.global_vrf.hld_obj)
        self.topology.tx_l3_ac_reg.hld_obj.set_vrf(self.topology.global_vrf.hld_obj)
        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        # change remote ip address
        self.gre_tunnel.set_remote_ip_address(self.GRE_DIP1.hld_obj)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP1.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_OVL_INPUT_IP / \
            S.TCP()

        self.input_packet, __ = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        # change the local ip address
        self.gre_tunnel.set_local_ip_address(self.GRE_SIP1.hld_obj)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP1.addr_str,
                 src=self.GRE_DIP1.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_OVL_INPUT_IP / \
            S.TCP()

        self.input_packet, __ = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        # change the overlay vrf
        self.gre_tunnel.set_overlay_vrf(self.topology.vrf.hld_obj)
        self.topology.tx_l3_ac_def.hld_obj.set_vrf(self.topology.vrf.hld_obj)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        packets, byte_count = self.l3_ingress_counter.read(0, True, True)
        self.assertEqual(packets, 5)

        self.gre_tunnel.set_tunnel_termination_type(sdk.la_gre_port.tunnel_termination_type_e_P2P)

    def _test_gre_port_decap_ip_over_ip(self):
        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_OVL_INPUT_IP / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            self.PORT_DECAP_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        self.destroy_gre_port_single_underlay_path()

        self.tunnel_dest = ip_test_base.ipv4_test_base.build_prefix(self.GRE_SIP, length=16)
        self.ip_over_ip_tunnel_port = T.ip_over_ip_tunnel_port(self, self.device,
                                                               self.IP_OVER_IP_PORT_GID,
                                                               self.topology.vrf,
                                                               self.tunnel_dest,
                                                               self.GRE_DIP,
                                                               self.topology.vrf2)
        self.ip_over_ip_tunnel_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.ip_over_ip_tunnel_port.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=254) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_OVL_INPUT_IP / \
            S.TCP()
        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        self.gre_port_single_underlay_path()
        self.device.destroy(self.ip_over_ip_tunnel_port.hld_obj)

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            self.PORT_DECAP_OVL_EXPECTED_IP / \
            S.TCP()
        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        self.destroy_gre_port_single_underlay_path()

    def _test_gre_port_decap_termination_negative(self, mode=sdk.la_ip_tunnel_mode_e_ENCAP_DECAP):

        # create a new tunnel (T2) with same local address as orginal tunnel(T) created in setup phase
        # termination type is P2P - the default
        # creation should succeed because the remote ip is different
        self.gre_tunnel2 = self.gre_port_setup(self.GRE_PORT_GID2, mode, self.topology.vrf,
                                               self.GRE_SIP, self.GRE_DIP2, self.topology.vrf2)

        # now try to change termination type for T2 to P2MP - this should fail
        # because we already have a P2P tunnel with same local address
        with self.assertRaises(sdk.ExistException):
            self.gre_tunnel2.set_tunnel_termination_type(sdk.la_gre_port.tunnel_termination_type_e_P2MP)
        self.device.destroy(self.gre_tunnel2)

        # re-create a tunnel T2 with different local address as orginal tunnel(T) created in setup phase
        # termination type is P2P - the default
        self.gre_tunnel2 = self.gre_port_setup(self.GRE_PORT_GID2, mode, self.topology.vrf,
                                               self.GRE_SIP2, self.GRE_DIP2, self.topology.vrf2)
        # change T2 termination type to P2MP
        self.gre_tunnel2.set_tunnel_termination_type(sdk.la_gre_port.tunnel_termination_type_e_P2MP)

        # try to create T3 with same local IP address as T2
        # this should fail since we already have a P2MP tunnel with same local IP addresss (T2)
        with self.assertRaises(sdk.ExistException):
            self.gre_tunnel3 = self.gre_port_setup(self.GRE_PORT_GID3, mode, self.topology.vrf,
                                                   self.GRE_SIP2, self.GRE_DIP1, self.topology.vrf2)
        self.device.destroy(self.gre_tunnel2)

    def _test_gre_port_local_and_remote_change(self):
        '''
        We have 3 tunnels:
        T1: SIP - DIP
        T2: SIP2 - DIP1
        T3: SIP2  - DIP
        When we try to change T3 to SIP and DIP1 and call each of set local and set remote
        it will fail. Now, if we call the set_local_and_remote it will succeed
        '''
        mode = sdk.la_ip_tunnel_mode_e_ENCAP_DECAP
        GRE_SIP_PREFIX = self.ip_impl.build_prefix(self.GRE_SIP, length=32)
        GRE_DIP1_PREFIX = self.ip_impl.build_prefix(self.GRE_DIP1, length=32)

        self.gre_tunnel2 = self.gre_port_setup(self.GRE_PORT_GID2, mode, self.topology.vrf,
                                               self.GRE_SIP2, self.GRE_DIP1, self.topology.vrf2)

        self.gre_tunnel3 = self.gre_port_setup(self.GRE_PORT_GID3, mode, self.topology.vrf,
                                               self.GRE_SIP2, self.GRE_DIP, self.topology.vrf2)
        with self.assertRaises(sdk.ExistException):
            self.gre_tunnel3.set_local_ip_prefix(GRE_SIP_PREFIX)

        with self.assertRaises(sdk.ExistException):
            self.gre_tunnel3.set_remote_ip_prefix(GRE_DIP1_PREFIX)

        self.gre_tunnel3.set_local_and_remote_ip_prefix(GRE_SIP_PREFIX, GRE_DIP1_PREFIX)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP1.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_OVL_INPUT_IP / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            self.PORT_DECAP_OVL_EXPECTED_IP / \
            S.TCP()
        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3,
                          self.expected_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3)

    def _test_gre_port_decap_mtu(self):
        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_OVL_INPUT_IP / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            self.PORT_DECAP_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        MTU.run_mtu_test(self, self.device,
                         self.input_packet, T.TX_SLICE_REG,
                         T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                         self.expected_packet, T.TX_SLICE_DEF,
                         T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

    def _test_gre_port_decap_qos(self):
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        self.ingress_qos_profile = T.ingress_qos_profile(self, self.device)
        self.ingress_qos_profile.hld_obj.set_qos_tag_mapping_enabled(True)
        self.gre_tunnel.set_ingress_qos_profile(self.ingress_qos_profile.hld_obj)
        self.ingress_qos_counter = self.device.create_counter(sdk.LA_NUM_L3_INGRESS_TRAFFIC_CLASSES)
        self.gre_tunnel.set_ingress_counter(sdk.la_counter_set.type_e_QOS, self.ingress_qos_counter)
        dscp = sdk.la_ip_dscp()
        dscp.value = 0
        self.ingress_qos_profile.hld_obj.set_meter_or_counter_offset_mapping(sdk.la_ip_version_e_IPV4, dscp, 1)
        self.ingress_qos_profile.hld_obj.set_meter_or_counter_offset_mapping(sdk.la_ip_version_e_IPV6, dscp, 1)

        # test setting DSCP by qos tag mapping
        self.ingress_qos_profile.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV4, self.IN_DSCP, self.TAG_IP_DSCP)
        self.ingress_qos_profile.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV6, self.IN_DSCP, self.TAG_IP_DSCP)
        self.topology.egress_qos_profile_def.hld_obj.set_qos_tag_mapping_dscp(
            self.TAG_IP_DSCP, self.OUT_DSCP, self.encap_qos_values)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_QOS_OVL_INPUT_IP / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            self.PORT_DECAP_QOS_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        # To BE Fixed after 32 class map support goes in
        # packets, byte_count = self.ingress_qos_counter.read(1, True, True)
        # self.assertEqual(packets, 1)

    def _test_gre_port_decap_qos2(self):
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255,
                 tos=self.OUT_TOS.flat) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_QOS_OVL_INPUT_IP / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            self.PORT_DECAP_QOS2_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        self.ingress_qos_profile = T.ingress_qos_profile(self, self.device)
        self.ingress_qos_profile.hld_obj.set_qos_tag_mapping_enabled(True)
        self.topology.tx_l3_ac_reg.hld_obj.set_ingress_qos_profile(self.ingress_qos_profile.hld_obj)
        dscp = sdk.la_ip_dscp()
        dscp.value = 0
        self.ingress_qos_profile.hld_obj.set_meter_or_counter_offset_mapping(sdk.la_ip_version_e_IPV4, dscp, 1)
        self.ingress_qos_profile.hld_obj.set_meter_or_counter_offset_mapping(sdk.la_ip_version_e_IPV6, dscp, 1)

        # test setting DSCP by qos tag mapping
        self.ingress_qos_profile.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV4, self.IN_DSCP, self.TAG_IP_DSCP)
        self.ingress_qos_profile.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV6, self.IN_DSCP, self.TAG_IP_DSCP)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255,
                 tos=self.IN_TOS.flat) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_QOS_OVL_INPUT_IP / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            self.PORT_DECAP_QOS2_TAG_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          self.expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)
        # reset the ingress qos profile to the original one
        self.topology.tx_l3_ac_reg.hld_obj.set_ingress_qos_profile(
            self.topology.ingress_qos_profile_def.hld_obj)
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)

    def _test_ip_over_ip_tunnel_port_single_underlay_path(self):
        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            self.SINGLE_UNDERLAY_OVL_INPUT_IP / \
            S.TCP()

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=self.GRE_DIP.addr_str,
                 src=self.GRE_SIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.SINGLE_UNDERLAY_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

    def _test_gre_port_single_underlay_path(self):
        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            self.SINGLE_UNDERLAY_OVL_INPUT_IP / \
            S.TCP()

        if self.source_based_forwarding == self.SBF_TEST_ENABLED_WITH_MPLS:
            expected_gre_encap = S.GRE(proto=0x8847) / \
                MPLS(label=self.SBF_MPLS_LABEL, ttl=255)
        else:
            expected_gre_encap = self.GRE_HEADER

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=self.GRE_DIP.addr_str,
                 src=self.GRE_SIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            expected_gre_encap / \
            self.SINGLE_UNDERLAY_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        # inTTL 1 should be trapped
        input_packet = self.input_packet.copy()
        is_ipv4 = isinstance(self.SINGLE_UNDERLAY_OVL_INPUT_IP, type(S.IP()))
        if is_ipv4:
            input_packet[IP].ttl = 1
        else:
            input_packet[IPv6].hlim = 1

        tc = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_TTL_OR_HOP_LIMIT_IS_ONE, 0, tc, None, False, False, True, 0)
        U.run_and_drop(self, self.device,
                       input_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        trap_packet_count = 1
        packets, bytes = tc.read(0,  # sub-counter index
                                     True,  # force_update
                                     True)  # clear_on_read
        if decor.is_pacific() or decor.is_gibraltar():
            # check egress trap counter only or pacific or GB. per Himanshu
            self.assertEqual(packets, trap_packet_count)
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_TTL_OR_HOP_LIMIT_IS_ONE)

        # change the TTL
        self.gre_tunnel.set_ttl(254)

        expected_packet_base[IP].ttl = 254

        __, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        # disable inner TTL decrement
        self.gre_tunnel.set_decrement_inner_ttl(False)

        self.set_single_underlay_ovl_expected_inner_ttl(expected_packet_base, decrement=False)

        __, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        # re-enable inner TTL decrement
        self.gre_tunnel.set_decrement_inner_ttl(True)

        self.set_single_underlay_ovl_expected_inner_ttl(expected_packet_base, decrement=True)

        # change the DIP
        self.gre_tunnel.set_remote_ip_address(self.GRE_DIP1.hld_obj)

        expected_packet_base[IP].dst = self.GRE_DIP1.addr_str

        __, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)
        # change the SIP
        self.gre_tunnel.set_local_ip_address(self.GRE_SIP1.hld_obj)

        expected_packet_base[IP].src = self.GRE_SIP1.addr_str

        __, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        # change the underlay detination
        self.gre_destination.set_underlay_destination(self.topology.nh_l3_ac_ext.hld_obj)

        expected_packet_base[Ether].dst = T.NH_L3_AC_EXT_MAC.addr_str
        expected_packet_base[Ether].src = T.TX_L3_AC_EXT_MAC.addr_str

        __, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_EXT,
                          T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

        self.gre_test_overlay_full_mask()

    def _test_gre_port_encap_per_proto_counter(self):

        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            self.SINGLE_UNDERLAY_OVL_INPUT_IP / \
            S.TCP()

        if self.source_based_forwarding == self.SBF_TEST_ENABLED_WITH_MPLS:
            expected_gre_encap = S.GRE(proto=0x8847) / \
                MPLS(label=self.SBF_MPLS_LABEL, ttl=255)
        else:
            expected_gre_encap = self.GRE_HEADER

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=self.GRE_DIP.addr_str,
                 src=self.GRE_SIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            expected_gre_encap / \
            self.SINGLE_UNDERLAY_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        # tunnel interface per proto stats
        if (self.source_based_forwarding == self.SBF_TEST_ENABLED_WITH_MPLS):
            packet_count, byte_count = self.l3_egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
            self.assertEqual(packet_count, 1)
        else:
            is_ipv4 = isinstance(self.SINGLE_UNDERLAY_OVL_INPUT_IP, type(S.IP()))
            if is_ipv4:
                packet_count, byte_count = self.l3_egress_counter.read(sdk.la_l3_protocol_e_IPV4_UC, True, True)
                self.assertEqual(packet_count, 1)
            else:
                packet_count, byte_count = self.l3_egress_counter.read(sdk.la_l3_protocol_e_IPV6_UC, True, True)
                self.assertEqual(packet_count, 1)

        # egress interface stats
        packet_cnt, byte = self.egress_port_counter_reg.read(sdk.la_l3_protocol_e_IPV6_UC, True, True)
        self.assertEqual(packet_cnt, 0)
        packet_cnt, byte = self.egress_port_counter_reg.read(sdk.la_l3_protocol_e_IPV4_UC, True, True)
        self.assertEqual(packet_cnt, 1)

    def _test_gre_port_encap_mtu(self):
        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            self.SINGLE_UNDERLAY_OVL_INPUT_IP / \
            S.TCP()

        expected_gre_encap = self.GRE_HEADER

        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=self.GRE_DIP.addr_str,
                 src=self.GRE_SIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            expected_gre_encap / \
            self.SINGLE_UNDERLAY_OVL_EXPECTED_IP / \
            S.TCP()

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        eth_port = self.device.get_ethernet_port(T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)
        # get mtu of egress ethernet port
        o_mtu = eth_port.get_mtu()
        # set mtu on egress ethernet port
        mtu = len(self.expected_packet) - 10
        eth_port.set_mtu(mtu)
        n_mtu = eth_port.get_mtu()
        tc = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_TX_MTU_FAILURE, 0, tc, None, False, False, True, 0)
        U.run_and_drop(self, self.device,
                       self.input_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        trap_packet_count = 1
        # check if sdk.LA_EVENT_L3_TX_MTU_FAILURE trap got set
        packets, bytes = tc.read(0,  # sub-counter index
                                     True,  # force_update
                                     True)  # clear_on_read
        self.assertEqual(packets, trap_packet_count)
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_TX_MTU_FAILURE)

    # Test added to verify NPL padding fix on BO/A0 pacific
    # Idea is to make the output packet size < 60 bytes,
    # so that NPL padding will kick in
    def _test_gre_port_single_underlay_path_verify_padding(self):
        input_packet_base = \
            S.Ether(dst=self.OVL_IP_PACKET_DMAC,
                    src=self.OVL_IP_PACKET_SMAC) / \
            self.SINGLE_UNDERLAY_OVL_INPUT_IP
        expected_packet_base = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            S.IP(dst=self.GRE_DIP.addr_str,
                 src=self.GRE_SIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.SINGLE_UNDERLAY_OVL_EXPECTED_IP

        self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                          self.expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        packets, byte_count = self.l3_egress_counter.read(0, True, True)
        self.assertEqual(packets, 1)
        U.assertPacketLengthEgress(self, self.expected_packet, byte_count)

    def _test_gre_unsupported_protocol_decap(self):

        self.device.clear_trap_configuration(sdk.LA_EVENT_IPV4_UNKNOWN_PROTOCOL)
        self.device.set_trap_configuration(sdk.LA_EVENT_IPV4_UNKNOWN_PROTOCOL, 0, None, self.punt_dest, False, False, True, 0)
        self.input_packet = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 ttl=255) / \
            S.GRE(proto=0) / \
            S.IP(dst=self.OVL_IP_PACKET_SIP,
                 src=self.OVL_IP_PACKET_DIP,
                 ttl=63) / \
            S.TCP()

        punt_packet = \
            Ether(dst=self.HOST_MAC_ADDR, src=self.PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=self.PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=len(Ether()),
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_IPV4_UNKNOWN_PROTOCOL,
                   source_sp=self.PI_SP_GID_HEX,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=self.GRE_PORT_GID,
                   destination_lp=sdk.LA_EVENT_IPV4_UNKNOWN_PROTOCOL,
                   relay_id=self.punt_relay_id, lpts_flow_type=0) / \
            self.input_packet

        U.run_and_compare(self, self.device,
                          self.input_packet, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          punt_packet, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.device.clear_trap_configuration(sdk.LA_EVENT_IPV4_UNKNOWN_PROTOCOL)

    def _test_gre_port_decap_lpts(self):
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)
        # input_packet_base = \
        input_packet = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_OVL_INPUT_OSPF

        # expected_packet_base = \
        expected_packet = \
            Ether(dst=self.HOST_MAC_ADDR, src=self.PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=self.PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=len(Ether()) + len(IP()) + len(GRE()),
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
                   code=121,
                   source_sp=self.PI_SP_GID_HEX,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=self.GRE_PORT_GID,
                   destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
                   relay_id=T.VRF2_GID, lpts_flow_type=11) / \
            input_packet

        #self.input_packet, self.expected_packet = U.pad_input_and_output_packets(input_packet_base, expected_packet_base)

        U.run_and_compare(self, self.device,
                          input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          expected_packet, self.PI_SLICE,
                          self.PI_IFG, self.PI_PIF_FIRST)

    def _test_gre_port_decap_miss(self):
        # This packet hits on the my_ipv4_table but is not a tunnel packet
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_TUNNEL)

        input_packet = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.NON_TUNNEL_SIP,
                 id=0,
                 flags=2,
                 proto=1,
                 ttl=255) / \
            IPv6()

        expected_packet = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str,
                    src=self.NEW_TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.NON_TUNNEL_SIP,
                 id=0,
                 flags=2,
                 proto=1,
                 ttl=254) / \
            IPv6()

        U.run_and_compare(self, self.device,
                          input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3,
                          expected_packet, T.TX_SLICE_DEF,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3)

    def _test_gre_port_decap_ecmp(self, proto=sdk.la_l3_protocol_e_IPV4_UC, soft_lb=True):
        self.gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

        input_packet_base = \
            S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                    src=self.UNL_IP_PACKET_SMAC) / \
            S.IP(dst=self.GRE_SIP.addr_str,
                 src=self.GRE_DIP.addr_str,
                 id=0,
                 flags=2,
                 ttl=255) / \
            self.GRE_HEADER / \
            self.PORT_DECAP_OVL_INPUT_IP / \
            S.TCP()

        input_packet = U.add_payload(input_packet_base, self.PAYLOAD_SIZE)

        lb_vec_entry_list = []
        hw_lb_vec = sdk.la_lb_vector_t()
        hw_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP
        hw_lb_vec.ipv4.sip = T.ipv4_addr(input_packet[IP].src).to_num()
        hw_lb_vec.ipv4.dip = T.ipv4_addr(input_packet[IP].dst).to_num()
        hw_lb_vec.ipv4.protocol = input_packet[IP].proto
        lb_vec_entry_list.append(hw_lb_vec)

        soft_lb_vec = sdk.la_lb_vector_t()
        if proto == sdk.la_l3_protocol_e_IPV4_UC:
            soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
            soft_lb_vec.ipv4.sip = T.ipv4_addr(input_packet[GRE][IP].src).to_num()
            soft_lb_vec.ipv4.dip = T.ipv4_addr(input_packet[GRE][IP].dst).to_num()
            soft_lb_vec.ipv4.protocol = input_packet[GRE][IP].proto
            soft_lb_vec.ipv4.src_port = input_packet[TCP].sport
            soft_lb_vec.ipv4.dest_port = input_packet[TCP].dport
            lb_vec_entry_list.append(soft_lb_vec)
        elif proto == sdk.la_l3_protocol_e_IPV6_UC:
            soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV6_TCP_UDP
            soft_lb_vec.ipv6.sip = U.split_bits(T.ipv6_addr(input_packet[IPv6].src).to_num(), 32)
            soft_lb_vec.ipv6.dip = U.split_bits(T.ipv6_addr(input_packet[IPv6].dst).to_num(), 32)
            soft_lb_vec.ipv6.next_header = input_packet[IPv6].nh
            soft_lb_vec.ipv6.flow_label = input_packet[IPv6].fl
            soft_lb_vec.ipv6.src_port = input_packet[TCP].sport
            soft_lb_vec.ipv6.dest_port = input_packet[TCP].dport
            lb_vec_entry_list.append(soft_lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.ecmp_group, lb_vec_entry_list)

        expected_mac = out_dest_chain[0].downcast().get_mac().flat
        expected_mac_str = T.mac_addr.mac_num_to_str(expected_mac)

        expected_packet_base = \
            S.Ether(dst=expected_mac_str,
                    src=T.TX_L3_AC_REG_MAC.addr_str) / \
            self.PORT_DECAP_OVL_EXPECTED_IP / \
            S.TCP()

        expected_packet = U.add_payload(expected_packet_base, self.PAYLOAD_SIZE)

        U.run_and_compare(self, self.device,
                          input_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3,
                          expected_packet, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3)
