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

import unittest
from leaba import sdk
from packet_test_utils import *
import sim_utils
import topology as T
from scapy.all import *
import nplapicli as nplapi
import smart_slices_choise as ssch

import ip_test_base

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
SA = T.mac_addr('be:ef:5d:35:7a:35')

PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xA13
DSCP_VALUE = 0x30
TOS_VALUE = DSCP_VALUE << 2
SYS_PORT_GID_BASE = 23
IN_SP_GID = SYS_PORT_GID_BASE
OUT_SP_GID = SYS_PORT_GID_BASE + 1
INJECT_SP_GID = SYS_PORT_GID_BASE + 2
NPUH_SP_GID = SYS_PORT_GID_BASE + 3
NPUH_SP_GID_REMOTE = SYS_PORT_GID_BASE + 4
NH_GID = 0x619

INJECT_SLICE = 0
INGRESS_DEVICE_ID = 1
EGRESS_DEVICE_ID = 10

OUT_PUNT_PIF = T.PI_PIF + 1

SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

TTL = 255
MIN_RX_INTERVAL = 1000
MIN_TX_INTERVAL = 2000
MULTIPLIER = 5

# Single hop
LOCAL_DISCRIMINATOR = 5
REMOTE_DISCRIMINATOR = 99

# Multihop
LOCAL_MH_DISCRIMINATOR = 0x2000000c
REMOTE_MH_DISCRIMINATOR = 100

# Multihop - remote
LOCAL_MH_REMOTE_DISCRIMINATOR = 0x30000007
REMOTE_MH_REMOTE_DISCRIMINATOR = 107

INPUT_PACKET = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / \
    UDP(sport=0xc100, dport=3784) / \
    BFD(your_discriminator=LOCAL_DISCRIMINATOR, my_discriminator=REMOTE_DISCRIMINATOR)

INPUT_IPV6_MH_PACKET = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=255) / \
    IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / \
    UDP(sport=0xc100, dport=4784) / \
    BFD(your_discriminator=LOCAL_MH_DISCRIMINATOR, my_discriminator=REMOTE_MH_DISCRIMINATOR)

INPUT_MISS_PACKET = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / \
    UDP(sport=0xc100, dport=3784) / \
    BFD(your_discriminator=LOCAL_DISCRIMINATOR + 1, my_discriminator=REMOTE_DISCRIMINATOR)

OUTPUT_SH_PACKET = \
    Ether(dst=SA.addr_str, src=T.RX_L3_AC_MAC.addr_str) / \
    IPv6(src=DIP.addr_str, dst=SIP.addr_str, hlim=TTL, tc=TOS_VALUE) / \
    UDP(sport=49152, dport=3784) / \
    BFD(your_discriminator=REMOTE_DISCRIMINATOR, my_discriminator=LOCAL_DISCRIMINATOR,
        min_rx_interval=MIN_RX_INTERVAL, min_tx_interval=MIN_TX_INTERVAL, detect_mult=MULTIPLIER,
        state=sdk.la_bfd_state_e_INIT, flags='P', diag=sdk.la_bfd_diagnostic_code_e_FORWARDING_PLANE_RESET)

OUTPUT_MH_PACKET = \
    Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
    IPv6(src=DIP.addr_str, dst=SIP.addr_str, hlim=TTL, tc=TOS_VALUE) / \
    UDP(sport=49152, dport=4784) / \
    BFD(your_discriminator=REMOTE_MH_DISCRIMINATOR, my_discriminator=LOCAL_MH_DISCRIMINATOR,
        min_rx_interval=MIN_RX_INTERVAL, min_tx_interval=MIN_TX_INTERVAL, detect_mult=MULTIPLIER,
        state=sdk.la_bfd_state_e_INIT, flags='P', diag=sdk.la_bfd_diagnostic_code_e_FORWARDING_PLANE_RESET)


class bfd_ipv6_base(unittest.TestCase):
    PRIVATE_DATA = 0x1234567890abcdef

    PCI_PUNT_SLICE = 0
    PCI_IFG = 0

    PI_SLICE = 3
    PI_IFG = 1
    PI_PIF_FIRST = 8
    SYS_PORT_GID_BASE = 23
    PI_SP_GID = SYS_PORT_GID_BASE + 2
    LPTS_FLOW_TYPE = 11
    LPTS_PUNT_CODE = 120

    def create_lpts_instance(self, meter=None):
        lpts = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV6)
        self.assertNotEqual(lpts, None)

        # create a default entry for BFD session missed
        k0 = sdk.la_lpts_key()
        k0.type = sdk.lpts_type_e_LPTS_TYPE_IPV6

        k0.val.ipv6.protocol = sdk.la_l4_protocol_e_UDP
        k0.mask.ipv6.protocol = 0xff

        k0.val.ipv6.ports.dport = 3784
        k0.mask.ipv6.ports.dport = 0xffff

        result = sdk.la_lpts_result()
        result.flow_type = self.LPTS_FLOW_TYPE
        result.punt_code = self.LPTS_PUNT_CODE
        result.dest = self.cpu_punt_dest[0]
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)
        if meter is not None:
            result.meter = meter

        lpts.append(k0, result)

    def set_up_session(self, session_type, local_discr, remote_disc, local_address, remote_address, local_session=True):

        # Create the session on a remote NPU if its specified as a remote_session (local_session=False)
        # and we are not simulating this as a local_send (local_send = False)
        if local_session or self.local_send:
            destination = self.npu_host_destination
        else:
            destination = self.npu_host_destination_remote

        session = self.device.create_bfd_session(
            local_discr,
            session_type,
            sdk.la_l3_protocol_e_IPV6_UC,
            destination)

        session.set_traffic_class(7)
        in_tos = sdk.la_ip_tos()
        in_tos.fields.dscp = DSCP_VALUE
        in_tos.fields.ecn = 0x0
        session.set_ip_tos(in_tos)
        out_tos = session.get_ip_tos()
        self.assertNotEqual(out_tos, in_tos)

        session.set_local_address(local_address.hld_obj)

        session.set_remote_address(remote_address.hld_obj)
        session.set_remote_discriminator(remote_disc)
        session.set_intervals(MIN_TX_INTERVAL, MIN_RX_INTERVAL, MULTIPLIER)

        flags = sdk.la_bfd_flags()
        # Some non-zero values to test
        flags.fields.state = sdk.la_bfd_state_e_INIT
        flags.fields.poll = 1
        session.set_local_state(sdk.la_bfd_diagnostic_code_e_FORWARDING_PLANE_RESET, flags)

        counter = self.device.create_counter(2)
        session.set_counter(counter)
        return session

    def create_l3_destinations(self):
        self.m_nh_spa = T.next_hop(self, self.device, 0x220, self.s_nh_spa_mac, self.m_l3_ac_spa)
        self.m_nh = T.next_hop(self, self.device, 0x221, self.s_nh_mac, self.m_l3_ac)

    def create_npu_host_destination_remote(self):
        self.npu_host_port_remote = T.npu_host_port(self, self.device, EGRESS_DEVICE_ID, True, NPUH_SP_GID_REMOTE)
        self.npu_host_destination_remote = self.device.create_npu_host_destination(self.npu_host_port_remote.hld_obj)

    def create_npu_host_destination(self):
        self.npu_host_port = T.npu_host_port(self, self.device, self.device.get_id(), False, NPUH_SP_GID)
        self.npu_host_destination = self.device.create_npu_host_destination(self.npu_host_port.hld_obj)

    def create_routing_entry(self):
        prefix = self.ip_impl.build_prefix(SIP, length=48)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        # create a route for the NH
        prefix = self.ip_impl.build_prefix(self.s_sip, length=128)
        self.m_fec = T.fec(self, self.device, self.m_nh)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.m_fec, self.PRIVATE_DATA, True)

        # Create a route for the SIP pointing to the SPA interface
        prefix = self.ip_impl.build_prefix(self.s_ipv6_address_spa, length=128)
        self.m_fec_spa = T.fec(self, self.device, self.m_nh_spa)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.m_fec_spa, self.PRIVATE_DATA, True)

    def setup_local_label(self, add_lsp_counter=False):
        # Set a local label to point to the encap and the spa interface.
        self.out_label = sdk.la_mpls_label()
        self.out_label.label = 0xbad
        PREFIX1_GID = 100
        pfx_obj = T.prefix_object(self, self.device, PREFIX1_GID, self.m_nh_spa.hld_obj)

        lsp_counter = self.device.create_counter(1)
        lsp_labels = []
        pfx_obj.hld_obj.set_nh_lsp_properties(self.m_nh_spa.hld_obj, lsp_labels, lsp_counter,
                                              sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        lsr = self.device.get_lsr()
        lsr.add_route(self.out_label, pfx_obj.hld_obj, self.PRIVATE_DATA)
        # make sure the ttl of the outgoing packet works in uniform mode.
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)

    def setUp(self):
        self.maxDiff = None

        # Default some test config
        if not hasattr(self, "linecard_mode"):
            self.linecard_mode = False
        if not hasattr(self, "pci_test"):
            self.pci_test = False
        if not hasattr(self, "local_send"):
            self.local_send = True

        if not self.linecard_mode:
            self.device = sim_utils.create_device(INGRESS_DEVICE_ID)
        else:
            self.device = sim_utils.create_device(INGRESS_DEVICE_ID, slice_modes=sim_utils.LINECARD_3N_3F_DEV)

        ssch.rechoose_PI_slices(self, self.device)

        self.ip_impl = ip_test_base.ipv6_test_base()
        self.topology = T.topology(self, self.device)
        self.add_default_route()
        self.l3_port_impl_class = T.ip_svi_base
        self.l3_port_impl = self.l3_port_impl_class(self.topology)

        pi_port = self.topology.inject_ports[INJECT_SLICE]

        # Setup punt and trap
        if self.pci_test:
            # Setup punt and trap for PCI punt
            self.cpu_punt_port = self.topology.inject_ports[INJECT_SLICE]

        else:
            # Setup punt and trap for control ethernet punt
            self.cpu_punt_port = T.punt_inject_port(
                self,
                self.device,
                self.PI_SLICE,
                self.PI_IFG,
                self.PI_SP_GID,
                self.PI_PIF_FIRST,
                PUNT_INJECT_PORT_MAC_ADDR)

        # Create 4 punt destinations to test the oamp trap dest limit
        self.cpu_punt_dest = []
        for i in range(4):
            punt_dest = T.create_l2_punt_destination(
                self,
                self.device,
                T.L2_PUNT_DESTINATION2_GID + i,
                self.cpu_punt_port,
                HOST_MAC_ADDR,
                PUNT_VLAN + i)
            self.cpu_punt_dest.append(punt_dest)

        # create an LPTS entry for missed BFD packets
        self.create_lpts_instance()

        # Add to the topology to a LAG
        self.create_lag()
        self.create_vlan_port()
        self.create_inject_up_port()

        self.create_l3_destinations()
        self.create_npu_host_destination_remote()
        self.create_npu_host_destination()

        self.create_routing_entry()
        self.setup_local_label()

        # Setup counter and trap
        self.session_lookup_failed_counter = self.device.create_counter(1)
        self.device.set_trap_configuration(
            sdk.LA_EVENT_OAMP_BFD_SESSION_LOOKUP_FAILED,
            0,
            self.session_lookup_failed_counter,
            self.cpu_punt_dest[0],
            False,
            False,
            True, 0)

        self.state_change_counter = self.device.create_counter(1)
        self.device.set_trap_configuration(
            sdk.LA_EVENT_OAMP_BFD_STATE_FLAG_CHANGE,
            0,
            self.state_change_counter,
            self.cpu_punt_dest[1],
            False,
            False,
            True, 0)

        self.bfd_mismatch_counter = self.device.create_counter(1)
        self.device.set_trap_configuration(
            sdk.LA_EVENT_OAMP_BFD_MISMATCH_DISCR,
            0,
            self.bfd_mismatch_counter,
            self.cpu_punt_dest[2],
            False,
            False,
            True, 0)

        # Enable trap for bfd rx
        self.device.set_trap_configuration(
            sdk.LA_EVENT_OAMP_BFD_SESSION_RECEIVED,
            0,
            None,
            None,
            False,
            False,
            True, 0)

        # set MPLS ttl 0 to ignore inject up packets.
        self.mpls_ttl_zero_counter = self.device.create_counter(1)
        self.device.set_trap_configuration(
            sdk.LA_EVENT_MPLS_TTL_IS_ZERO,
            0,
            self.mpls_ttl_zero_counter,
            self.cpu_punt_dest[0],
            True,
            False,
            True, 0)

        # Enable MC traffic
        self.m_l3_ac_spa.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        # Disable the IPv4 redirect trap - this is needed for BFD echo
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_ICMP_REDIRECT)

        # Set the Inject up MAC address
        self.device.set_bfd_inject_up_mac_address(self.s_rx_mac_inject_up.hld_obj)

        self.single_hop_session = self.set_up_session(sdk.la_bfd_session.type_e_SINGLE_HOP,
                                                      LOCAL_DISCRIMINATOR,
                                                      REMOTE_DISCRIMINATOR,
                                                      DIP,
                                                      SIP)

        self.single_hop_session.set_l3_port(self.topology.rx_l3_ac.hld_obj)
        nh = T.next_hop(self, self.device, NH_GID, SA, self.topology.rx_l3_ac)
        self.single_hop_session.set_inject_down_destination(nh.hld_obj)

        # Test that set_inject_down_destination will return an error if NH type
        # is invalid, i.e. if it is not nh_type_e_NORMAL.
        NH_GLEAN_GID = 3
        NH_L3_AC_MAC = T.mac_addr('11:22:33:44:55:66')
        glean_nh = T.next_hop(self, self.device, NH_GLEAN_GID, NH_L3_AC_MAC, None, sdk.la_next_hop.nh_type_e_GLEAN)
        with self.assertRaises(sdk.InvalException):
            self.single_hop_session.set_inject_down_destination(glean_nh.hld_obj)

        self.multi_hop_session = self.set_up_session(sdk.la_bfd_session.type_e_MULTI_HOP,
                                                     LOCAL_MH_DISCRIMINATOR,
                                                     REMOTE_MH_DISCRIMINATOR,
                                                     local_address=DIP,
                                                     remote_address=SIP)
        self.multi_hop_session.set_inject_up_source_port(self.m_l3_ac_inject_up.hld_obj)

        # Set up micro session
        self.bfd_ipv6_micro_session = self.set_up_session(sdk.la_bfd_session.type_e_MICRO,
                                                          self.s_local_ipv6_micro_discriminator,
                                                          self.s_remote_ipv6_micro_discriminator,
                                                          local_address=self.s_ipv6_address_forus,
                                                          remote_address=self.s_ipv6_address_spa)
        self.bfd_ipv6_micro_session.set_inject_down_destination(self.m_nh_spa.hld_obj)
        # For micro BFD set the system port.
        self.bfd_ipv6_micro_session.set_system_port(self.m_sys_port2.hld_obj)

        # Set up BFD over Logical bundle
        self.bfd_ipv6_blb_session = self.set_up_session(sdk.la_bfd_session.type_e_SINGLE_HOP,
                                                        self.s_local_ipv6_blb_discriminator,
                                                        self.s_remote_ipv6_blb_discriminator,
                                                        local_address=self.s_ipv6_address_forus,
                                                        remote_address=self.s_ipv6_address_spa)

        self.bfd_ipv6_blb_session.set_inject_up_source_port(self.m_l3_ac_inject_up.hld_obj)
        self.bfd_ipv6_blb_session.set_l3_port(self.m_l3_ac_spa.hld_obj)

        # Set up BFD over Logical bundle with link local address
        self.bfd_ipv6_blb_ll_session = self.set_up_session(sdk.la_bfd_session.type_e_SINGLE_HOP,
                                                           self.s_local_ipv6_blb_ll_discriminator,
                                                           self.s_remote_ipv6_blb_ll_discriminator,
                                                           local_address=self.s_ipv6_address_forus_ll,
                                                           remote_address=self.s_ipv6_address_spa_ll)

        self.bfd_ipv6_blb_ll_session.set_inject_up_source_port(self.m_l3_ac_inject_up.hld_obj)
        self.bfd_ipv6_blb_ll_session.set_l3_port(self.m_l3_ac_spa.hld_obj)
        # Set the ttl to zero so that it gets decremented to 255. This is what gets written to the inner IP packet.
        self.bfd_ipv6_blb_ll_session.set_mpls_encap(self.out_label, 0)

        self.bfd_ipv4_remote_mh_session = self.set_up_session(sdk.la_bfd_session.type_e_MULTI_HOP,
                                                              LOCAL_MH_REMOTE_DISCRIMINATOR,
                                                              REMOTE_MH_REMOTE_DISCRIMINATOR,
                                                              self.s_ipv6_address_forus,
                                                              self.s_ipv6_address_spa,
                                                              local_session=False)
        self.setup_forus_dest()

        # Save the oq for the NPU host
        self.IPV6_MH_OVER_FABRIC.dest_oq = self.device.get_oq_num(self.PI_IFG, self.device.get_pci_serdes()) + self.BFD_TC_VALUE

    def tearDown(self):
        self.device.clear_trap_configuration(sdk.LA_EVENT_OAMP_BFD_STATE_FLAG_CHANGE)
        self.device.clear_trap_configuration(sdk.LA_EVENT_OAMP_BFD_MISMATCH_DISCR)
        self.device.clear_trap_configuration(sdk.LA_EVENT_OAMP_BFD_SESSION_RECEIVED)
        self.device.tearDown()

    def add_default_route(self):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x0
        prefix.length = 0
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.topology.nh_l3_ac_def.hld_obj, PRIVATE_DATA_DEFAULT, False)
        self.has_default_route = True

    def destroy_default_route(self):
        if self.has_default_route:
            prefix = sdk.la_ipv4_prefix_t()
            prefix.addr.s_addr = 0x0
            prefix.length = 0
            self.topology.vrf.hld_obj.delete_ipv4_route(prefix)
            self.has_default_route = False

    def setup_forus_dest(self):

        self.prefix_uc = self.ip_impl.build_prefix(DIP, length=96)
        self.ip_impl.add_route(self.topology.vrf, self.prefix_uc,
                               self.topology.forus_dest,
                               PRIVATE_DATA_DEFAULT)
        # Create a route for forus address
        prefix = self.ip_impl.build_prefix(self.s_ipv6_address_forus, length=128)
        self.ip_impl.add_route(self.topology.vrf, prefix,
                               self.topology.forus_dest,
                               PRIVATE_DATA_DEFAULT, True)
        # create a forus entry for link local addresses
        link_local = T.ipv6_addr('fe80:0000:0000:0000:0000:0000:0000:0000')
        prefix = self.ip_impl.build_prefix(link_local, length=10)
        self.ip_impl.add_route(self.topology.vrf, prefix,
                               self.topology.forus_dest,
                               PRIVATE_DATA_DEFAULT)

    def cleanup_forus_dest(self):
        self.ip_impl.delete_route(self.topology.vrf, self.prefix_uc)

    # JWB FIXME - Need to create the inject up port on the inject system port
    def create_inject_up_port(self):
        # create mac port
        self.m_mac_port_inject_up = T.mac_port(
            self,
            self.device,
            self.s_rx_slice_inject_up,
            self.s_rx_ifg_inject_up,
            self.s_serdes_inject_up_1st,
            self.s_serdes_inject_up_last)

        # create system port
        self.m_sys_port_inject_up = T.system_port(self, self.device, self.s_sys_iup_gid, self.m_mac_port_inject_up)

        # create ethernet port
        self.m_eth_port_inject_up = T.sa_ethernet_port(self, self.device, self.m_sys_port_inject_up)

        self.m_l3_ac_inject_up = T.l3_ac_port(self,
                                              self.device,
                                              self.s_l3_ac_iup_gid,
                                              self.m_eth_port_inject_up,
                                              self.topology.vrf,
                                              self.s_rx_mac_inject_up,
                                              self.s_vlan_inject_up,
                                              0)

        # Set the vlan for the tx side for l3 ac
        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0x8100
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = self.s_vlan_inject_up

        self.m_l3_ac_inject_up.hld_obj.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)
        self.m_l3_ac_inject_up.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.m_l3_ac_inject_up.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

    def create_vlan_port(self):
        # create mac port
        self.m_mac_port3 = T.mac_port(
            self,
            self.device,
            self.s_rx_slice,
            self.s_rx_ifg,
            self.s_first_serdes_p3,
            self.s_last_serdes_p3)

        # create system port
        self.m_sys_port3 = T.system_port(self, self.device, self.s_sys_p3_gid, self.m_mac_port3)

        # create ethernet port
        self.m_eth_port = T.sa_ethernet_port(self, self.device, self.m_sys_port3)

        self.m_l3_ac = T.l3_ac_port(self,
                                    self.device,
                                    self.s_l3_ac_gid,
                                    self.m_eth_port,
                                    self.topology.vrf,
                                    self.s_rx_mac,
                                    self.s_vlan1,
                                    0)

        # Set the vlan for the tx side for l3 ac
        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0x8100
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = self.s_vlan1

        self.m_l3_ac.hld_obj.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

        self.m_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.m_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

    def create_lag(self):
        # create mac port 1
        self.m_mac_port1 = T.mac_port(
            self,
            self.device,
            self.s_rx_slice,
            self.s_rx_ifg,
            self.s_first_serdes_p1,
            self.s_last_serdes_p1)

        # create system port1
        self.m_sys_port1 = T.system_port(self, self.device, self.s_sys_p1_gid, self.m_mac_port1)

        # create mac port 2
        self.m_mac_port2 = T.mac_port(
            self,
            self.device,
            self.s_rx_slice,
            self.s_rx_ifg,
            self.s_first_serdes_p2,
            self.s_last_serdes_p2)
        self.m_sys_port2 = T.system_port(self, self.device, self.s_sys_p2_gid, self.m_mac_port2)

        # create the spa port
        self.m_spa_port = T.spa_port(self, self.device, self.s_spa_gid)

        # attach sys port 1 and 2 to the LAG
        self.m_spa_port.add(self.m_sys_port1)
        self.m_spa_port.add(self.m_sys_port2)

        # create ethernet port
        self.m_spa_eth_port = T.sa_ethernet_port(self, self.device, self.m_spa_port)

        self.m_l3_ac_spa = T.l3_ac_port(self,
                                        self.device,
                                        self.s_l3_ac_spa_gid,
                                        self.m_spa_eth_port,
                                        self.topology.vrf,
                                        self.s_rx_mac)
        self.m_l3_ac_spa.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.m_l3_ac_spa.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

    def calculate_expected_output(self, input_packet, local_label=False):
        dip = T.ipv6_addr(input_packet[IPv6].dst).hld_obj.d_addr
        sip = T.ipv6_addr(input_packet[IPv6].src).hld_obj.d_addr

        lb_vec_entry_list = []

        if local_label:
            hw_lb_vec = sdk.la_lb_vector_t()
            hw_lb_vec.type = sdk.LA_LB_VECTOR_MPLS
            hw_lb_vec.mpls.label = [self.out_label.label, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            hw_lb_vec.mpls.num_valid_labels = 1
            lb_vec_entry_list.append(hw_lb_vec)

            soft_lb_vec = sdk.la_lb_vector_t()
            soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV6_TCP_UDP
            soft_lb_vec.ipv6.sip = sip
            soft_lb_vec.ipv6.dip = dip
            soft_lb_vec.ipv6.next_header = input_packet[IPv6].nh
            soft_lb_vec.ipv6.flow_label = input_packet[IPv6].fl
            soft_lb_vec.ipv6.src_port = input_packet[UDP].sport
            soft_lb_vec.ipv6.dest_port = input_packet[UDP].dport
            lb_vec_entry_list.append(soft_lb_vec)
        else:
            lb_vec = sdk.la_lb_vector_t()
            lb_vec.type = sdk.LA_LB_VECTOR_IPV6_TCP_UDP
            lb_vec.ipv6.sip = sip
            lb_vec.ipv6.dip = dip
            lb_vec.ipv6.next_header = input_packet[IPv6].nh
            lb_vec.ipv6.flow_label = input_packet[IPv6].fl
            lb_vec.ipv6.src_port = input_packet[UDP].sport
            lb_vec.ipv6.dest_port = input_packet[UDP].dport
            lb_vec_entry_list.append(lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(self.m_nh_spa.hld_obj, lb_vec_entry_list)

        self.assertEqual(out_dest_chain[-1].type(), sdk.la_object.object_type_e_SYSTEM_PORT)
        out_dsp = out_dest_chain[-1].downcast()

        out_slice = out_dsp.get_slice()
        out_ifg = out_dsp.get_ifg()
        out_pif = out_dsp.get_base_serdes()

        return out_slice, out_ifg, out_pif

    # static members
    # Remote mac
    s_nh_spa_mac = T.mac_addr('1c:f5:7d:e9:61:eb')
    s_nh_mac = T.mac_addr('1c:f5:7d:e9:61:ef')

    # Local mac
    s_rx_mac = T.mac_addr('84:20:75:3e:8c:05')
    s_rx_micro_mac = T.mac_addr('01:00:5e:90:00:01')

    s_local_ipv6_micro_discriminator = 200
    s_remote_ipv6_micro_discriminator = 300
    s_local_ipv6_blb_discriminator = 201
    s_remote_ipv6_blb_discriminator = 301

    s_local_ipv6_blb_ll_discriminator = 202
    s_remote_ipv6_blb_ll_discriminator = 302

    s_sip = T.ipv6_addr('1222:0db8:0a0b:12f0:0000:0000:0000:2222')
    s_ipv6_address_forus = T.ipv6_addr('4202:0db8:0a0b:12f0:0000:ffff:0000:2222')
    s_ipv6_address_spa = T.ipv6_addr('3222:0db8:0a0b:12f0:ffff:0000:ffff:2222')

    s_ipv6_address_forus_ll = T.ipv6_addr('fe80:0db8:0a0b:12f0:0000:ffff:0000:2222')
    s_ipv6_address_spa_ll = T.ipv6_addr('fe80:0db8:0a0b:12f0:ffff:0000:ffff:2222')

    s_rx_slice = 0
    s_rx_ifg = 0
    s_first_serdes_p1 = T.LAST_SERDES_L3 + 1
    s_last_serdes_p1 = s_first_serdes_p1 + 1
    s_first_serdes_p2 = s_last_serdes_p1 + 1
    s_last_serdes_p2 = s_first_serdes_p2 + 1
    s_first_serdes_p3 = s_last_serdes_p2 + 1
    s_last_serdes_p3 = s_first_serdes_p3 + 1
    s_vlan1 = 0xaaa

    # Inject Up parameters
    s_rx_mac_inject_up = T.mac_addr('11:12:13:14:15:16')
    s_rx_slice_inject_up = 2
    s_rx_ifg_inject_up = 0
    s_vlan_inject_up = 0x123
    s_serdes_inject_up_1st = s_last_serdes_p3 + 1
    s_serdes_inject_up_last = s_serdes_inject_up_1st + 1
    s_sys_iup_gid = 0x48
    s_l3_ac_iup_gid = 0x49

    # GID
    s_sys_p1_gid = 0x41
    s_sys_p2_gid = 0x42
    s_sys_p3_gid = 0x43
    s_l3_ac_spa_gid = 0x44
    s_l3_ac_gid = 0x45
    s_l3_ac_new_gid = 0x46
    s_spa_gid = 0x51

    INPUT_IPV6_MICRO_PACKET = \
        Ether(dst=s_rx_micro_mac.addr_str, src=s_nh_spa_mac.addr_str) / \
        IPv6(src=s_ipv6_address_spa.addr_str, dst=s_ipv6_address_forus.addr_str, hlim=255) / \
        UDP(sport=0xc100, dport=6784) / \
        BFD(your_discriminator=s_local_ipv6_micro_discriminator, my_discriminator=s_remote_ipv6_micro_discriminator)

    OUTPUT_IPV6_MICRO_PACKET = \
        Ether(dst=s_nh_spa_mac.addr_str, src=s_rx_mac.addr_str) / \
        IPv6(src=s_ipv6_address_forus.addr_str, dst=s_ipv6_address_spa.addr_str, hlim=255, tc=TOS_VALUE) / \
        UDP(sport=49152, dport=6784) / \
        BFD(your_discriminator=s_remote_ipv6_micro_discriminator, my_discriminator=s_local_ipv6_micro_discriminator,
            min_rx_interval=MIN_RX_INTERVAL, min_tx_interval=MIN_TX_INTERVAL, detect_mult=MULTIPLIER,
            state=sdk.la_bfd_state_e_INIT, flags='P', diag=sdk.la_bfd_diagnostic_code_e_FORWARDING_PLANE_RESET)

    INPUT_IPV6_BLB_LL_PACKET = \
        Ether(dst=s_rx_mac.addr_str, src=s_nh_spa_mac.addr_str) / \
        IPv6(src=s_ipv6_address_spa_ll.addr_str, dst=s_ipv6_address_forus_ll.addr_str, hlim=255) / \
        UDP(sport=0xc100, dport=3784) / \
        BFD(your_discriminator=s_local_ipv6_blb_ll_discriminator, my_discriminator=s_remote_ipv6_blb_ll_discriminator)

    OUTPUT_IPV6_BLB_LL_PACKET = \
        Ether(dst=s_nh_spa_mac.addr_str, src=s_rx_mac.addr_str) / \
        IPv6(src=s_ipv6_address_forus_ll.addr_str, dst=s_ipv6_address_spa_ll.addr_str, hlim=255, tc=TOS_VALUE) / \
        UDP(sport=49152, dport=3784) / \
        BFD(your_discriminator=s_remote_ipv6_blb_ll_discriminator, my_discriminator=s_local_ipv6_blb_ll_discriminator,
            min_rx_interval=MIN_RX_INTERVAL, min_tx_interval=MIN_TX_INTERVAL, detect_mult=MULTIPLIER,
            state=sdk.la_bfd_state_e_INIT, flags='P', diag=sdk.la_bfd_diagnostic_code_e_FORWARDING_PLANE_RESET)

    INPUT_IPV6_BLB_PACKET = \
        Ether(dst=s_rx_mac.addr_str, src=s_nh_spa_mac.addr_str) / \
        IPv6(src=s_ipv6_address_spa.addr_str, dst=s_ipv6_address_forus.addr_str, hlim=255) / \
        UDP(sport=0xc100, dport=3784) / \
        BFD(your_discriminator=s_local_ipv6_blb_discriminator, my_discriminator=s_remote_ipv6_blb_discriminator)

    OUTPUT_IPV6_BLB_PACKET = \
        Ether(dst=s_nh_spa_mac.addr_str, src=s_rx_mac.addr_str) / \
        IPv6(src=s_ipv6_address_forus.addr_str, dst=s_ipv6_address_spa.addr_str, hlim=255, tc=TOS_VALUE) / \
        UDP(sport=49152, dport=3784) / \
        BFD(your_discriminator=s_remote_ipv6_blb_discriminator, my_discriminator=s_local_ipv6_blb_discriminator,
            min_rx_interval=MIN_RX_INTERVAL, min_tx_interval=MIN_TX_INTERVAL, detect_mult=MULTIPLIER,
            state=sdk.la_bfd_state_e_INIT, flags='P', diag=sdk.la_bfd_diagnostic_code_e_FORWARDING_PLANE_RESET)

    INPUT_IPV6_BLB_SWITCH_PACKET = \
        Ether(dst=s_rx_mac.addr_str, src=s_nh_spa_mac.addr_str) / \
        IPv6(src=s_ipv6_address_spa.addr_str, dst=s_ipv6_address_spa.addr_str, hlim=TTL) / \
        UDP(sport=0xc100, dport=3784) / \
        BFD(your_discriminator=s_local_ipv6_blb_discriminator, my_discriminator=s_remote_ipv6_blb_discriminator)

    OUTPUT_IPV6_BLB_SWITCH_PACKET = \
        Ether(dst=s_nh_spa_mac.addr_str, src=s_rx_mac.addr_str) / \
        IPv6(src=s_ipv6_address_spa.addr_str, dst=s_ipv6_address_spa.addr_str, hlim=TTL - 1) / \
        UDP(sport=0xc100, dport=3784) / \
        BFD(your_discriminator=s_local_ipv6_blb_discriminator, my_discriminator=s_remote_ipv6_blb_discriminator)

    INPUT_IPV6_SH_MISMATCH_DISC_PACKET = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / \
        UDP(sport=0xc100, dport=3784) / \
        BFD(your_discriminator=LOCAL_DISCRIMINATOR, my_discriminator=REMOTE_DISCRIMINATOR + 1)

    PUNT_PACKET_IPV6_SH_MISMATCH_DISC_PACKET = \
        Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=PUNT_VLAN + 2, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
             fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
             next_header_offset=0,
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_NPUH,
             code=sdk.LA_EVENT_OAMP_BFD_MISMATCH_DISCR,
             source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
             relay_id=T.VRF_GID, lpts_flow_type=0) / \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / \
        UDP(sport=0xc100, dport=3784) / \
        BFD(your_discriminator=LOCAL_DISCRIMINATOR, my_discriminator=REMOTE_DISCRIMINATOR + 1)

    PUNT_PACKET_IPV6_MICRO_DISABLE_IP_PACKET = \
        Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=PUNT_VLAN + 3, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
             fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
             next_header_offset=14,
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
             code=sdk.LA_EVENT_L3_BFD_MICRO_IP_DISABLED,
             source_sp=s_sys_p2_gid, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             source_lp=s_l3_ac_new_gid, destination_lp=sdk.LA_EVENT_L3_BFD_MICRO_IP_DISABLED,
             relay_id=0, lpts_flow_type=0) / \
        Ether(dst=s_rx_micro_mac.addr_str, src=s_nh_spa_mac.addr_str) / \
        IPv6(src=s_ipv6_address_spa.addr_str, dst=s_ipv6_address_forus.addr_str, hlim=255) / \
        UDP(sport=0xc100, dport=6784) / \
        BFD(your_discriminator=s_local_ipv6_micro_discriminator, my_discriminator=s_remote_ipv6_micro_discriminator)

    INPUT_IPV6_SH_FLAG_CHANGE_PACKET = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / \
        UDP(sport=0xc100, dport=3784) / \
        BFD(state=sdk.la_bfd_state_e_INIT, flags='P', your_discriminator=LOCAL_DISCRIMINATOR, my_discriminator=REMOTE_DISCRIMINATOR)

    PUNT_PACKET_IPV6_SH_FLAG_CHANGE = \
        Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=PUNT_VLAN + 1, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
             fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
             next_header_offset=0,
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_NPUH,
             code=sdk.LA_EVENT_OAMP_BFD_STATE_FLAG_CHANGE,
             source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
             relay_id=T.VRF_GID, lpts_flow_type=0) / \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / \
        UDP(sport=0xc100, dport=3784) / \
        BFD(state=sdk.la_bfd_state_e_INIT, flags='P', your_discriminator=LOCAL_DISCRIMINATOR, my_discriminator=REMOTE_DISCRIMINATOR)

    PUNT_PACKET_IPV6_SESSION_MISS = \
        Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
             fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
             next_header_offset=0,
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_NPUH,
             code=sdk.LA_EVENT_OAMP_BFD_SESSION_LOOKUP_FAILED,
             source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
             relay_id=T.VRF_GID, lpts_flow_type=0) / \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=TTL) / \
        UDP(sport=0xc100, dport=3784) / \
        BFD(your_discriminator=LOCAL_DISCRIMINATOR + 1, my_discriminator=REMOTE_DISCRIMINATOR)

    INPUT_IPV6_REMOTE_MULTIHOP_PACKET = \
        Ether(dst=s_rx_mac.addr_str, src=s_nh_spa_mac.addr_str) / \
        IPv6(src=s_ipv6_address_spa.addr_str, dst=s_ipv6_address_forus.addr_str, hlim=TTL) / \
        UDP(sport=0xc100, dport=4784) / \
        BFD(state=sdk.la_bfd_state_e_UP, flags='P',
            your_discriminator=LOCAL_MH_REMOTE_DISCRIMINATOR, my_discriminator=REMOTE_MH_REMOTE_DISCRIMINATOR)

    PUNT_PACKET_IPV6_REMOTE_MH_FLAG_CHANGE = \
        Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=PUNT_VLAN + 1, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
             fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
             next_header_offset=0,
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_NPUH,
             code=sdk.LA_EVENT_OAMP_BFD_STATE_FLAG_CHANGE,
             source_sp=s_sys_p2_gid, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             source_lp=s_l3_ac_spa_gid, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
             relay_id=T.VRF_GID, lpts_flow_type=0) / \
        INPUT_IPV6_REMOTE_MULTIHOP_PACKET

    BFD_TC_VALUE = 7

    IPV6_MH_OVER_FABRIC = \
        TS_PLB(header_type="ONE_PKT_TS3",
               link_fc=0,
               fcn=0,
               plb_context="UC_L",
               ts3=[0, 0, 0],
               src_device=INGRESS_DEVICE_ID,
               src_slice=s_rx_slice,
               reserved=0) / \
        TM(header_type="UUU_DD",
           vce=0,
           tc=BFD_TC_VALUE,
           dp=0,
           reserved=0,
           dest_device=EGRESS_DEVICE_ID,
           dest_slice=0) / \
        NPU_Header_ext(
            base_type=1,
            fwd_header_type=15,
            slp_qos_id=15,
            fwd_offset=40,
            encap_type=14,
            encap=0x800e00040000fee06,
            punt_mc_expand_encap=0x800e,
            ipv4_first_fragment=1,
            ttl=255,
            fwd_slp_info=1088,
            fwd_relay_id=T.VRF_GID) / \
        NPU_Soft_Header(
            unparsed_0=0xcf042) / \
        INPUT_IPV6_REMOTE_MULTIHOP_PACKET
