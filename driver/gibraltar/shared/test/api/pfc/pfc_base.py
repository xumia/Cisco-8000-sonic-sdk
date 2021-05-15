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

import unittest
from leaba import sdk
from packet_test_utils import *
from scapy.all import *
import topology as T
import ip_test_base
import pdb
import nplapicli
import smart_slices_choise as ssch

from pfc_common import *

INJECT_SLICE = 0
INGRESS_DEVICE_ID = 1

EGRESS_DEVICE_ID = 10

PCP_VALUE = 3
PCPDEI_VALUE = (PCP_VALUE << 1)
TC_SHIFT_VALUE = 12
DEST_VALUE = 0x42
DEST_VALUE_REMOTE = 0x1c

SYS_PORT_GID_BASE = 23
PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xA13
MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
PFC_PILOT_MIRROR_GID = 28 + MIRROR_GID_INGRESS_OFFSET
PFC_MEASUREMENT_GID = 29 + MIRROR_GID_INGRESS_OFFSET
NF_MIRROR_CMD_GID = 10 + MIRROR_GID_INGRESS_OFFSET
MIRROR_VLAN = 0xA12
PUNT_SLICE = 2  # must be even numbered slice
INJECT_SLICE = 0
PUNT_PIF_FIRST = 8
PUNT_PIF_LAST = PUNT_PIF_FIRST
NPUH_SP_GID = SYS_PORT_GID_BASE + 3
NPUH_SP_GID_REMOTE = SYS_PORT_GID_BASE + 4
TTL = 255

EGRESS_TX_SLICE = 2
EGRESS_TX_IFG = 0
EGRESS_TX_SERDES_FIRST = 16
EGRESS_TX_SERDES_LAST = EGRESS_TX_SERDES_FIRST + 1
EGRESS_SYS_PORT_GID = 0x1c

NH_GID_1 = 0x221
NH_GID_2 = 0x223


class pfc_base(unittest.TestCase):
    PI_SLICE = 3
    PI_IFG = 1
    PI_PIF_FIRST = 8
    PI_SP_GID = SYS_PORT_GID_BASE + 2
    PRIVATE_DATA = 0x1234567890abcdef

    def set_pfc_congestion_table(self, dest, tc, cong, slice):
        table = self.device.get_device_tables().em_pfc_cong_table[0]
        key = nplapicli.npl_em_pfc_cong_table_key_t()
        key.dsp1 = dest
        key.dsp2 = dest
        key.dsp3 = dest
        key.dsp4 = dest
        key.tc = tc
        key.slice = slice
        if cong:
            value = nplapicli.npl_em_pfc_cong_table_value_t()
            value.payloads.em_payload.pfc.rmep_id = 0
            value.payloads.em_payload.pfc.mep_id = 0
            value.payloads.em_payload.pfc.access_rmep = 0
            value.payloads.em_payload.pfc.access_mp = 0
            value.payloads.em_payload.pfc.mp_data_select = 0
            table.set(key, value)
        else:
            table.erase(key)

    def find_voq_set(self, sys_port_id):
        found = False
        sys_ports = self.device.get_objects(sdk.la_object.object_type_e_SYSTEM_PORT)
        for sys_port in sys_ports:
            if sys_port.get_gid() == sys_port_id:
                found = True
                break
        if not found:
            return None
        return sys_port.get_voq_set()

    def lower_pfc_sampling_rate(self):
        # configure to smaller probability - 1% = 10/1000
        self.device.set_int_property(sdk.la_device_property_e_PACIFIC_PFC_MEASUREMENT_PROBABILITY, 10)

    def create_routing_entry(self):
        # create a route for the NH
        prefix = self.ip_impl.build_prefix(self.s_dip, length=32)
        self.m_fec = T.fec(self, self.device, self.m_nh)
        self.ip_impl.add_route(self.topology.global_vrf, prefix, self.m_fec, self.PRIVATE_DATA, True)

    def create_l3_destinations(self):
        self.m_nh = T.next_hop(self, self.device, NH_GID_1, self.s_nh_mac, self.m_l3_ac_p2)

    def create_remote_port(self):
        # Create remote port
        remote_port = T.remote_port(
            self,
            self.device,
            EGRESS_DEVICE_ID,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_TX_SERDES_FIRST,
            EGRESS_TX_SERDES_LAST)

        # Create remote system port above the remote port
        remote_sys_port = T.system_port(self, self.device, EGRESS_SYS_PORT_GID, remote_port)

        # Create remote ethernet port above the remote system port
        self.remote_eth_port = T.sa_ethernet_port(self, self.device, remote_sys_port)

        # Create remote AC port above the remote ethernet
        self.m_l3_ac_remote = T.l3_ac_port(self,
                                           self.device,
                                           self.s_l3_ac_gid + 10,
                                           self.remote_eth_port,
                                           self.topology.global_vrf,
                                           self.s_rx_mac_remote,
                                           self.s_vlan1,
                                           0)
        self.m_nh_remote = T.next_hop(self, self.device, NH_GID_2, self.s_rx_mac_remote, self.m_l3_ac_remote)
        prefix = self.ip_impl.build_prefix(self.s_dip_remote, length=32)
        self.m_fec_remote = T.fec(self, self.device, self.m_nh_remote)
        self.ip_impl.add_route(self.topology.global_vrf, prefix, self.m_fec_remote, self.PRIVATE_DATA, True)

    def create_vlan_port(self):
        # create mac port
        self.m_mac_port = T.mac_port(
            self,
            self.device,
            self.s_rx_slice,
            self.s_rx_ifg,
            self.s_first_serdes_p1,
            self.s_last_serdes_p1)

        # create mac port
        self.m_mac_port_p2 = T.mac_port(
            self,
            self.device,
            self.s_tx_slice,
            self.s_tx_ifg,
            self.s_first_serdes_p2,
            self.s_last_serdes_p2)

        # create system port
        self.m_sys_port = T.system_port(self, self.device, self.s_sys_p1_gid, self.m_mac_port)
        self.m_sys_port_p2 = T.system_port(self, self.device, self.s_sys_p2_gid, self.m_mac_port_p2)

        # create ethernet port
        self.m_eth_port = T.sa_ethernet_port(self, self.device, self.m_sys_port)
        self.m_eth_port_p2 = T.sa_ethernet_port(self, self.device, self.m_sys_port_p2)

        self.m_l3_ac = T.l3_ac_port(self,
                                    self.device,
                                    self.s_l3_ac_gid,
                                    self.m_eth_port,
                                    self.topology.global_vrf,
                                    self.s_rx_mac,
                                    self.s_vlan1,
                                    0)

        self.m_l3_ac_p2 = T.l3_ac_port(self,
                                       self.device,
                                       self.s_l3_ac_p2_gid,
                                       self.m_eth_port_p2,
                                       self.topology.global_vrf,
                                       self.s_rx_mac,
                                       self.s_vlan2,
                                       0)

        # Set the vlan for the tx side for l3 ac
        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0x8100
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = self.s_vlan1

        self.m_l3_ac.hld_obj.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

        # Set the vlan for the tx side for l3 ac
        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0x8100
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = self.s_vlan2

        self.m_l3_ac_p2.hld_obj.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

        self.m_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.m_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

        self.m_l3_ac_p2.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.m_l3_ac_p2.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

    def create_npu_host_destination_remote(self):
        self.npu_host_port_remote = T.npu_host_port(self, self.device, EGRESS_DEVICE_ID, True, NPUH_SP_GID_REMOTE)
        self.npu_host_destination_remote = self.device.create_npu_host_destination(self.npu_host_port_remote.hld_obj)

    def setup_forus_dest(self):
        self.prefix_uc = self.ip_impl.build_prefix(DIP, length=24)
        self.ip_impl.add_route(self.topology.global_vrf, self.prefix_uc,
                               self.topology.forus_dest,
                               PRIVATE_DATA_DEFAULT)

    def create_meter_set(self, set_size, cir, eir, slice_id, ifg):
        meter_type = sdk.la_meter_set.type_e_PER_IFG_EXACT
        meter = self.device.create_meter(meter_type, set_size)
        meter_profile = self.topology.per_ifg_meter_profile_def
        meter_action_profile = self.topology.meter_action_profile_def

        slice_ifg = sdk.la_slice_ifg()
        slice_ifg.slice = slice_id
        slice_ifg.ifg = ifg

        # Configure
        for meter_index in range(set_size):
            meter.set_committed_bucket_coupling_mode(meter_index, sdk.la_meter_set.coupling_mode_e_TO_EXCESS_BUCKET)
            meter.set_meter_action_profile(meter_index, meter_action_profile)
            meter.set_meter_profile(meter_index, meter_profile)
            meter.set_cir(meter_index, slice_ifg, cir)
            meter.set_eir(meter_index, slice_ifg, eir)
        return meter

    def create_mirror(self, gid):
        sampling_rate = 1.0
        HOST_MAC_ADDR1 = T.mac_addr('cd:cd:cd:cd:cd:cd')
        mirror_cmd = T.create_l2_mirror_command(
            self.device,
            gid,
            self.pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN,
            sampling_rate)

    def sw_pfc_init(self):
        # Enable PFC at input port
        METER_SET_SIZE = 8
        # Meter must be hardcoded to IFG 1
        self.pfc_tx_meter = self.create_meter_set(METER_SET_SIZE, 90, 180, self.s_rx_slice, 1)
        self.pfc_rx_counter = self.device.create_counter(METER_SET_SIZE)

        mac_port = self.m_mac_port.hld_obj
        mac_port.set_pfc_enable(0)
        mac_port.set_pfc_counter(self.pfc_rx_counter)
        mac_port.set_pfc_meter(self.pfc_tx_meter)
        mac_port.set_pfc_quanta(100)

        # Enable SW-base PFC on the dest port.
        dest_mac_port = self.m_mac_port_p2.hld_obj
        meter = self.create_meter_set(METER_SET_SIZE, 90, 180, self.s_tx_slice, 1)
        counter = self.device.create_counter(METER_SET_SIZE)
        dest_mac_port.set_pfc_enable(0)
        dest_mac_port.set_pfc_counter(counter)
        dest_mac_port.set_pfc_meter(meter)
        self.device.set_sw_fc_pause_threshold(TC_VALUE, 800)

    def setUp(self):
        self.maxDiff = None

        if self.create_standalone:
            self.device = sim_utils.create_device(INGRESS_DEVICE_ID)
        else:
            self.device = sim_utils.create_device(INGRESS_DEVICE_ID, slice_modes=sim_utils.LINECARD_3N_3F_DEV)
            if not T.can_be_used_as_fabric(self.device):
                self.skipTest("This device cannot be used in LINECARD and FABRIC modes. Thus, this test is irrelevant.")
                return

        ssch.rechoose_PI_slices(self, self.device)

        self.device.set_bool_property(sdk.la_device_property_e_ENABLE_PACIFIC_SW_BASED_PFC, True)

        self.ip_impl = ip_test_base.ipv4_test_base()
        self.topology = T.topology(self, self.device)

        self.create_vlan_port()
        self.create_l3_destinations()
        self.create_remote_port()
        self.create_npu_host_destination_remote()
        self.create_npu_host_destination()
        self.create_routing_entry()

        self.pi_port = self.topology.inject_ports[INJECT_SLICE]
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

        self.cpu_punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.cpu_punt_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)

        # Punt to the CPU if we get a PFC packet but PFC is not enabled for that interface.
        pfc_lookup_failed_counter = self.device.create_counter(1)
        self.device.set_trap_configuration(
            sdk.LA_EVENT_OAMP_PFC_LOOKUP_FAILED,
            0,
            pfc_lookup_failed_counter,
            self.cpu_punt_dest,
            False,
            False,
            True, 0)

        # Punt to the CPU if we receive an invalid PFC packet
        pfc_invalid_counter = self.device.create_counter(1)
        self.device.set_trap_configuration(
            sdk.LA_EVENT_OAMP_PFC_DROP_INVALID_RX,
            0,
            pfc_invalid_counter,
            self.cpu_punt_dest,
            False,
            False,
            True, 0)

        # Add a couple of mirrors that overlap 4b of the PFC mirrors.
        # This is to test the issue of programming the recycle_override_network table
        # with overlapping mirrors.
        self.create_mirror(PFC_MEASUREMENT_GID & 0xf)
        self.create_mirror(PFC_PILOT_MIRROR_GID & 0xf)

        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_PFC_SAMPLE)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_PFC_DIRECT_SAMPLE)
        if self.device.get_ll_device().is_pacific():
            self.device.set_bool_property(sdk.la_device_property_e_PACIFIC_PFC_HBM_ENABLED, True)
            # Set the probabilities to 100% 1000/1000
            self.device.set_int_property(sdk.la_device_property_e_PACIFIC_PFC_MEASUREMENT_PROBABILITY, 1000)
            self.device.set_int_property(sdk.la_device_property_e_PACIFIC_PFC_PILOT_PROBABILITY, 1000)

        # Configure netflow as well. PFC should take precedence since its high priority
        sampling_rate = 1.0
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_INGRESS_MONITOR)
        priority = 1
        nf_mirror_cmd = T.create_l2_mirror_command(
            self.device,
            NF_MIRROR_CMD_GID,
            self.pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN,
            sampling_rate)
        self.device.set_snoop_configuration(sdk.LA_EVENT_L3_INGRESS_MONITOR, priority, False, False, nf_mirror_cmd)
        # Enable netflow at input port
        self.m_l3_ac.hld_obj.set_ingress_sflow_enabled(True)

        if self.device.get_ll_device().is_pacific():
            self.sw_pfc_init()

        self.device.set_sw_pfc_destination(self.s_sys_p1_gid, self.npu_host_destination)
        self.device.set_sw_pfc_destination(EGRESS_SYS_PORT_GID, self.npu_host_destination_remote)

        TAG_DSCP = sdk.la_ip_dscp()
        TAG_DSCP.value = 0
        self.topology.ingress_qos_profile_def.hld_obj.set_traffic_class_mapping(sdk.la_ip_version_e_IPV4, TAG_DSCP, TC_VALUE)

        self.m_l3_ac_phy = T.l3_ac_port(self,
                                        self.device,
                                        self.s_l3_ac_gid_phy,
                                        self.m_eth_port,
                                        self.topology.global_vrf,
                                        self.s_rx_mac)
        self.m_l3_ac_phy.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.m_l3_ac_phy.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        self.enable_rx_counting_common(self.m_eth_port)
        self.enable_rx_counting(self.m_eth_port)

    def tearDown(self):
        self.device.clear_trap_configuration(sdk.LA_EVENT_OAMP_PFC_LOOKUP_FAILED)
        self.device.clear_trap_configuration(sdk.LA_EVENT_OAMP_PFC_DROP_INVALID_RX)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_L2CP0)
        self.device.clear_snoop_configuration(sdk.LA_EVENT_L3_INGRESS_MONITOR)
        self.device.set_bool_property(sdk.la_device_property_e_PACIFIC_PFC_HBM_ENABLED, False)
        self.device.tearDown()

   # Local mac
    s_rx_mac = T.mac_addr('84:20:75:3e:8c:05')
    s_rx_mac_remote = T.mac_addr('84:20:75:4e:8c:05')
    s_nh_mac = T.mac_addr('1c:f5:7d:e9:61:ef')
    s_vlan1 = 0xaaa
    s_vlan2 = 0xbbb

    s_sip = T.ipv4_addr('16.04.04.253')
    s_dip = T.ipv4_addr('16.04.04.253')
    s_dip_remote = T.ipv4_addr('16.04.04.100')

    s_rx_slice = 2
    s_tx_slice = 1

    s_rx_ifg = 0
    s_tx_ifg = 1

    s_first_serdes_p1 = T.LAST_SERDES_L3 + 1
    s_last_serdes_p1 = s_first_serdes_p1 + 1
    s_first_serdes_p2 = s_last_serdes_p1 + 1
    s_last_serdes_p2 = s_first_serdes_p2 + 1

    TTL = 255
    # GID
    s_sys_p1_gid = 0x4e
    s_sys_p2_gid = 0x42
    s_l3_ac_gid = 0x45
    s_l3_ac_p2_gid = 0x47
    s_l3_ac_gid_phy = 0x52
    port_speed = 50

    INPUT_TEST_PACKET = \
        Ether(dst=s_rx_mac.addr_str, src=s_nh_mac.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1QPrio(vlan=s_vlan1, pcpdei=PCPDEI_VALUE) / \
        IP(src=s_sip.addr_str, dst=s_dip.addr_str, ttl=TTL) / \
        UDP()

    INPUT_REMOTE_PACKET = \
        Ether(dst=s_rx_mac.addr_str, src=s_nh_mac.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1QPrio(vlan=s_vlan1, pcpdei=PCPDEI_VALUE) / \
        IP(src=s_sip.addr_str, dst=s_dip_remote.addr_str, ttl=TTL) / \
        UDP()

    OUTPUT_TEST_PACKET = \
        Ether(dst=s_nh_mac.addr_str, src=s_rx_mac.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1QPrio(vlan=s_vlan2, pcpdei=0) / \
        IP(src=s_sip.addr_str, dst=s_dip.addr_str, ttl=TTL - 1) / \
        UDP()

    COMMON_NPU_HDR = \
        NPU_Header_ext(
            base_type=1,
            fwd_header_type=2,
            slp_qos_id=15,
            fwd_offset=40,
            lb_key=0xbf93,
            encap_type=0xe,
            encap=((nplapicli.NPL_REDIRECT_CODE_PFC_MEASUREMENT << 68) |
                   (PFC_MEASUREMENT_GID << 12) |
                   (nplapicli.NPL_PUNT_NW_PFC_ENCAP_TYPE << 8) |
                   0x00000000000000011),
            punt_mc_expand_encap=((nplapicli.NPL_REDIRECT_CODE_PFC_MEASUREMENT << 16) | 0xe000000),
            ipv4_first_fragment=1,
            ttl=255,
            fwd_slp_info=1104)

    COMMON_TS_PLB = \
        TS_PLB(header_type="ONE_PKT_TS3",
               link_fc=0,
               fcn=0,
               plb_context="UC_L",
               ts3=[0, 0, 0],
               src_device=INGRESS_DEVICE_ID,
               src_slice=s_rx_slice,
               reserved=0)

    INPUT_REMOTE_OVER_FABRIC = \
        COMMON_TS_PLB / \
        TM(header_type="UUU_DD",
           vce=0,
           tc=TC_VALUE,
           dp=0,
           reserved=0,
           dest_device=EGRESS_DEVICE_ID,
           dest_slice=EGRESS_TX_SLICE,
           dest_oq=128 + TC_VALUE) / \
        NPU_Header_ext(
            base_type=1,
            fwd_header_type=2,
            slp_qos_id=15,
            fwd_offset=32,
            encap_type=3,
            lb_key=0xbf93,
            encap=(0x4f << 64) + (NH_GID_2 << 48),
            punt_mc_expand_encap=0x50006,
            ipv4_first_fragment=1,
            ttl=255,
            fwd_slp_info=1104) / \
        IP(src=s_sip.addr_str, dst=s_dip_remote.addr_str, ttl=TTL) / \
        UDP()

    destination_remote = DEST_VALUE_REMOTE + (TC_VALUE << TC_SHIFT_VALUE)
    destination_local = DEST_VALUE + (TC_VALUE << TC_SHIFT_VALUE)

    SAMPLED_PKT_OVER_FABRIC = \
        COMMON_TS_PLB / \
        TM(header_type="UUU_DD",
           vce=0,
           tc=TC_VALUE,
           dp=0,
           reserved=0,
           dest_device=EGRESS_DEVICE_ID,
           dest_slice=EGRESS_TX_SLICE,
           dest_oq=128 + TC_VALUE) / \
        COMMON_NPU_HDR / \
        NPU_Soft_Header(
            unparsed_0=s_sys_p1_gid + (destination_remote << 12)) / \
        Ether(dst=s_rx_mac.addr_str, src=s_nh_mac.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1QPrio(vlan=s_vlan1, pcpdei=PCPDEI_VALUE) / \
        IP(src=s_sip.addr_str, dst=s_dip_remote.addr_str, ttl=TTL) / \
        UDP()

    P2_SAMPLED_PKT_OVER_FABRIC = \
        COMMON_TS_PLB / \
        TM(header_type="UUU_DD",
           vce=0,
           tc=TC_VALUE,
           dp=0,
           reserved=0,
           dest_device=INGRESS_DEVICE_ID,
           dest_slice=EGRESS_TX_SLICE,
           dest_oq=128 + TC_VALUE) / \
        COMMON_NPU_HDR / \
        NPU_Soft_Header(
            unparsed_0=0x42000d00000000 + (destination_remote << 12) + EGRESS_SYS_PORT_GID) / \
        Ether(dst=s_rx_mac.addr_str, src=s_nh_mac.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1QPrio(vlan=s_vlan1, pcpdei=PCPDEI_VALUE) / \
        IP(src=s_sip.addr_str, dst=s_dip_remote.addr_str, ttl=TTL) / \
        UDP()

    COMMON_PKT_OVER_FABRIC = \
        COMMON_TS_PLB / \
        TM(header_type="UUU_DD",
           vce=0,
           tc=0,
           dp=0,
           reserved=0,
           dest_device=EGRESS_DEVICE_ID,
           dest_slice=0,
           dest_oq=304) / \
        NPU_Header_ext(
            base_type=1,
            fwd_header_type=12,
            slp_qos_id=0,
            fwd_offset=40,
            fwd_qos_tag=0,
            lb_key=0x0,
            encap_type=0x0,
            encap=PFC_MEASUREMENT_GID << 16,
            punt_mc_expand_encap=0x0,
            ipv4_first_fragment=0,
            ttl=0,
            fwd_slp_info=0) / \
        NPU_Soft_Header(
            unparsed_0=0,
        ) / \
        NPU_host_ext(
            first_npe_macro_id=nplapicli.NPL_PFC_AA_RECEIVE_MACRO,
            first_fi_macro_id=nplapicli.NPL_FI_MACRO_ID_OAMP,
            ether_type=0x7102)

    COMMON_SAMPLED_PKT = \
        PFC_modified_input_ether(
            dst=s_rx_mac.hld_obj.flat,
            device_time=0x1112131415161715,
            vlan=((PCPDEI_VALUE << 12) | s_vlan1),
            ether_type=0x800
        ) / \
        IP(src=s_sip.addr_str, dst=s_dip_remote.addr_str, ttl=TTL) / \
        UDP()

    P3_SAMPLED_PKT_OVER_FABRIC = \
        COMMON_PKT_OVER_FABRIC / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4,
             fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
             next_header_offset=0,
             source=0,
             code=nplapicli.NPL_REDIRECT_CODE_PFC_MEASUREMENT,
             source_sp=EGRESS_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             source_lp=s_l3_ac_gid, destination_lp=destination_remote,
             relay_id=0, lpts_flow_type=0, time_stamp=((nplapicli.NPL_REDIRECT_CODE_PFC_MEASUREMENT << 40) | 0xf28e000000000000)) / \
        COMMON_SAMPLED_PKT

    P4_SAMPLED_PKT_OVER_FABRIC = \
        COMMON_PKT_OVER_FABRIC / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4,
             fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
             next_header_offset=0,
             source=0,
             code=nplapicli.NPL_REDIRECT_CODE_PFC_MEASUREMENT,
             source_sp=s_sys_p1_gid, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             source_lp=s_l3_ac_gid, destination_lp=destination_remote,
             relay_id=0, lpts_flow_type=0, time_stamp=((nplapicli.NPL_REDIRECT_CODE_PFC_MEASUREMENT << 40) | 0xf28e000000000000)) / \
        COMMON_SAMPLED_PKT

    NETFLOW_PKT = \
        Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
             next_header_offset=0,
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=NF_MIRROR_CMD_GID,
             source_sp=s_sys_p1_gid, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             source_lp=s_l3_ac_gid, destination_lp=s_l3_ac_p2_gid,
             relay_id=0, lpts_flow_type=0) / \
        INPUT_TEST_PACKET
