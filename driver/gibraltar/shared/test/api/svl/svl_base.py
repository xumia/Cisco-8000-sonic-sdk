#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import os
import sys
import unittest
from distutils.util import strtobool
from leaba import sdk
import sim_utils
import packet_test_utils as U
import topology as T
from packet_test_defs import *
from scapy.all import *
from scapy.layers.l2 import *


class Port:
    def __init__(self, slice = 0, ifg = 0, first_serdes = 0, last_serdes = 0):
        self.slice = slice
        self.ifg   = ifg
        self.first_serdes = first_serdes
        self.last_serdes  = last_serdes


stack_ports = [Port(4, 0, 4, 5), Port(4, 1, 8, 9), Port(5, 0, 4, 5), Port(5, 1, 8, 9)]
ports = [Port(0, 0, 4, 5), Port(0, 1, 8, 9), Port(1, 0, 4, 5), Port(1, 1, 8, 9),
         Port(2, 0, 4, 5), Port(2, 1, 8, 9), Port(3, 0, 4, 5), Port(3, 1, 8, 9),
         Port(0, 0, 0, 1), Port(1, 0, 0, 1), Port(2, 0, 0, 1), Port(3, 0, 0, 1)]

INJECT_PORT_MAC_ADDR  = "12:34:56:78:9a:bc"

NW_CONTROL_PUNT_DEST_GID  = 253
SVL_CONTROL_PUNT_DEST_GID = 252

SVL_CONTROL_PUNT_VLAN = 0xA13
SVL_CONTROL_HOST_MAC_ADDR = "fe:dc:ba:98:76:54"

NW_CONTROL_PUNT_VLAN = 0xA13
NW_CONTROL_HOST_MAC_ADDR = "fe:dc:ba:12:34:56"

IPC_PUNT_DEST_MAC_ADDR = "12:34:56:78:9a:ff"

PUNT_VLAN = 0xA13

BASEVID0 = 10
BASEVRF0 = 99


class SubIfForwardingContext:
    def __init__(
            self,
            num_if,
            vlan,
            l_l3ac_gb,
            l_l3ac_mb,
            l_nh_gb,
            l_nh_mb,
            l_v4pb,
            r_l3ac_gb,
            r_l3ac_mb,
            r_nh_gb,
            r_nh_mb,
            r_v4pb):
        self.num_if = num_if
        self.vlan_id_base = vlan
        self.local_l3ac_gid_base = l_l3ac_gb
        self.local_nh_gid_base = l_nh_gb
        self.local_l3ac_mac_base = l_l3ac_mb
        self.local_nh_mac_base = l_nh_mb
        self.local_v4_prefix_base = l_v4pb
        self.remote_l3ac_gid_base = r_l3ac_gb
        self.remote_nh_gid_base = r_nh_gb
        self.remote_l3ac_mac_base = r_l3ac_mb
        self.remote_nh_mac_base = r_nh_mb
        self.remote_v4_prefix_base = r_v4pb


# L3 Sub-Interface specific constants
NUM_L3_SUBIF_PER_SWITCH       = 5
L3_SUBIF_VLAN_BASE     = 20
ACTIVE_L3_SUBIF_L3AC_MAC_BASE = 0x00BEE0CAFE01
ACTIVE_L3_SUBIF_NH_MAC_BASE   = 0x00DEE0CAFE01
ACTIVE_L3_SUBIF_L3AC_GID_BASE = 120
ACTIVE_L3_SUBIF_NH_GID_BASE   = 140
ACTIVE_L3_SUBIF_V4PREFIX_BASE = 0x0A140100

STANDBY_L3_SUBIF_L3AC_MAC_BASE = 0x00AEE0CAFE01
STANDBY_L3_SUBIF_NH_MAC_BASE   = 0x00CEE0CAFE01
STANDBY_L3_SUBIF_L3AC_GID_BASE = 220
STANDBY_L3_SUBIF_NH_GID_BASE   = 240
STANDBY_L3_SUBIF_V4PREFIX_BASE = 0x140A0100


subIfFcSwitch0 = SubIfForwardingContext(
    NUM_L3_SUBIF_PER_SWITCH,
    L3_SUBIF_VLAN_BASE,
    ACTIVE_L3_SUBIF_L3AC_GID_BASE,
    ACTIVE_L3_SUBIF_L3AC_MAC_BASE,
    ACTIVE_L3_SUBIF_NH_GID_BASE,
    ACTIVE_L3_SUBIF_NH_MAC_BASE,
    ACTIVE_L3_SUBIF_V4PREFIX_BASE,
    STANDBY_L3_SUBIF_L3AC_GID_BASE,
    STANDBY_L3_SUBIF_L3AC_MAC_BASE,
    STANDBY_L3_SUBIF_NH_GID_BASE,
    STANDBY_L3_SUBIF_NH_MAC_BASE,
    STANDBY_L3_SUBIF_V4PREFIX_BASE)

subIfFcSwitch1 = SubIfForwardingContext(
    NUM_L3_SUBIF_PER_SWITCH,
    L3_SUBIF_VLAN_BASE,
    STANDBY_L3_SUBIF_L3AC_GID_BASE,
    STANDBY_L3_SUBIF_L3AC_MAC_BASE,
    STANDBY_L3_SUBIF_NH_GID_BASE,
    STANDBY_L3_SUBIF_NH_MAC_BASE,
    STANDBY_L3_SUBIF_V4PREFIX_BASE,
    ACTIVE_L3_SUBIF_L3AC_GID_BASE,
    ACTIVE_L3_SUBIF_L3AC_MAC_BASE,
    ACTIVE_L3_SUBIF_NH_GID_BASE,
    ACTIVE_L3_SUBIF_NH_MAC_BASE,
    ACTIVE_L3_SUBIF_V4PREFIX_BASE)

subIfFc = [subIfFcSwitch0, subIfFcSwitch1]


#
# Temporary until the real issue is fixed in multicast
#
# ----- not a svl feature issue -----
#
# only in hardware testing, the multicast copy is coming to source without deja-vu check
# this issue is being debugged by team
#


def is_dejavu_failed_packet(ingress_packet, egress_packet):
    if (ingress_packet['slice'] == egress_packet.slice) and \
       (ingress_packet['ifg'] == egress_packet.ifg) and \
       (ingress_packet['pif'] == egress_packet.pif):
        ingress_packet_hex = U.scapy_to_hex(ingress_packet['data'])
        egress_packet_hex = egress_packet.packet
        return (egress_packet_hex == ingress_packet_hex)
    else:
        return False


def clear_switch_num_from_gid(gid):
    mask = ~(1 << T.SVL_DEVICE_ID_MARKING_BIT_IN_SYS_PORT_GID)
    return (gid & mask)


def set_switch_num_in_gid(gid, switch_num):
    mask = switch_num << T.SVL_DEVICE_ID_MARKING_BIT_IN_SYS_PORT_GID
    return (gid | mask)


def toggle_switch_num_in_gid(gid):
    mask = 1 << T.SVL_DEVICE_ID_MARKING_BIT_IN_SYS_PORT_GID
    return (gid ^ mask)


def run_and_compare_list_then_save(
        testcase,
        uutprovider,
        ingress_packet,
        egress_compare_list,
        save_remaining=False,
        pcap_file=None):
    unchecked_packets = U.run_and_compare_list(testcase, uutprovider, ingress_packet, egress_compare_list, expect_unchecked=True)
    # Identify SVL packets
    for pak in unchecked_packets:
        scapy_packet = U.hex_to_scapy(pak.packet)
        if (scapy_packet.type == Ethertype.Dot1Q.value) and (scapy_packet[1].type == Ethertype.SVL.value):
            continue
        elif (is_dejavu_failed_packet(ingress_packet, pak)):
            print('Warning! Dejavu Check Failed')
            unchecked_packets.remove(pak)
        else:
            print('Unwanted packet found on Slice: ', pak.slice, ' Ifg: ', pak.ifg, ' Pif: ', pak.pif)
            scapy_packet.show()
            assert(False)
    if len(unchecked_packets) and save_remaining:
        if not pcap_file:
            pcap_file = testcase._testMethodName
        packet_dump_file = os.path.join(os.environ['BASE_OUTPUT_DIR'], pcap_file)
        writer = scapy.utils.RawPcapWriter(packet_dump_file, linktype=0)
        for pak in unchecked_packets:
            ipacket = bytes(U.hex_to_scapy(pak.packet))
            writer.write(ipacket)
        writer.close()
    return unchecked_packets


def get_packet_from_saved_pcap(pcap_file=None):
    packet_dump_file = os.path.join(os.environ['BASE_OUTPUT_DIR'], pcap_file)
    if not os.path.exists(packet_dump_file):
        return None
    reader = scapy.utils.RawPcapReader(packet_dump_file)
    packet = reader.read_packet()
    reader.close()

    scapy_packet = U.hex_to_scapy(packet[0].hex())
    return scapy_packet


def remove_saved_pcap(pcap_file=None):
    packet_dump_file = os.path.join(os.environ['BASE_OUTPUT_DIR'], pcap_file)
    if not os.path.exists(packet_dump_file):
        return None
    os.remove(packet_dump_file)


class SvlBase:
    dev = None
    smps = []
    mps = []
    rps = []
    ssps = []
    lsps = []
    rsps = []
    eps = []
    reps = []
    l2acs = []
    rl2acs = []
    l3acs = []
    rl3acs = []
    lnh = []
    rnh = []
    stack_spa = None
    stackport = None
    gid = 0
    punt_inject = []
    recycle = []
    control_trap_counter = None
    control_trap_priority = 0
    control_trap_tc = 0
    nw_control_trap_counter = None
    nw_control_trap_priority = 0
    nw_control_trap_tc = 0
    ac_profile = None
    nw_control_punt_destination = None

    def __init__(self, device_id, remote_device_id, switch_num, active_mode=False):
        self.device_id = device_id
        self.remote_device_id = remote_device_id
        self.switch_num = switch_num
        self.active = active_mode
        self.testcase = None

        slice_modes = sim_utils.STANDALONE_DEV
        device_config_func = SvlBase.device_config_func
        maxDiff = None
        self.device = U.sim_utils.create_device(self.device_id, slice_modes=slice_modes, device_config_func=device_config_func)
        SvlBase.dev = self.device
        SvlBase.reset()

    @classmethod
    def tearDownClass(cls):
        SvlBase.dev.tearDown()
        SvlBase.dev = None

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @staticmethod
    def device_config_func(device, state):
        device.set_bool_property(sdk.la_device_property_e_ENABLE_SVL_MODE, True)

    @staticmethod
    def reset():
        SvlBase.switch = None
        SvlBase.vrf  = None
        SvlBase.smps = []
        SvlBase.mps  = []
        SvlBase.rps  = []
        SvlBase.ssps = []
        SvlBase.lsps = []
        SvlBase.rsps = []
        SvlBase.eps  = []
        SvlBase.reps = []
        SvlBase.l2acs  = []
        SvlBase.rl2acs = []
        SvlBase.l3acs  = []
        SvlBase.rl3acs = []
        SvlBase.lnh  = []
        SvlBase.rnh  = []
        SvlBase.stack_spa = None
        SvlBase.stackport = None
        SvlBase.gid  = SvlBase.dev.get_limit(sdk.limit_type_e_DEVICE__MIN_SYSTEM_PORT_GID)
        SvlBase.punt_inject = []
        SvlBase.recycle = []
        SvlBase.network_control_punt_destination = None

    def create_mac_ports_for_stack_ports(self):
        for p in stack_ports:
            mp = T.mac_port(self.testcase, self.device, p.slice, p.ifg, p.first_serdes, p.last_serdes)
            mp.activate()
            SvlBase.smps.append(mp)

    def create_mac_ports(self):
        for p in ports:
            mp = T.mac_port(self.testcase, self.device, p.slice, p.ifg, p.first_serdes, p.last_serdes)
            mp.activate()
            SvlBase.mps.append(mp)

    def create_remote_ports(self):
        for p in ports:
            rp = T.remote_port(self.testcase, self.device, self.remote_device_id, p.slice, p.ifg, p.first_serdes, p.last_serdes)
            SvlBase.rps.append(rp)

    def create_stack_port(self):
        for mp in SvlBase.smps:
            gid = SvlBase.gid
            sp = T.system_port(self.testcase, self.device, gid, mp)
            SvlBase.gid = SvlBase.gid + 1
            SvlBase.ssps.append(sp)

        SvlBase.stack_spa = self.device.create_spa_port(SvlBase.gid)
        SvlBase.gid = SvlBase.gid + 1

        for sp in SvlBase.ssps:
            SvlBase.stack_spa.add(sp.hld_obj)
            SvlBase.stack_spa.set_member_transmit_enabled(sp.hld_obj, True)

        SvlBase.stackport = self.device.create_stack_port(SvlBase.stack_spa)

    def create_punt_inject_recycle_ports(self):
        for slice in self.device.get_used_slices():
            if slice in [1, 3, 5]:
                recycle_sys_port_gid = (T.RCY_SYS_PORT_GID_BASE - slice)
                rcyport = T.recycle_port(self.testcase, self.device, slice, 0)
                rcysysport = T.system_port(self.testcase, self.device, recycle_sys_port_gid, rcyport)
                SvlBase.recycle.append(rcysysport)

        for slice in self.device.get_used_slices():
            injectport = None
            if slice in [0, 2, 4]:
                pci_sys_port_gid = (T.INJECT_PORT_BASE_GID + slice)
                pciport = T.pci_port(self.testcase, self.device, slice, 0)
                pcisysport = T.system_port(self.testcase, self.device, pci_sys_port_gid, pciport)
                mac_address = T.mac_addr(INJECT_PORT_MAC_ADDR)
                injectport = self.device.create_punt_inject_port(pcisysport.hld_obj, mac_address.hld_obj)
                pciport.hld_obj.activate()
                SvlBase.punt_inject.append(injectport)

    def create_local_system_ports(self):
        for mp in SvlBase.mps:
            gid = SvlBase.gid
            if self.switch_num:
                gid = (SvlBase.gid | 0x400)
            sp = T.system_port(self.testcase, self.device, gid, mp)
            SvlBase.gid = SvlBase.gid + 1
            SvlBase.lsps.append(sp)

    def create_remote_system_ports(self):
        for rp in SvlBase.rps:
            gid = SvlBase.gid
            if not self.switch_num:
                gid = (SvlBase.gid | 0x400)
            sp = T.system_port(self.testcase, self.device, gid, rp)
            SvlBase.gid = SvlBase.gid + 1
            SvlBase.rsps.append(sp)

    def create_ethernet_ports(self):
        if not self.switch_num:
            for sp in SvlBase.lsps:
                ep = self.device.create_ethernet_port(sp.hld_obj, sdk.la_ethernet_port.port_type_e_AC)
                ep.set_ac_profile(SvlBase.ac_profile)
                SvlBase.eps.append(ep)
            for sp in SvlBase.rsps:
                ep = self.device.create_ethernet_port(sp.hld_obj, sdk.la_ethernet_port.port_type_e_AC)
                ep.set_ac_profile(SvlBase.ac_profile)
                SvlBase.reps.append(ep)
        else:
            for sp in SvlBase.rsps:
                ep = self.device.create_ethernet_port(sp.hld_obj, sdk.la_ethernet_port.port_type_e_AC)
                ep.set_ac_profile(SvlBase.ac_profile)
                SvlBase.reps.append(ep)
            for sp in SvlBase.lsps:
                ep = self.device.create_ethernet_port(sp.hld_obj, sdk.la_ethernet_port.port_type_e_AC)
                ep.set_ac_profile(SvlBase.ac_profile)
                SvlBase.eps.append(ep)

    def configure_svl_control_traps(self):
        punt_port = SvlBase.punt_inject[1]

        host_mac_addr = T.mac_addr(SVL_CONTROL_HOST_MAC_ADDR)
        tag_tci = sdk.la_vlan_tag_tci_t()
        tag_tci.fields.pcp = 0
        tag_tci.fields.dei = 0
        tag_tci.fields.vid = SVL_CONTROL_PUNT_VLAN
        punt_dest = self.device.create_l2_punt_destination(SVL_CONTROL_PUNT_DEST_GID, punt_port, host_mac_addr.hld_obj, tag_tci)

        SvlBase.control_trap_counter = self.device.create_counter(1)
        SvlBase.control_trap_priority = 0
        SvlBase.control_trap_tc = 5
        self.device.set_trap_configuration(
            sdk.LA_EVENT_SVL_CONTROL_IPC,
            SvlBase.control_trap_priority,
            SvlBase.control_trap_counter,
            punt_dest,
            False,
            False,
            True,
            SvlBase.control_trap_tc)
        self.device.set_trap_configuration(
            sdk.LA_EVENT_SVL_CONTROL_PROTOCOL,
            SvlBase.control_trap_priority,
            SvlBase.control_trap_counter,
            punt_dest,
            False,
            False,
            True,
            SvlBase.control_trap_tc)

    def configure_network_control_traps(self):
        if (self.active):
            punt_port = SvlBase.punt_inject[0]
            # allow punt packets coming from stack port to reach active CPU
            punt_sysport = punt_port.get_system_port()
            SvlBase.stackport.set_local_punt_system_port(punt_sysport)
        else:
            punt_port = SvlBase.stackport
            port_mac_addr = T.mac_addr(INJECT_PORT_MAC_ADDR)
            SvlBase.stackport.set_remote_punt_system_port(SvlBase.ssps[0].hld_obj)
            SvlBase.stackport.set_remote_punt_src_mac(port_mac_addr.hld_obj)

        host_mac_addr = T.mac_addr(NW_CONTROL_HOST_MAC_ADDR)
        tag_tci = sdk.la_vlan_tag_tci_t()
        tag_tci.fields.pcp = 0
        tag_tci.fields.dei = 0
        tag_tci.fields.vid = NW_CONTROL_PUNT_VLAN
        punt_dest = self.device.create_l2_punt_destination(NW_CONTROL_PUNT_DEST_GID, punt_port, host_mac_addr.hld_obj, tag_tci)
        SvlBase.network_control_punt_destination = punt_dest

        SvlBase.nw_control_trap_counter = self.device.create_counter(1)
        SvlBase.nw_control_trap_priority = 0
        SvlBase.nw_control_trap_tc = 5
        self.device.set_trap_configuration(
            sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
            SvlBase.nw_control_trap_priority,
            SvlBase.nw_control_trap_counter,
            punt_dest,
            False,
            False,
            True,
            SvlBase.nw_control_trap_tc)

    def create_default_ac_profile(self):
        SvlBase.ac_profile = self.device.create_ac_profile()

        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x0000
        pvf.tpid2 = 0x0000
        SvlBase.ac_profile.set_key_selector_per_format(pvf, sdk.la_ac_profile.key_selector_e_PORT)

        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x8100
        pvf.tpid2 = 0x0000
        SvlBase.ac_profile.set_key_selector_per_format(pvf, sdk.la_ac_profile.key_selector_e_PORT_VLAN)

        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x9100
        pvf.tpid2 = 0x8100
        SvlBase.ac_profile.set_key_selector_per_format(pvf, sdk.la_ac_profile.key_selector_e_PORT_VLAN_VLAN)

    def create_topology(self, testcase, ingress_qos_profile, egress_qos_profile, mcast_enable = False):
        self.testcase = testcase
        SvlBase.create_base_topology(self)
        SvlBase.create_minimal_ports_topology(self, ingress_qos_profile, egress_qos_profile, mcast_enable)

    def create_unicast_host_route_topology(self, testcase, ingress_qos_profile, egress_qos_profile):
        self.testcase = testcase
        SvlBase.create_base_topology(self)
        SvlBase.create_uc_host_route_topology(self, ingress_qos_profile, egress_qos_profile)

    def create_multihome_topology(self, testcase, ingress_qos_profile, egress_qos_profile):
        self.testcase = testcase
        SvlBase.create_base_topology(self)

        switch0 = self.device.create_switch(BASEVID0)

        fg = self.device.create_filter_group()

        l2_mc_group = self.device.create_l2_multicast_group(0x1, sdk.la_replication_paradigm_e_EGRESS)

        spa_gid_base = 50
        l2_mac_base = 0x00BEEFCAFE00
        l2_ac_gid_base = 100
        macaddr0 = sdk.la_mac_addr_t()
        for p in range(4):
            spa = self.device.create_spa_port(spa_gid_base + p)
            spa.add(SvlBase.lsps[p].hld_obj)
            spa.add(SvlBase.rsps[p].hld_obj)

            spa.set_member_transmit_enabled(SvlBase.lsps[p].hld_obj, True)

            ep = self.device.create_ethernet_port(spa, sdk.la_ethernet_port.port_type_e_AC)
            ep.set_ac_profile(SvlBase.ac_profile)
            ep.set_stack_mc_prune(True)

            macaddr0.flat = l2_mac_base + p
            l2acport = self.device.create_ac_l2_service_port(
                l2_ac_gid_base + p, ep, BASEVID0, 0, fg, ingress_qos_profile.hld_obj, egress_qos_profile.hld_obj)
            l2acport.attach_to_switch(switch0)

            l2acport.set_stp_state(sdk.la_port_stp_state_e_FORWARDING)
            switch0.set_mac_entry(macaddr0, l2acport, sdk.LA_MAC_AGING_TIME_NEVER)

            l2acport.set_egress_feature_mode(sdk.la_l2_service_port.egress_feature_mode_e_L2)
            l2_mc_group.add(l2acport, SvlBase.lsps[p].hld_obj)

        if not self.switch_num:
            l2_mac_base = 0x00BEEFCAFE00
            remote_l2_mac_base = 0x00DEADBEEF00
            local_base_id = 100
            remote_base_id = 200
        else:
            l2_mac_base = 0x00DEADBEEF00
            remote_l2_mac_base = 0x00BEEFCAFE00
            local_base_id = 200
            remote_base_id = 100

        for p in range(4, 8):
            local_ep = self.device.create_ethernet_port(SvlBase.lsps[p].hld_obj, sdk.la_ethernet_port.port_type_e_AC)
            local_ep.set_ac_profile(SvlBase.ac_profile)

            remote_ep = self.device.create_ethernet_port(SvlBase.rsps[p].hld_obj, sdk.la_ethernet_port.port_type_e_AC)
            remote_ep.set_ac_profile(SvlBase.ac_profile)

            gid = local_base_id + p
            # Local
            macaddr0.flat = l2_mac_base + p
            l2acport = self.device.create_ac_l2_service_port(
                gid, local_ep, BASEVID0, 0, fg, ingress_qos_profile.hld_obj, egress_qos_profile.hld_obj)
            l2acport.attach_to_switch(switch0)

            l2acport.set_stp_state(sdk.la_port_stp_state_e_FORWARDING)
            switch0.set_mac_entry(macaddr0, l2acport, sdk.LA_MAC_AGING_TIME_NEVER)

            l2acport.set_egress_feature_mode(sdk.la_l2_service_port.egress_feature_mode_e_L2)
            l2_mc_group.add(l2acport, local_ep.get_system_port())

            # Remote
            gid = remote_base_id + p
            macaddr0.flat = remote_l2_mac_base + p
            l2acport = self.device.create_ac_l2_service_port(
                gid, remote_ep, BASEVID0, 0, fg, ingress_qos_profile.hld_obj, egress_qos_profile.hld_obj)
            l2acport.attach_to_switch(switch0)

            l2acport.set_stp_state(sdk.la_port_stp_state_e_FORWARDING)
            switch0.set_mac_entry(macaddr0, l2acport, sdk.LA_MAC_AGING_TIME_NEVER)

            l2acport.set_egress_feature_mode(sdk.la_l2_service_port.egress_feature_mode_e_L2)

        # remote switch ports are added as stack copy
        l2_mc_group.add(SvlBase.stackport, SvlBase.ssps[0].hld_obj)
        # set flood destination as this multicast group
        switch0.set_flood_destination(l2_mc_group)

    def create_base_topology(self):
        SvlBase.create_mac_ports_for_stack_ports(self)
        SvlBase.create_mac_ports(self)
        SvlBase.create_remote_ports(self)
        SvlBase.create_stack_port(self)
        SvlBase.create_punt_inject_recycle_ports(self)
        SvlBase.configure_network_control_traps(self)
        SvlBase.configure_svl_control_traps(self)
        if not self.switch_num:
            SvlBase.create_local_system_ports(self)
            SvlBase.create_remote_system_ports(self)
        else:
            SvlBase.create_remote_system_ports(self)
            SvlBase.create_local_system_ports(self)
        SvlBase.create_default_ac_profile(self)

    def create_l3_sub_interface_topology(self, testcase, topology, ingress_qos_profile, egress_qos_profile):
        # create local sub interfaces
        ep = SvlBase.eps[8]
        SvlBase.create_l3_sub_interfaces(self, testcase, ep, topology, ingress_qos_profile, egress_qos_profile, False)
        # create remote sub interfaces
        r_ep = SvlBase.reps[8]
        SvlBase.create_l3_sub_interfaces(self, testcase, r_ep, topology, ingress_qos_profile, egress_qos_profile, True)

    def create_sub_interface_voq_set(self, testcase, topology, slice_id, ifg):
        self.testcase = testcase
        is_success, base_voq, base_vsc_vec = T.topology.allocate_voq_set(self.device, self.device.get_id(), slice_id, ifg, 4)
        testcase.assertTrue(is_success)
        self.voq_set = self.device.create_voq_set(base_voq, 4, base_vsc_vec, self.device.get_id(), slice_id, ifg)
        for voq in range(4):
            self.voq_set.set_cgm_profile(voq, topology.uc_voq_cgm_profile_def)
        return self.voq_set

    def create_l3_sub_interfaces(self, testcase, ep, topology, iqp, eqp, remote):
        self.testcase = testcase
        sys_port = ep.get_system_port()
        vlan_step = 1
        if remote:
            L3AC_GID_BASE = subIfFc[self.device_id].remote_l3ac_gid_base
            NH_GID_BASE   = subIfFc[self.device_id].remote_nh_gid_base
            L3AC_MAC_BASE = subIfFc[self.device_id].remote_l3ac_mac_base
            NH_MAC_BASE = subIfFc[self.device_id].remote_nh_mac_base
            V4_PREFIX_BASE = subIfFc[self.device_id].remote_v4_prefix_base
        else:
            L3AC_GID_BASE = subIfFc[self.device_id].local_l3ac_gid_base
            NH_GID_BASE   = subIfFc[self.device_id].local_nh_gid_base
            L3AC_MAC_BASE = subIfFc[self.device_id].local_l3ac_mac_base
            NH_MAC_BASE = subIfFc[self.device_id].local_nh_mac_base
            V4_PREFIX_BASE = subIfFc[self.device_id].local_v4_prefix_base
        VLAN_ID_BASE   = subIfFc[self.device_id].vlan_id_base
        for i in range(NUM_L3_SUBIF_PER_SWITCH):
            l3ac_gid = L3AC_GID_BASE + i
            nh_gid = NH_GID_BASE + i
            macaddr0 = sdk.la_mac_addr_t()
            macaddr1 = sdk.la_mac_addr_t()
            macaddr0.flat = L3AC_MAC_BASE + i
            macaddr1.flat = NH_MAC_BASE + i
            vlan_id = VLAN_ID_BASE + (i * vlan_step)

            l3ac_port = self.device.create_l3_ac_port(l3ac_gid, ep, vlan_id, 0, macaddr0, SvlBase.vrf, iqp.hld_obj, eqp.hld_obj)
            l3ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
            if remote:
                l3ac_port.set_stack_remote_logical_port_queueing_enabled(sys_port, True)
            else:
                voq_set = self.create_sub_interface_voq_set(testcase, topology, sys_port.get_slice(), sys_port.get_ifg())
                l3ac_port.set_system_port_voq_set(sys_port, voq_set)

            l3ac_port.set_tc_profile(topology.tc_profile_def.hld_obj)

            nh = self.device.create_next_hop(nh_gid, macaddr1, l3ac_port, sdk.la_next_hop.nh_type_e_NORMAL)
            v4prefix0 = sdk.la_ipv4_prefix_t()
            v4prefix0.length = 24
            v4prefix0.addr.s_addr = (V4_PREFIX_BASE + (i * 256))

            SvlBase.vrf.add_ipv4_route(v4prefix0, nh, 0, False)
        if not remote:
            sp_sch = sys_port.get_scheduler()
            sp_sch.set_logical_port_enabled(True)

    def create_uc_host_route_topology(self, ingress_qos_profile, egress_qos_profile):
        SvlBase.create_ethernet_ports(self)
        macaddr0 = sdk.la_mac_addr_t()
        macaddr1 = sdk.la_mac_addr_t()

        vrf = self.device.create_vrf(BASEVRF0)
        switch0 = self.device.create_switch(BASEVID0)

        SvlBase.switch = switch0
        SvlBase.vrf = vrf

        fg = self.device.create_filter_group()

        # SVI
        macaddr0.flat = 0x0000C0FFEE00
        svi = self.device.create_svi_port(99, switch0, vrf, macaddr0, ingress_qos_profile.hld_obj, egress_qos_profile.hld_obj)
        svi.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        # 4 L3 AC Ports ( on each switch )
        if not self.switch_num:
            l3_mac_base = 0x00FFFFCAFE00
            remote_l3_mac_base = 0x00FFFFBEEF00
            local_base_id = 2048
            remote_base_id = 2148
        else:
            l3_mac_base = 0x00FFFFBEEF00
            remote_l3_mac_base = 0x00FFFFCAFE00
            local_base_id = 2148
            remote_base_id = 2048

        for p in range(8, 12):
            gid = local_base_id + p
            # Local
            macaddr0.flat = l3_mac_base + p
            l3acport = self.device.create_l3_ac_port(
                gid,
                SvlBase.eps[p],
                BASEVID0,
                0,
                macaddr0,
                vrf,
                ingress_qos_profile.hld_obj,
                egress_qos_profile.hld_obj)
            l3acport.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

            SvlBase.l3acs.append(l3acport)
            # /32 route
            macaddr0.flat = l3_mac_base + p + 4
            # IP
            addr = sdk.la_ipv4_addr_t()
            ip_base_byte = (10 * (p - 3))
            addr.s_addr = ((ip_base_byte << 24) | (ip_base_byte << 16) | (ip_base_byte << 8)) + p + 4
            v4prefix = sdk.la_ipv4_prefix_t()
            v4prefix.length = 28
            v4prefix.addr.s_addr = addr.s_addr & 0xFFFFFFF0

            l3acport.add_ipv4_subnet(v4prefix)
            l3acport.add_ipv4_host(addr, macaddr0)
            # Remote
            gid = remote_base_id + p
            macaddr1.flat = remote_l3_mac_base + p
            l3acport = self.device.create_l3_ac_port(
                gid,
                SvlBase.reps[p],
                BASEVID0,
                0,
                macaddr1,
                vrf,
                ingress_qos_profile.hld_obj,
                egress_qos_profile.hld_obj)
            l3acport.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

            SvlBase.rl3acs.append(l3acport)
            # /32 route
            macaddr0.flat = remote_l3_mac_base + p + 4
            # IP
            addr = sdk.la_ipv4_addr_t()
            ip_base_byte = (10 * (p + 1))
            addr.s_addr = ((ip_base_byte << 24) | (ip_base_byte << 16) | (ip_base_byte << 8)) + p + 4
            v4prefix = sdk.la_ipv4_prefix_t()
            v4prefix.length = 28
            v4prefix.addr.s_addr = addr.s_addr & 0xFFFFFFF0

            l3acport.add_ipv4_subnet(v4prefix)
            l3acport.add_ipv4_host(addr, macaddr0)

    def create_minimal_ports_topology(self, ingress_qos_profile, egress_qos_profile, mcast_enable):
        SvlBase.create_ethernet_ports(self)
        macaddr0 = sdk.la_mac_addr_t()
        macaddr1 = sdk.la_mac_addr_t()

        vrf = self.device.create_vrf(BASEVRF0)
        switch0 = self.device.create_switch(BASEVID0)

        SvlBase.switch = switch0
        SvlBase.vrf = vrf

        fg = self.device.create_filter_group()

        # SVI
        macaddr0.flat = 0x0000C0FFEE00
        svi = self.device.create_svi_port(99, switch0, vrf, macaddr0, ingress_qos_profile.hld_obj, egress_qos_profile.hld_obj)
        svi.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        if mcast_enable:
            svi.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
            l2_mc_group = self.device.create_l2_multicast_group(0x1, sdk.la_replication_paradigm_e_EGRESS)
            ip_mc_group0 = self.device.create_ip_multicast_group(0x2, sdk.la_replication_paradigm_e_EGRESS)

        # 4 L2 AC Ports ( on each switch )
        if not self.switch_num:
            l2_mac_base = 0x00BEEFCAFE00
            remote_l2_mac_base = 0x00DEADBEEF00
            local_base_id = 100
            remote_base_id = 200
        else:
            l2_mac_base = 0x00DEADBEEF00
            remote_l2_mac_base = 0x00BEEFCAFE00
            local_base_id = 200
            remote_base_id = 100

        for p in range(4):
            gid = local_base_id + p
            # Local
            macaddr0.flat = l2_mac_base + p
            l2acport = self.device.create_ac_l2_service_port(
                gid, SvlBase.eps[p], BASEVID0, 0, fg, ingress_qos_profile.hld_obj, egress_qos_profile.hld_obj)
            l2acport.attach_to_switch(switch0)
            l2acport.set_stp_state(sdk.la_port_stp_state_e_FORWARDING)
            switch0.set_mac_entry(macaddr0, l2acport, sdk.LA_MAC_AGING_TIME_NEVER)
            l2acport.set_egress_feature_mode(sdk.la_l2_service_port.egress_feature_mode_e_L2)
            SvlBase.l2acs.append(l2acport)
            # mcast support
            if mcast_enable:
                l2_mc_group.add(l2acport, SvlBase.eps[p].get_system_port())
                ip_mc_group0.add(svi, l2acport, SvlBase.eps[p].get_system_port())
            # Remote
            gid = remote_base_id + p
            macaddr0.flat = remote_l2_mac_base + p
            l2acport = self.device.create_ac_l2_service_port(
                gid, SvlBase.reps[p], BASEVID0, 0, fg, ingress_qos_profile.hld_obj, egress_qos_profile.hld_obj)
            l2acport.attach_to_switch(switch0)
            l2acport.set_stp_state(sdk.la_port_stp_state_e_FORWARDING)
            switch0.set_mac_entry(macaddr0, l2acport, sdk.LA_MAC_AGING_TIME_NEVER)
            l2acport.set_egress_feature_mode(sdk.la_l2_service_port.egress_feature_mode_e_L2)
            SvlBase.rl2acs.append(l2acport)

        # remote switch ports are added as stack copy
        if mcast_enable:
            l2_mc_group.add(SvlBase.stackport, SvlBase.ssps[0].hld_obj)
            # set flood destination as this multicast group
            switch0.set_flood_destination(l2_mc_group)
            # first two L3 ports are part of local multicast group
            # last two ports from each switch forms another multicast group
            # another mcast group holds all L3 ports and L2 ports via SVI
            ip_mc_group1 = self.device.create_ip_multicast_group(0x3, sdk.la_replication_paradigm_e_EGRESS)
            ip_mc_group2 = self.device.create_ip_multicast_group(0x4, sdk.la_replication_paradigm_e_EGRESS)

        # 4 L3 AC Ports ( on each switch )
        if not self.switch_num:
            l3_mac_base = 0x00BEEFCAFE00
            nh_mac_base = 0x00CAFEBABE00
            remote_l3_mac_base = 0x00DEADBEEF00
            remote_nh_mac_base = 0x00BEEFBABE00
            local_base_id = 300
            remote_base_id = 400
            nh_base_gid = 500
            remote_nh_base_gid = 600
        else:
            l3_mac_base = 0x00DEADBEEF00
            nh_mac_base = 0x00BEEFBABE00
            remote_l3_mac_base = 0x00BEEFCAFE00
            remote_nh_mac_base = 0x00CAFEBABE00
            local_base_id = 400
            remote_base_id = 300
            nh_base_gid = 600
            remote_nh_base_gid = 500

        for p in range(4, 8):
            gid = local_base_id + p
            # Local
            macaddr0.flat = l3_mac_base + p
            l3acport = self.device.create_l3_ac_port(
                gid,
                SvlBase.eps[p],
                BASEVID0,
                0,
                macaddr0,
                vrf,
                ingress_qos_profile.hld_obj,
                egress_qos_profile.hld_obj)
            l3acport.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
            if mcast_enable:
                l3acport.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

            gid = nh_base_gid + p
            macaddr0.flat = nh_mac_base + p
            nh = self.device.create_next_hop(gid, macaddr0, l3acport, sdk.la_next_hop.nh_type_e_NORMAL)
            SvlBase.l3acs.append(l3acport)
            SvlBase.lnh.append(nh)
            if mcast_enable:
                if p < 6:
                    ip_mc_group1.add(l3acport, None, SvlBase.eps[p].get_system_port())
                else:
                    ip_mc_group2.add(l3acport, None, SvlBase.eps[p].get_system_port())
                ip_mc_group0.add(l3acport, None, SvlBase.eps[p].get_system_port())
            # Remote
            gid = remote_base_id + p
            macaddr1.flat = remote_l3_mac_base + p
            l3acport = self.device.create_l3_ac_port(
                gid,
                SvlBase.reps[p],
                BASEVID0,
                0,
                macaddr1,
                vrf,
                ingress_qos_profile.hld_obj,
                egress_qos_profile.hld_obj)
            l3acport.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

            gid = remote_nh_base_gid + p
            macaddr0.flat = remote_nh_mac_base + p
            nh = self.device.create_next_hop(gid, macaddr0, l3acport, sdk.la_next_hop.nh_type_e_NORMAL)
            SvlBase.rl3acs.append(l3acport)
            SvlBase.rnh.append(nh)

        if mcast_enable:
            # remote switch ports are added as stack copy
            ip_mc_group2.add(SvlBase.stackport, SvlBase.ssps[1].hld_obj)
            ip_mc_group0.add(SvlBase.stackport, SvlBase.ssps[2].hld_obj)
            # multicast routes
            # Global IP Multicast Group 224.0.1.2
            # Local IP Multicast Group 224.0.1.3
            # Last two L3 ports of both the switches form IP Multicast Group 224.0.1.4
            global_mc_group_addr = T.ipv4_addr('224.0.1.2')
            local_mc_group_addr  = T.ipv4_addr('224.0.1.3')
            local_and_remote_mc_group_addr = T.ipv4_addr('224.0.1.4')
            rpf = None
            counter = None
            punt_and_forward = False
            punt_on_rpf_fail = False
            vrf.add_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, global_mc_group_addr.hld_obj,
                                         ip_mc_group0, rpf, punt_on_rpf_fail,
                                         punt_and_forward, counter)
            vrf.add_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, local_mc_group_addr.hld_obj,
                                         ip_mc_group1, rpf, punt_on_rpf_fail,
                                         punt_and_forward, counter)
            vrf.add_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, local_and_remote_mc_group_addr.hld_obj,
                                         ip_mc_group2, rpf, punt_on_rpf_fail,
                                         punt_and_forward, counter)

        v4prefix0 = sdk.la_ipv4_prefix_t()
        v4prefix0.length = 24
        if not self.switch_num:
            # 10.10.10.0/24
            v4prefix0.addr.s_addr = 0x0A0A0A00
            vrf.add_ipv4_route(v4prefix0, SvlBase.lnh[0], 0, False)
            # 20.20.20.0/24
            v4prefix0.addr.s_addr = 0x14141400
            vrf.add_ipv4_route(v4prefix0, SvlBase.lnh[1], 0, False)
            # 30.30.30.0/24
            v4prefix0.addr.s_addr = 0x1E1E1E00
            vrf.add_ipv4_route(v4prefix0, SvlBase.lnh[2], 0, False)
            # 40.40.40.0/24
            v4prefix0.addr.s_addr = 0x28282800
            vrf.add_ipv4_route(v4prefix0, SvlBase.lnh[3], 0, False)

            # 50.50.50.0/24
            v4prefix0.addr.s_addr = 0x32323200
            vrf.add_ipv4_route(v4prefix0, SvlBase.rnh[0], 0, False)
            # 60.60.60.0/24
            v4prefix0.addr.s_addr = 0x3C3C3C00
            vrf.add_ipv4_route(v4prefix0, SvlBase.rnh[1], 0, False)
            # 70.70.70.0/24
            v4prefix0.addr.s_addr = 0x46464600
            vrf.add_ipv4_route(v4prefix0, SvlBase.rnh[2], 0, False)
            # 80.80.80.0/24
            v4prefix0.addr.s_addr = 0x50505000
            vrf.add_ipv4_route(v4prefix0, SvlBase.rnh[3], 0, False)
        else:
            # 10.10.10.0/24
            v4prefix0.addr.s_addr = 0x0A0A0A00
            vrf.add_ipv4_route(v4prefix0, SvlBase.rnh[0], 0, False)
            # 20.20.20.0/24
            v4prefix0.addr.s_addr = 0x14141400
            vrf.add_ipv4_route(v4prefix0, SvlBase.rnh[1], 0, False)
            # 30.30.30.0/24
            v4prefix0.addr.s_addr = 0x1E1E1E00
            vrf.add_ipv4_route(v4prefix0, SvlBase.rnh[2], 0, False)
            # 40.40.40.0/24
            v4prefix0.addr.s_addr = 0x28282800
            vrf.add_ipv4_route(v4prefix0, SvlBase.rnh[3], 0, False)

            # 50.50.50.0/24
            v4prefix0.addr.s_addr = 0x32323200
            vrf.add_ipv4_route(v4prefix0, SvlBase.lnh[0], 0, False)
            # 60.60.60.0/24
            v4prefix0.addr.s_addr = 0x3C3C3C00
            vrf.add_ipv4_route(v4prefix0, SvlBase.lnh[1], 0, False)
            # 70.70.70.0/24
            v4prefix0.addr.s_addr = 0x46464600
            vrf.add_ipv4_route(v4prefix0, SvlBase.lnh[2], 0, False)
            # 80.80.80.0/24
            v4prefix0.addr.s_addr = 0x50505000
            vrf.add_ipv4_route(v4prefix0, SvlBase.lnh[3], 0, False)

    def install_an_entry_in_copc_mac_table(
            self,
            ether_value,
            ether_mask,
            mac_da_value,
            event,
            mac_da_mask=T.mac_addr('ff:ff:ff:ff:ff:ff'),
            npp_attribute=0x0,
            mac_lp_type_value=0x0,
            mac_lp_type_mask=0x0):

        key1 = []
        f1 = sdk.field()
        f1.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_ETHERNET_PROFILE_ID
        f1.val.mac.ethernet_profile_id = npp_attribute
        f1.mask.mac.ethernet_profile_id = npp_attribute
        key1.append(f1)

        f2 = sdk.field()
        f2.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_DA
        f2.val.mac.da = mac_da_value.hld_obj
        f2.mask.mac.da = mac_da_mask.hld_obj
        key1.append(f2)

        f3 = sdk.field()
        f3.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_ETHERTYPE
        f3.val.mac.ethertype = ether_value
        f3.mask.mac.ethertype = ether_mask
        key1.append(f3)

        f4 = sdk.field()
        f4.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_LP_TYPE
        f4.val.mac.lp_type = mac_lp_type_value
        f4.mask.mac.lp_type = mac_lp_type_mask
        key1.append(f4)

        result1 = sdk.result()
        result1.event = event

        self.copc_mac.append(key1, result1)

    def clear_entries_from_copc_mac_table(self):
        self.copc_mac.clear()


class SvlBaseActiveContext:
    active = True
    switch_num = 0
    device_id  = switch_num
    remote_device_id = not switch_num


class SvlBaseStandbyContext:
    active = False
    switch_num = 1
    device_id  = switch_num
    remote_device_id = not switch_num
