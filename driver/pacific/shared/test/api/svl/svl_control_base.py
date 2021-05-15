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
import decor
import packet_test_utils as U
import topology as T
import nplapicli as nplapi
from packet_test_defs import *
from scapy.all import *
from scapy.layers.l2 import *
import svl_base
from svl_base import *

LLC = scapy.layers.l2.LLC
load_contrib("cdp")


class ISO(Packet):
    name = "ISO"
    fields_desc = [ByteField("disc", 0),
                   ByteField("lenIndic", 0),
                   ByteField("idExt", 0),
                   ByteField("idLen", 0),
                   BitField("reserv", 0, 3),
                   BitField("pduType", 0, 5),
                   ByteField("pduVer", 0),
                   ByteField("reserv", 0),
                   ByteField("minArea", 0)
                   ]


bind_layers(LLC, ISO, dsap=0xfe)

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210


@unittest.skipIf(decor.is_hw_device(), "Skip for HW device.")
@unittest.skipIf(not (decor.is_gibraltar() or decor.is_pacific()), "Test is applicable only on Pacific and Gibraltar")
@unittest.skipIf(decor.is_matilda('3.2'), "These tests require at least 4 slices, Matilda has 3, so skip.")
class SvlBaseControlActive(unittest.TestCase, svl_base.SvlBaseActiveContext):
    topology_init_done = False
    base = None
    dev = None

    @classmethod
    def tearDownClass(cls):
        if SvlBaseControlActive.dev is not None:
            SvlBaseControlActive.dev.tearDown()

    def setUp(self):
        if not SvlBaseControlActive.topology_init_done:
            if SvlBaseControlActive.dev is None:
                self.base = SvlBase(self.device_id, self.remote_device_id, self.switch_num, self.active)
                self.device = SvlBase.dev
                SvlBaseControlActive.dev = self.device
                SvlBaseControlActive.base = self.base
            else:
                self.base = SvlBaseControlActive.base
                self.device = SvlBaseControlActive.dev
            self.topology = T.topology(self, self.device, create_default_topology=False)
            ingress_qos_profile = T.ingress_qos_profile(self, self.device)
            egress_qos_profile = T.egress_qos_profile(self, self.device)
            self.base.create_topology(self, ingress_qos_profile, egress_qos_profile)
            SvlBaseControlActive.topology_init_done = True
        self.device = SvlBase.dev
        self.base = SvlBaseControlActive.base
        self.copc_mac = self.device.create_copc(sdk.la_control_plane_classifier.type_e_MAC)

    def test_svl_control_active_network_control_to_local(self):
        cdp_da = '01:00:0C:CC:CC:CC'
        SA = '00:BE:EF:CA:FE:00'

        PUNT_PIF = self.device.get_pci_serdes()

        CDP_PACKET_BASE = \
            Ether(dst=cdp_da, src=SA, type=0x011e) / \
            LLC(dsap=170, ssap=170, ctrl=3) / SNAP() / CDPv2_HDR() / CDPMsgDeviceID() / CDPAddrRecordIPv4() / CDPMsgAddr() / \
            CDPMsgPortID() / CDPMsgCapabilities() / CDPMsgSoftwareVersion() / CDPMsgPlatform()

        self.output_packet, __ = U.enlarge_packet_to_min_length(CDP_PACKET_BASE)

        dest_id = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP,
            SvlBase.lsps[0].hld_obj.get_gid())

        INJECT_PACKET = \
            Ether(dst=NW_CONTROL_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=0, type=U.Ethertype.Inject.value) / \
            InjectDown(dest=dest_id, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            self.output_packet

        U.run_and_compare(self, self.device,
                          INJECT_PACKET, 0, 0, PUNT_PIF,
                          self.output_packet, ports[0].slice, ports[0].ifg, ports[0].first_serdes)

    def test_svl_control_active_network_control_to_standby(self):
        cdp_da = '01:00:0C:CC:CC:CC'
        SA = '00:BE:EF:CA:FE:00'

        PUNT_PIF = self.device.get_pci_serdes()

        CDP_PACKET_BASE = \
            Ether(dst=cdp_da, src=SA, type=0x011e) / \
            LLC(dsap=170, ssap=170, ctrl=3) / SNAP() / CDPv2_HDR() / CDPMsgDeviceID() / CDPAddrRecordIPv4() / CDPMsgAddr() / \
            CDPMsgPortID() / CDPMsgCapabilities() / CDPMsgSoftwareVersion() / CDPMsgPlatform()

        dest_id = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP,
            SvlBase.ssps[0].hld_obj.get_gid())

        # First Port in remote switch
        dest_remote = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP,
            SvlBase.rsps[0].hld_obj.get_gid())

        INJECT_PACKET = \
            Ether(dst=NW_CONTROL_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=0, type=U.Ethertype.Inject.value) / \
            InjectDown(dest=dest_id, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            Ether(dst=NW_CONTROL_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=0, type=U.Ethertype.Inject.value) / \
            InjectDown(dest=dest_remote, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            CDP_PACKET_BASE

        STACK_PORT_OUTPUT_PACKET = \
            Ether(dst=NW_CONTROL_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=0, type=U.Ethertype.Inject.value) / \
            InjectDown(dest=dest_remote, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            CDP_PACKET_BASE

        U.run_and_compare(self, self.device,
                          INJECT_PACKET, 0, 0, PUNT_PIF,
                          STACK_PORT_OUTPUT_PACKET, stack_ports[0].slice, stack_ports[0].ifg, stack_ports[0].first_serdes)

    def test_svl_control_active_network_control_to_cpu(self):
        cdp_da = '01:00:0C:CC:CC:CC'
        SA = '00:BE:EF:CA:FE:00'
        SvlBase.install_an_entry_in_copc_mac_table(self, 0, 0, T.mac_addr(
            cdp_da), sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, T.mac_addr('ff:ff:ff:ff:ff:fe'))

        PUNT_PIF = self.device.get_pci_serdes()

        CDP_PACKET_BASE = \
            Ether(dst=cdp_da, src=SA, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=BASEVID0) / \
            LLC(dsap=170, ssap=170, ctrl=3) / SNAP() / CDPv2_HDR() / CDPMsgDeviceID() / CDPAddrRecordIPv4() / CDPMsgAddr() / \
            CDPMsgPortID() / CDPMsgCapabilities() / CDPMsgSoftwareVersion() / CDPMsgPlatform()

        PUNT_PACKET = \
            Ether(dst=NW_CONTROL_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
                   source_sp=SvlBase.lsps[0].hld_obj.get_gid(),
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=(nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING | SvlBase.l2acs[0].get_gid()),
                   destination_lp=sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
                   relay_id=0, lpts_flow_type=0) / \
            CDP_PACKET_BASE

        U.run_and_compare(self, self.device,
                          CDP_PACKET_BASE, ports[0].slice, ports[0].ifg, ports[0].first_serdes,
                          PUNT_PACKET, 0, 0, PUNT_PIF)

        SvlBase.clear_entries_from_copc_mac_table(self)

    def test_svl_control_active_network_control_from_remote_to_cpu(self):
        cdp_da = '01:00:0C:CC:CC:CC'
        SA = '00:BE:EF:CA:FE:00'

        PUNT_PIF = self.device.get_pci_serdes()

        CDP_PACKET_BASE = \
            Ether(dst=cdp_da, src=SA, type=0x011e) / \
            LLC(dsap=170, ssap=170, ctrl=3) / SNAP() / CDPv2_HDR() / CDPMsgDeviceID() / CDPAddrRecordIPv4() / CDPMsgAddr() / \
            CDPMsgPortID() / CDPMsgCapabilities() / CDPMsgSoftwareVersion() / CDPMsgPlatform()

        # source_sp and source_lp will hold the remote port's data
        STACK_PORT_INPUT_PACKET = \
            Ether(dst=NW_CONTROL_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
                   source_sp=0,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=0,
                   destination_lp=sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
                   relay_id=0, lpts_flow_type=0) / \
            CDP_PACKET_BASE

        U.run_and_compare(self, self.device,
                          STACK_PORT_INPUT_PACKET, stack_ports[0].slice, stack_ports[0].ifg, stack_ports[0].first_serdes,
                          STACK_PORT_INPUT_PACKET, 0, 0, PUNT_PIF)

    def test_svl_control_active_stack_control_message_transmit(self):
        ISIS_ISO = Ether(dst='01:80:c2:00:00:14', src='be:ef:5d:35:7a:35') / \
            LLC(dsap=0xFE, ssap=0xFE, ctrl=0x3) / ISO() / \
            Raw(load=0x03111111111111001e003700d303000000f001028101cc01040349000184040a000001)
        ISIS_ISO[ISO].disc = 0x83  # ISIS
        ISIS_ISO[ISO].lenIndic = 20
        ISIS_ISO[ISO].idExt = 1
        ISIS_ISO[ISO].pduType = 17  # P2P HELLO
        ISIS_ISO[ISO].pduVer = 1

        dest_id = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP,
            SvlBase.ssps[0].hld_obj.get_gid())

        ISIS_INJECT_PACKET = Ether(dst=SVL_CONTROL_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=10, type=Ethertype.Inject.value) / \
            InjectDown(dest=dest_id, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / ISIS_ISO

        PUNT_PIF = self.device.get_pci_serdes()

        U.run_and_compare(self, self.device,
                          ISIS_INJECT_PACKET, 2, 0, PUNT_PIF,
                          ISIS_ISO, stack_ports[0].slice, stack_ports[0].ifg, stack_ports[0].first_serdes)

    def test_svl_control_active_stack_control_message_receive(self):
        ISIS_ISO = Ether(dst='01:80:c2:00:00:14', src='be:ef:5d:35:7a:35') / \
            LLC(dsap=0xFE, ssap=0xFE, ctrl=0x3) / ISO() / \
            Raw(load=0x03111111111111001e003700d303000000f001028101cc01040349000184040a000001)
        ISIS_ISO[ISO].disc = 0x83  # ISIS
        ISIS_ISO[ISO].lenIndic = 20
        ISIS_ISO[ISO].idExt = 1
        ISIS_ISO[ISO].pduType = 17  # P2P HELLO
        ISIS_ISO[ISO].pduVer = 1

        PUNT_PIF = self.device.get_pci_serdes()
        STACK_CONTROL_MESSAGE_WITH_PUNT_HEADER = Ether(dst=SVL_CONTROL_HOST_MAC_ADDR,
                                                       src=INJECT_PORT_MAC_ADDR,
                                                       type=U.Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                                             id=0,
                                                                                             vlan=PUNT_VLAN,
                                                                                             type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                                                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                                                   next_header_offset=0,
                                                                                                                                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                                                   code=sdk.LA_EVENT_SVL_CONTROL_PROTOCOL,
                                                                                                                                   source_sp=SvlBase.ssps[0].hld_obj.get_gid(),
                                                                                                                                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                                   source_lp=0,
                                                                                                                                   destination_lp=sdk.LA_EVENT_SVL_CONTROL_PROTOCOL,
                                                                                                                                   relay_id=0,
                                                                                                                                   lpts_flow_type=0) / ISIS_ISO

        U.run_and_compare(self, self.device,
                          ISIS_ISO, stack_ports[0].slice, stack_ports[0].ifg, stack_ports[0].first_serdes,
                          STACK_CONTROL_MESSAGE_WITH_PUNT_HEADER, 2, 0, PUNT_PIF)

    def test_svl_control_active_stack_ipc_message_transmit(self):
        RAW_PAYLOAD = '\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'
        IPC_INPUT_PACKET = Ether(dst='01:80:c2:00:00:14', src='be:ef:5d:35:7a:35') / \
            IP(src='10.1.0.1', dst='10.2.0.1', ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        dest_id = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP,
            SvlBase.ssps[0].hld_obj.get_gid())

        # unused by remote, placeholder to indicate the source switch info
        dest_remote = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP,
            SvlBase.ssps[0].hld_obj.get_gid())

        # inner inject header requires special destination mac address
        IPC_INJECT_PACKET = Ether(dst=SVL_CONTROL_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=10, type=Ethertype.Inject.value) / \
            InjectDown(dest=dest_id, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            Ether(dst=IPC_PUNT_DEST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=10, type=Ethertype.Inject.value) / \
            InjectDown(dest=dest_remote, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            IPC_INPUT_PACKET

        IPC_OUTPUT_PACKET = Ether(dst=IPC_PUNT_DEST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=10, type=Ethertype.Inject.value) / \
            InjectDown(dest=dest_remote, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            IPC_INPUT_PACKET
        PUNT_PIF = self.device.get_pci_serdes()

        U.run_and_compare(self, self.device,
                          IPC_INJECT_PACKET, 2, 0, PUNT_PIF,
                          IPC_OUTPUT_PACKET, stack_ports[0].slice, stack_ports[0].ifg, stack_ports[0].first_serdes)

    def test_svl_control_active_stack_ipc_message_receive(self):
        RAW_PAYLOAD = '\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'
        IPC_INPUT_PACKET = Ether(dst='01:80:c2:00:00:14', src='be:ef:5d:35:7a:35') / \
            IP(src='10.1.0.1', dst='10.2.0.1', ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        IPC_INPUT_PACKET = Ether(dst=IPC_PUNT_DEST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=10, type=Ethertype.Inject.value) / \
            InjectDown(dest=0, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            IPC_INPUT_PACKET

        PUNT_PIF = self.device.get_pci_serdes()
        IPC_MESSAGE_WITH_PUNT_HEADER = Ether(dst=SVL_CONTROL_HOST_MAC_ADDR,
                                             src=INJECT_PORT_MAC_ADDR,
                                             type=U.Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                                   id=0,
                                                                                   vlan=PUNT_VLAN,
                                                                                   type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                                         fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                                         next_header_offset=0,
                                                                                                                         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                                         code=sdk.LA_EVENT_SVL_CONTROL_IPC,
                                                                                                                         source_sp=SvlBase.ssps[0].hld_obj.get_gid(),
                                                                                                                         destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                         source_lp=0,
                                                                                                                         destination_lp=sdk.LA_EVENT_SVL_CONTROL_IPC,
                                                                                                                         relay_id=0,
                                                                                                                         lpts_flow_type=0) / IPC_INPUT_PACKET

        U.run_and_compare(self, self.device,
                          IPC_INPUT_PACKET, stack_ports[0].slice, stack_ports[0].ifg, stack_ports[0].first_serdes,
                          IPC_MESSAGE_WITH_PUNT_HEADER, 2, 0, PUNT_PIF)

    def test_svl_control_active_lpts_local_receive(self):
        print('')

    def test_svl_control_active_lpts_remote_receive(self):
        print('')


@unittest.skipIf(decor.is_hw_device(), "Skip for HW device.")
@unittest.skipIf(not (decor.is_gibraltar() or decor.is_pacific()), "Test is applicable only on Pacific and Gibraltar")
@unittest.skipIf(decor.is_matilda('3.2'), "These tests require at least 4 slices, Matilda has 3, so skip.")
class SvlBaseControlStandby(unittest.TestCase, svl_base.SvlBaseStandbyContext):
    topology_init_done = False
    base = None
    dev = None

    @classmethod
    def tearDownClass(cls):
        if SvlBaseControlStandby.dev is not None:
            SvlBaseControlStandby.dev.tearDown()

    def setUp(self):
        if not SvlBaseControlStandby.topology_init_done:
            if SvlBaseControlStandby.dev is None:
                self.base = SvlBase(self.device_id, self.remote_device_id, self.switch_num, self.active)
                self.device = SvlBase.dev
                SvlBaseControlStandby.dev = self.device
                SvlBaseControlStandby.base = self.base
            else:
                self.device = SvlBaseControlStandby.dev
                self.base = SvlBaseControlStandby.base
            self.topology = T.topology(self, self.device, create_default_topology=False)
            ingress_qos_profile = T.ingress_qos_profile(self, self.device)
            egress_qos_profile = T.egress_qos_profile(self, self.device)
            self.base.create_topology(self, ingress_qos_profile, egress_qos_profile)
            SvlBaseControlStandby.topology_init_done = True
        self.device = SvlBase.dev
        self.base = SvlBaseControlStandby.base
        self.copc_mac = self.device.create_copc(sdk.la_control_plane_classifier.type_e_MAC)

    def test_svl_control_standby_network_control_to_local(self):
        # packet actually comes from stack port through active CPU
        cdp_da = '01:00:0C:CC:CC:CC'
        SA = '00:BE:EF:CA:FE:00'

        CDP_PACKET_BASE = \
            Ether(dst=cdp_da, src=SA, type=0x011e) / \
            LLC(dsap=170, ssap=170, ctrl=3) / SNAP() / CDPv2_HDR() / CDPMsgDeviceID() / CDPAddrRecordIPv4() / CDPMsgAddr() / \
            CDPMsgPortID() / CDPMsgCapabilities() / CDPMsgSoftwareVersion() / CDPMsgPlatform()

        dest_id = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP,
            SvlBase.lsps[0].hld_obj.get_gid())

        STACK_PORT_OUTPUT_PACKET = \
            Ether(dst=NW_CONTROL_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=0, type=U.Ethertype.Inject.value) / \
            InjectDown(dest=dest_id, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            CDP_PACKET_BASE

        U.run_and_compare(self, self.device,
                          STACK_PORT_OUTPUT_PACKET, stack_ports[0].slice, stack_ports[0].ifg, stack_ports[0].first_serdes,
                          CDP_PACKET_BASE, ports[0].slice, ports[0].ifg, ports[0].first_serdes)

    def test_svl_control_standby_network_control_to_remote_cpu(self):
        cdp_da = '01:00:0C:CC:CC:CC'
        SA = '00:BE:EF:CA:FE:00'
        SvlBase.install_an_entry_in_copc_mac_table(self, 0, 0, T.mac_addr(
            cdp_da), sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, T.mac_addr('ff:ff:ff:ff:ff:fe'))

        CDP_PACKET_BASE = \
            Ether(dst=cdp_da, src=SA, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=BASEVID0) / \
            LLC(dsap=170, ssap=170, ctrl=3) / SNAP() / CDPv2_HDR() / CDPMsgDeviceID() / CDPAddrRecordIPv4() / CDPMsgAddr() / \
            CDPMsgPortID() / CDPMsgCapabilities() / CDPMsgSoftwareVersion() / CDPMsgPlatform()

        PUNT_PACKET = \
            Ether(dst=NW_CONTROL_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
                   source_sp=SvlBase.lsps[0].hld_obj.get_gid(),
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=(nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING | SvlBase.l2acs[0].get_gid()),
                   destination_lp=sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
                   relay_id=0, lpts_flow_type=0) / \
            CDP_PACKET_BASE

        U.run_and_compare(self, self.device,
                          CDP_PACKET_BASE, ports[0].slice, ports[0].ifg, ports[0].first_serdes,
                          PUNT_PACKET, stack_ports[0].slice, stack_ports[0].ifg, stack_ports[0].first_serdes)

        SvlBase.clear_entries_from_copc_mac_table(self)

    def test_svl_control_standby_stack_control_message_transmit(self):
        ISIS_ISO = Ether(dst='01:80:c2:00:00:14', src='be:ef:5d:35:7a:35') / \
            LLC(dsap=0xFE, ssap=0xFE, ctrl=0x3) / ISO() / \
            Raw(load=0x03111111111111001e003700d303000000f001028101cc01040349000184040a000001)
        ISIS_ISO[ISO].disc = 0x83  # ISIS
        ISIS_ISO[ISO].lenIndic = 20
        ISIS_ISO[ISO].idExt = 1
        ISIS_ISO[ISO].pduType = 17  # P2P HELLO
        ISIS_ISO[ISO].pduVer = 1

        dest_id = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP,
            SvlBase.ssps[0].hld_obj.get_gid())

        ISIS_INJECT_PACKET = Ether(dst=SVL_CONTROL_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=10, type=Ethertype.Inject.value) / \
            InjectDown(dest=dest_id, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / ISIS_ISO

        PUNT_PIF = self.device.get_pci_serdes()

        U.run_and_compare(self, self.device,
                          ISIS_INJECT_PACKET, 2, 0, PUNT_PIF,
                          ISIS_ISO, stack_ports[0].slice, stack_ports[0].ifg, stack_ports[0].first_serdes)

    def test_svl_control_standby_stack_control_message_receive(self):
        ISIS_ISO = Ether(dst='01:80:c2:00:00:14', src='be:ef:5d:35:7a:35') / \
            LLC(dsap=0xFE, ssap=0xFE, ctrl=0x3) / ISO() / \
            Raw(load=0x03111111111111001e003700d303000000f001028101cc01040349000184040a000001)
        ISIS_ISO[ISO].disc = 0x83  # ISIS
        ISIS_ISO[ISO].lenIndic = 20
        ISIS_ISO[ISO].idExt = 1
        ISIS_ISO[ISO].pduType = 17  # P2P HELLO
        ISIS_ISO[ISO].pduVer = 1

        PUNT_PIF = self.device.get_pci_serdes()
        STACK_CONTROL_MESSAGE_WITH_PUNT_HEADER = Ether(dst=SVL_CONTROL_HOST_MAC_ADDR,
                                                       src=INJECT_PORT_MAC_ADDR,
                                                       type=U.Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                                             id=0,
                                                                                             vlan=PUNT_VLAN,
                                                                                             type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                                                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                                                   next_header_offset=0,
                                                                                                                                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                                                   code=sdk.LA_EVENT_SVL_CONTROL_PROTOCOL,
                                                                                                                                   source_sp=SvlBase.ssps[0].hld_obj.get_gid(),
                                                                                                                                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                                   source_lp=0,
                                                                                                                                   destination_lp=sdk.LA_EVENT_SVL_CONTROL_PROTOCOL,
                                                                                                                                   relay_id=0,
                                                                                                                                   lpts_flow_type=0) / ISIS_ISO

        U.run_and_compare(self, self.device,
                          ISIS_ISO, stack_ports[0].slice, stack_ports[0].ifg, stack_ports[0].first_serdes,
                          STACK_CONTROL_MESSAGE_WITH_PUNT_HEADER, 2, 0, PUNT_PIF)

    def test_svl_control_standby_stack_ipc_message_transmit(self):
        RAW_PAYLOAD = '\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'
        IPC_INPUT_PACKET = Ether(dst='01:80:c2:00:00:14', src='be:ef:5d:35:7a:35') / \
            IP(src='10.1.0.1', dst='10.2.0.1', ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        dest_id = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP,
            SvlBase.ssps[0].hld_obj.get_gid())

        # unused by remote, placeholder to indicate the source switch info
        dest_remote = sdk.la_get_destination_id_from_gid(
            sdk.la_packet_types.LA_PACKET_INJECT_DOWN_DEST_DSP,
            SvlBase.ssps[0].hld_obj.get_gid())

        # inner inject header requires special destination mac address
        IPC_INJECT_PACKET = Ether(dst=SVL_CONTROL_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=10, type=Ethertype.Inject.value) / \
            InjectDown(dest=dest_id, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            Ether(dst=IPC_PUNT_DEST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=10, type=Ethertype.Inject.value) / \
            InjectDown(dest=dest_remote, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            IPC_INPUT_PACKET

        IPC_OUTPUT_PACKET = Ether(dst=IPC_PUNT_DEST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=10, type=Ethertype.Inject.value) / \
            InjectDown(dest=dest_remote, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            IPC_INPUT_PACKET
        PUNT_PIF = self.device.get_pci_serdes()

        U.run_and_compare(self, self.device,
                          IPC_INJECT_PACKET, 2, 0, PUNT_PIF,
                          IPC_OUTPUT_PACKET, stack_ports[0].slice, stack_ports[0].ifg, stack_ports[0].first_serdes)

    def test_svl_control_standby_stack_ipc_message_receive(self):
        RAW_PAYLOAD = '\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'
        IPC_INPUT_PACKET = Ether(dst='01:80:c2:00:00:14', src='be:ef:5d:35:7a:35') / \
            IP(src='10.1.0.1', dst='10.2.0.1', ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        IPC_INPUT_PACKET = Ether(dst=IPC_PUNT_DEST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=10, type=Ethertype.Inject.value) / \
            InjectDown(dest=0, encap=sdk.la_packet_types.LA_PACKET_INJECT_DOWN_ENCAP_NONE) / \
            IPC_INPUT_PACKET

        PUNT_PIF = self.device.get_pci_serdes()
        IPC_MESSAGE_WITH_PUNT_HEADER = Ether(dst=SVL_CONTROL_HOST_MAC_ADDR,
                                             src=INJECT_PORT_MAC_ADDR,
                                             type=U.Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                                   id=0,
                                                                                   vlan=PUNT_VLAN,
                                                                                   type=U.Ethertype.Punt.value) / U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                                         fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                                                                                                                         next_header_offset=0,
                                                                                                                         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                                         code=sdk.LA_EVENT_SVL_CONTROL_IPC,
                                                                                                                         source_sp=SvlBase.ssps[0].hld_obj.get_gid(),
                                                                                                                         destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                         source_lp=0,
                                                                                                                         destination_lp=sdk.LA_EVENT_SVL_CONTROL_IPC,
                                                                                                                         relay_id=0,
                                                                                                                         lpts_flow_type=0) / IPC_INPUT_PACKET

        U.run_and_compare(self, self.device,
                          IPC_INPUT_PACKET, stack_ports[0].slice, stack_ports[0].ifg, stack_ports[0].first_serdes,
                          IPC_MESSAGE_WITH_PUNT_HEADER, 2, 0, PUNT_PIF)

    def test_svl_control_standby_lpts_remote_send(self):
        print('')
