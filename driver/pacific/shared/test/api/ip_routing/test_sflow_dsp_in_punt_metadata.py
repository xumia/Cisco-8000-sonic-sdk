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
from leaba.debug import debug_device
from packet_test_utils import *
import scapy.all as S
import topology as T
import ip_test_base
import decor
from sdk_test_case_base import *
from copy import deepcopy
import mtu.mtu_test_utils as MTU
from trap_counter_utils import *
import smart_slices_choise as ssch


PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xA13
PUNT_RELAY_ID = 0 if decor.is_pacific() else T.VRF_GID
MIRROR_CMD_GID = 10
MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_VLAN = 0xA12

SYS_PORT_GID_BASE = 23

PUNT_SLICE = T.get_device_slice(2)  # must be even numbered slice
PUNT_IFG = 0
PUNT_PIF_FIRST = T.get_device_first_serdes(8)
PUNT_PIF_LAST = PUNT_PIF_FIRST
PUNT_SP_GID = SYS_PORT_GID_BASE  + 3


@unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
@unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
class test_sflow_dsp_in_punt_metadata(sdk_test_case_base):

    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl = ip_test_base.ipv4_test_base

    INJECT_SLICE = T.get_device_slice(3)
    INJECT_IFG = T.get_device_ifg(1)
    INJECT_PIF_FIRST = 8
    INJECT_SP_GID = SYS_PORT_GID_BASE + 2
    INJECT_SP_GID2 = SYS_PORT_GID_BASE + 3

    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    TTL = 128

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1)

    SNOOP_PACKET_BASE = \
        Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=MIRROR_VLAN, type=U.Ethertype.Punt.value) / \
        U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
               next_header_offset=0,
               source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=MIRROR_CMD_INGRESS_GID,
               source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
               source_lp=T.RX_L3_AC_GID, destination_lp=T.TX_L3_AC_SYS_PORT_REG_GID,
               relay_id=T.VRF_GID, lpts_flow_type=0
               ) / \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

    INPUT_PACKET, PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, PAYLOAD_SIZE)
    SNOOP_PACKET = U.add_payload(SNOOP_PACKET_BASE, PAYLOAD_SIZE)

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            device.set_bool_property(sdk.la_device_property_e_DESTINATION_SYSTEM_PORT_IN_IBM_METADATA, True)

    @classmethod
    def setUpClass(cls):
        super(test_sflow_dsp_in_punt_metadata, cls).setUpClass(
            device_config_func=test_sflow_dsp_in_punt_metadata.device_config_func)

    def setUp(self):
        super().setUp()
        ssch.rechoose_odd_inject_slice(self, self.device)

        self.l3_port_impl = T.ip_l3_ac_base(self.topology)
        self.add_default_route()

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh,
                               self.PRIVATE_DATA_DEFAULT)
        self.has_default_route = True

    def _try_set_snoop(self, snoop, priority, mirror_cmd):
        try:
            self.device.set_snoop_configuration(snoop, priority, False, False, mirror_cmd)
        except sdk.BaseException as STATUS:
            if (STATUS.args[0] != sdk.la_status_e_E_NOTFOUND):
                raise STATUS

    def __setup_sflow(self, snoop_packet, is_host, is_pci):
        # Setup punt and trap
        if is_pci:
            self.pi_port = self.topology.inject_ports[PUNT_SLICE]
            punt_ifg = 0
            punt_pif_first = self.device.get_pci_serdes()
            punt_pif_last = self.device.get_pci_serdes()
        else:
            self.pi_port = T.punt_inject_port(
                self,
                self.device,
                PUNT_SLICE,
                PUNT_IFG,
                PUNT_SP_GID,
                PUNT_PIF_FIRST,
                PUNT_INJECT_PORT_MAC_ADDR)
            punt_ifg = PUNT_IFG
            punt_pif_first = PUNT_PIF_FIRST
            punt_pif_last = PUNT_PIF_LAST

        sampling_rate = 0.5
        self.mirror_cmd = T.create_l2_mirror_command(
            self.device,
            MIRROR_CMD_INGRESS_GID,
            self.pi_port,
            HOST_MAC_ADDR,
            MIRROR_VLAN,
            sampling_rate)
        priority = 0

        # Clear trap and set snoop -> packet will go out and another packet with punt header will be generated.
        la_event = sdk.LA_EVENT_L3_INGRESS_MONITOR
        self.orig_trap_config = self.device.get_trap_configuration(la_event)
        self.device.clear_trap_configuration(la_event)
        self._try_set_snoop(la_event, priority, self.mirror_cmd)

        # Enable netflow at input port
        self.l3_port_impl.rx_port.hld_obj.set_ingress_sflow_enabled(True)

        # Set the route
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        if is_host:
            self.ip_impl.add_subnet(self.l3_port_impl.tx_port, prefix)
            self.ip_impl.add_host(self.l3_port_impl.tx_port, self.DIP, self.l3_port_impl.reg_nh.mac_addr)
        else:
            self.ip_impl.add_route(self.topology.vrf, prefix,
                                   self.l3_port_impl.reg_fec,
                                   self.PRIVATE_DATA)

        # Inject the packet and test outputs
        self.ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        self.expected_packets = []
        self.expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                      'ifg': T.TX_IFG_REG, 'pif': self.l3_port_impl.serdes_reg})
        self.expected_packets.append({'data': snoop_packet, 'slice': PUNT_SLICE, 'ifg': punt_ifg, 'pif': punt_pif_first})
        self.expected_packets_no_sflow = [{'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                           'ifg': T.TX_IFG_REG, 'pif': self.l3_port_impl.serdes_reg}]

    def __cleanup_sflow(self, is_host, is_pci):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        if is_host:
            self.ip_impl.delete_host(self.l3_port_impl.tx_port, self.DIP)
            self.ip_impl.delete_subnet(self.l3_port_impl.tx_port, prefix)
        else:
            self.ip_impl.delete_route(self.topology.vrf, prefix)

        la_event = sdk.LA_EVENT_L3_INGRESS_MONITOR
        self.device.clear_snoop_configuration(la_event)
        self.device.set_trap_configuration(la_event,
                                           self.orig_trap_config[0],  # priority
                                           self.orig_trap_config[1],  # counter_or_meter
                                           self.orig_trap_config[2],  # destination
                                           self.orig_trap_config[3],  # skip_inject_up_packets
                                           self.orig_trap_config[4],  # skip_p2p_packets
                                           self.orig_trap_config[5],  # overwrite_phb
                                           self.orig_trap_config[6])  # tc

        self.device.destroy(self.mirror_cmd)
        if not is_pci:
            self.device.destroy(self.pi_port.hld_obj)

    def __test_sflow(self, packets_nr, sampling_rate):
        self.mirror_cmd.set_probability(sampling_rate)

        mirrors = 0
        for i in range(packets_nr):
            try:
                run_and_compare_list(self, self.device, self.ingress_packet, self.expected_packets)
            except AssertionError:
                pass
            else:
                mirrors += 1

        print('packets_nr=%d mirrors=%d' % (packets_nr, mirrors))
        tolerance = 0.5
        self.assertTrue((mirrors > packets_nr * sampling_rate * (1 - tolerance)) and
                        (mirrors < packets_nr * sampling_rate * (1 + tolerance)))

        registered_sampling_rate = self.mirror_cmd.get_probability()
        self.assertAlmostEqual(sampling_rate, registered_sampling_rate)

    def _test_sflow_with_dsp_in_punt_header(self, snoop_packet, is_host=False, is_pci=False):
        self.__setup_sflow(snoop_packet, is_host, is_pci)

        self.__test_sflow(packets_nr=100, sampling_rate=0.5)
        self.__test_sflow(packets_nr=500, sampling_rate=0.1)

        self.__cleanup_sflow(is_host, is_pci)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_sflow(self):
        self._test_sflow_with_dsp_in_punt_header(self.SNOOP_PACKET)


if __name__ == '__main__':
    unittest.main()
