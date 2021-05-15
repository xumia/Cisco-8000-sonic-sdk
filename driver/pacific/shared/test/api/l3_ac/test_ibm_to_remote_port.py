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
import packet_test_utils as U
from lc_base import *
import scapy.all as S
import topology as T
import ip_test_base
import sim_utils
import decor

MIRROR_CMD_GID = 2

MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET

PAYLOAD_SIZE = 64
IN_L3_AC_PORT_MAC = "40:40:40:40:40:40"
OUT_L3_AC_PORT_MAC = "40:40:40:40:40:44"
PRIVATE_DATA = 0x1234567890abcdef

INJECT_PIF_FIRST = 8
INJECT_SP_GID = 25

PUNT_VLAN = 0xA13


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
class test_ipv4_local_span(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(INGRESS_DEVICE_ID, slice_modes=sim_utils.LINECARD_3N_3F_DEV)

        self.topology = T.topology(self, self.device, create_default_topology=False)
        self.topology.create_inject_ports()
        self.ip_impl = ip_test_base.ipv4_test_base()
        self.vrf = T.vrf(self, self.device, VRF_GID)
        self.DIP = T.ipv4_addr('192.168.0.1')
        self.SIP = T.ipv4_addr('193.168.0.1')
        self.TTL = 255
        ac_profile = T.ac_profile(self, self.device)

        # create Rx L3AC
        in_rx_eth_port = T.ethernet_port(
            self,
            self.device,
            INGRESS_RX_SLICE,
            INGRESS_RX_IFG,
            SYS_PORT_GID_BASE,
            INGRESS_RX_SERDES_FIRST,
            INGRESS_RX_SERDES_LAST)
        in_rx_eth_port.set_ac_profile(ac_profile)

        in_l3_port_mac = T.mac_addr(IN_L3_AC_PORT_MAC)
        self.in_l3_ac = T.l3_ac_port(self, self.device,
                                     GID_BASE,
                                     in_rx_eth_port,
                                     self.vrf,
                                     in_l3_port_mac,
                                     T.RX_L3_AC_PORT_VID1,
                                     T.RX_L3_AC_PORT_VID2)
        self.in_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.in_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

        # create Tx L3AC
        self.tx_eth_port = T.ethernet_port(
            self,
            self.device,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            SYS_PORT_GID_BASE + 1,
            INGRESS_RX_SERDES_FIRST,
            INGRESS_RX_SERDES_LAST)
        self.tx_eth_port.set_ac_profile(ac_profile)

        out_l3_port_mac = T.mac_addr(OUT_L3_AC_PORT_MAC)
        self.out_l3_ac = T.l3_ac_port(self, self.device,
                                      GID_BASE + 1,
                                      self.tx_eth_port,
                                      self.vrf,
                                      in_l3_port_mac,
                                      T.RX_L3_AC_PORT_VID1,
                                      T.RX_L3_AC_PORT_VID2)
        self.out_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.out_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

        self.nh_l3_ac_reg = T.next_hop(self, self.device, GID_BASE + 2, T.NH_L3_AC_REG_MAC, self.out_l3_ac)

        self.INPUT_PACKET_BASE = \
            S.Ether(dst=in_l3_port_mac.addr_str, src=out_l3_port_mac.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.TTL)
        self.INPUT_PACKET = U.add_payload(self.INPUT_PACKET_BASE, PAYLOAD_SIZE)

        self.EXPECTED_OUTPUT_PACKET_BASE = \
            S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=in_l3_port_mac.addr_str) / \
            S.IP(src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.TTL - 1)

        self.EXPECTED_OUTPUT_PACKET = U.add_payload(self.EXPECTED_OUTPUT_PACKET_BASE, PAYLOAD_SIZE)

        self.ingress_tx_span_pkt = \
            TS_PLB(header_type="ONE_PKT_TS3",
                   link_fc=0,
                   fcn=0,
                   plb_context="UC_L",
                   ts3=[0, 0, 0],
                   src_device=INGRESS_DEVICE_ID,
                   src_slice=INGRESS_RX_SLICE,
                   reserved=0) / \
            TM(header_type="UUU_DD",
               vce=0,
               tc=0,
               dp=0,
               reserved=0,
               dest_device=EGRESS_DEVICE_ID,
               dest_slice=EGRESS_TX_SLICE,
               dest_oq=T.topology.get_oq_num(EGRESS_TX_IFG, EGRESS_TX_SERDES_FIRST)) / \
            self.npu_header_per_device() / \
            NPU_Soft_Header(unparsed_0=0x000000000000b017) / \
            self.INPUT_PACKET

    def tearDown(self):
        self.device.tearDown()

    def npu_header_per_device(self):
        lldev = self.device.device.get_ll_device()
        if lldev.is_pacific():
            return NPU_Header(unparsed_0=0x1000000000000002,   # The NPU header data is arbitrary and taken as-is from the actual packet
                              unparsed_1=0x8a95f28e03000000,
                              unparsed_2=0x0011e0300,
                              unparsed_3=0x1ff0000a003ee)
        elif lldev.is_gibraltar():
            return NPU_Header(unparsed_0=0x1000000000000002,   # The NPU header data is arbitrary and taken as-is from the actual packet
                              unparsed_1=0x46faf28e03000000,
                              unparsed_2=0x0011e0300,
                              unparsed_3=0x1ff0000a003ee)

    @unittest.skipIf(decor.is_hw_device(), "Test cannot work on HW device")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_local_span(self):
        # Set the route
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.vrf, prefix,
                               self.nh_l3_ac_reg,
                               PRIVATE_DATA)

        # Inject the packet and test outputs
        ingress_packet = {
            'data': self.INPUT_PACKET,
            'slice': INGRESS_RX_SLICE,
            'ifg': INGRESS_RX_IFG,
            'pif': INGRESS_RX_SERDES_FIRST}
        egress_packet = {
            'data': self.EXPECTED_OUTPUT_PACKET,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': INGRESS_RX_SERDES_FIRST}
        expected_packets = []
        expected_packets.append(egress_packet)
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        voq_offset = 0
        system_port = self.tx_eth_port.hld_obj.get_system_port()
        mirror_cmd = self.device.create_l2_mirror_command(
            MIRROR_CMD_INGRESS_GID,
            self.tx_eth_port.hld_obj,
            system_port,
            voq_offset,
            1)
        self.in_l3_ac.hld_obj.set_ingress_mirror_command(mirror_cmd, is_acl_conditioned=False)
        copy_packet = {'data': self.INPUT_PACKET, 'slice': T.TX_SLICE_REG, 'ifg': T.TX_IFG_REG, 'pif': INGRESS_RX_SERDES_FIRST}
        expected_packets.append(copy_packet)
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Create fabric port
        in_tx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            INGRESS_TX_SLICE,
            INGRESS_TX_IFG,
            INGRESS_TX_SERDES_FIRST,
            INGRESS_TX_SERDES_LAST)
        in_tx_fabric_port = T.fabric_port(self, self.device, in_tx_fabric_mac_port)

        # Manually set reachability to egress device
        self.device.set_bool_property(sdk.la_device_property_e_LC_ADVERTISE_DEVICE_ON_FABRIC_MODE, False)
        reachable_devices = []
        reachable_devices.append(EGRESS_DEVICE_ID)
        in_tx_fabric_port.hld_obj.set_reachable_lc_devices(reachable_devices)

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
        remote_sys_port = T.system_port(self, self.device, EGRESS_SYS_PORT_GID + 1, remote_port)

        ac_profile = T.ac_profile(self, self.device)
        # Create remote ethernet port above the remote system port
        remote_eth_port = T.sa_ethernet_port(self, self.device, remote_sys_port, ac_profile)

        # create mirror to remote port
        voq_offset = 0
        system_port = remote_eth_port.hld_obj.get_system_port()
        new_mirror_cmd = self.device.create_l2_mirror_command(
            MIRROR_CMD_INGRESS_GID + 1, remote_eth_port.hld_obj, system_port, voq_offset, 1)
        self.in_l3_ac.hld_obj.set_ingress_mirror_command(new_mirror_cmd, is_acl_conditioned=False)
        expected_packets.pop(1)

        copy_packet = {
            'data': self.ingress_tx_span_pkt,
            'slice': INGRESS_TX_SLICE,
            'ifg': INGRESS_TX_IFG,
            'pif': INGRESS_TX_SERDES_FIRST}
        expected_packets.append(copy_packet)
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, TS_PLB)

        self.device.destroy(new_mirror_cmd)
        self.device.destroy(mirror_cmd)

    @unittest.skipIf(decor.is_hw_device(), "Test cannot work on HW device")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ibm_copy_on_egress_device(self):
        ''' Replay the copy packet with Fabric headers from fabric slice.
            Create shadow interface hierarchy on same device
            verify fabric headers are stripped and replicated packet is same as source packet on ingress
        '''

        # create fabric rx port
        out_rx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            EGRESS_RX_SLICE,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            EGRESS_RX_SERDES_LAST)
        out_rx_fabric_port = T.fabric_port(self, self.device, out_rx_fabric_mac_port)

        # Create tx mac port
        out_tx_mac_port = T.mac_port(
            self,
            self.device,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_TX_SERDES_FIRST,
            EGRESS_TX_SERDES_LAST)

        # Create tx system port above the mac port
        out_tx_sys_port = T.system_port(self, self.device, EGRESS_SYS_PORT_GID + 2, out_tx_mac_port)

        ac_profile = T.ac_profile(self, self.device)
        # Create tx ethernet port above the system port
        out_tx_eth_port = T.sa_ethernet_port(self, self.device, out_tx_sys_port, ac_profile)

        out_l3_port_mac = T.mac_addr(OUT_L3_AC_PORT_MAC)
        out_l3_ac = T.l3_ac_port(self, self.device,
                                 GID_BASE + 2,
                                 out_tx_eth_port,
                                 self.vrf,
                                 out_l3_port_mac)
        out_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        out_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

        run_and_compare(
            self,
            self.device,
            self.ingress_tx_span_pkt,
            EGRESS_RX_SLICE,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            self.INPUT_PACKET,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_TX_SERDES_FIRST)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mirror_create_destory(self):
        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            INJECT_SP_GID,
            INJECT_PIF_FIRST,
            T.INJECT_PORT_MAC_ADDR)
        mirror_cmd = T.create_l2_mirror_command(self.device, MIRROR_CMD_INGRESS_GID, self.pi_port, T.HOST_MAC_ADDR, PUNT_VLAN, 1)
        self.device.destroy(mirror_cmd)


if __name__ == '__main__':
    unittest.main()
