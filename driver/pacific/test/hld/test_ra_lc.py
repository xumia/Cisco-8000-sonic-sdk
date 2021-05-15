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

import sim_utils
import hld_sim_utils
from scapy.all import *
import topology as T
from packet_test_utils import *
import rtl_test_utils

INGRESS_DEVICE_ID = 1
INGRESS_RX_SLICE = 0
INGRESS_RX_IFG = 0
INGRESS_RX_SERDES_FIRST = 0
INGRESS_RX_SERDES_LAST = INGRESS_RX_SERDES_FIRST

INGRESS_TX_SLICE = 3
INGRESS_TX_IFG = 0
INGRESS_TX_SERDES_FIRST = 10
INGRESS_TX_SERDES_LAST = INGRESS_TX_SERDES_FIRST + 1

EGRESS_DEVICE_ID = INGRESS_DEVICE_ID
EGRESS_RX_SLICE = 3
EGRESS_RX_IFG = 1
EGRESS_RX_SERDES_FIRST = 8
EGRESS_RX_SERDES_LAST = EGRESS_RX_SERDES_FIRST + 1

EGRESS_TX_SLICE = 1
EGRESS_TX_IFG = 1
EGRESS_TX_SERDES_FIRST = 2
EGRESS_TX_SERDES_LAST = EGRESS_TX_SERDES_FIRST


IN_SP_GID = 17
IN_AC_GID = 260

OUT_SP_GID = 29
OUT_AC_GID = 300

SWITCH_GID = 490

VLAN1 = 0xBB7
VLAN2 = 0x0
VLAN3 = 0xAA3

SRC_MAC = "00:33:44:55:b5:84"
IN_MAC = "00:bd:89:0f:b5:84"
OUT_MAC = "00:be:38:f3:f7:56"
DEST_MAC = "00:af:83:3f:cc:aa"

SIP = '12.10.12.10'
DIP = '82.81.95.250'


class ra_lc_unit_test(unittest.TestCase):

    socket_port = 0
    use_socket = False
    compare_expected = False
    is_full_chip = False
    slice_modes = [sdk.la_slice_mode_e_NETWORK] * 3 + [sdk.la_slice_mode_e_CARRIER_FABRIC] * 3

    def block_filter_getter(self, ll_device):
        if self.is_full_chip:
            return []
        if ll_device.is_pacific():
            return rtl_test_utils.pacific_npu_blocks
        if ll_device.is_gibraltar():
            return rtl_test_utils.gb_npu_blocks
        return []

    def setUp(self):
        pass

    def tearDown(self):
        self.device.tearDown()

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            device.set_bool_property(sdk.la_device_property_e_LC_FORCE_FORWARD_THROUGH_FABRIC_MODE, True)

    def init_device(self):
        self.device = sim_utils.create_device(
            '/dev/uio0',
            0,
            create_sim=True,
            device_config_func=ra_lc_unit_test.device_config_func)  # '/dev/uio0'
        self.device.set_bool_property(sdk.la_device_property_e_LC_FORCE_FORWARD_THROUGH_FABRIC_MODE, True)

        self.topo = T.topology(self, self.device, create_default_topology=False)
        self.topo.create_inject_ports()
        self.ll_device = self.device.get_ll_device()
        self.tree = self.ll_device.get_pacific_tree()

    def init_ra(self):
        self.device = hld_sim_utils.create_ra_device('/dev/testdev/rtl', INGRESS_DEVICE_ID,
                                                     ra_lc_unit_test.use_socket, ra_lc_unit_test.socket_port,
                                                     block_filter_getter=self.block_filter_getter,
                                                     create_sim=True,
                                                     slice_modes=ra_lc_unit_test.slice_modes,
                                                     device_config_func=ra_lc_unit_test.device_config_func)

        self.topo = T.topology(self, self.device, create_default_topology=False)
        self.topo.create_inject_ports()
        self.ll_device = self.device.get_ll_device()
        self.tree = self.ll_device.get_pacific_tree()

    def init_nsim(self):
        self.device = sim_utils.create_test_device(
            '/dev/testdev',
            1,
            slice_modes=ra_lc_unit_test.slice_modes,
            enable_logging=False,
            device_config_func=ra_lc_unit_test.device_config_func)
        self.device.nsim_provider.set_logging(True)

        self.topo = T.topology(self, self.device, create_default_topology=False)
        self.topo.create_inject_ports()
        self.ll_device = self.device.get_ll_device()
        self.tree = self.ll_device.get_pacific_tree()

    def lc_p2p_config(self):
        self.lc_config()
        self.in_ac_port.hld_obj.set_destination(self.out_ac_port.hld_obj)

    def npu_header_per_device(self):
        lldev = self.device.device.get_ll_device()
        if lldev.is_pacific():
            return NPU_Header(unparsed_0=0x1000000000000400,  # The NPU header data is arbitrary and taken as-is from the actual packet
                              unparsed_1=0x5490f2008012c000,
                              unparsed_2=0x0,
                              unparsed_3=0x1000000004000)
        elif lldev.is_gibraltar():
            return NPU_Header(unparsed_0=0x1000000000000400,  # The NPU header data is arbitrary and taken as-is from the actual packet
                              unparsed_1=0x5490f2008012c000,
                              unparsed_2=0x0,
                              unparsed_3=0x1000000004000)

    def lc_config(self):
        self.ingress_rx_pkt = \
            Ether(dst=IN_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN1) / \
            IP(src=SIP, dst=DIP, ttl=10) / \
            TCP() / Raw(load='\xAB\xCD')

        self.ingress_tx_pkt = \
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
               dest_oq=self.device.get_oq_num(EGRESS_TX_IFG, EGRESS_TX_SERDES_FIRST)) / \
            self.npu_header_per_device() / \
            Ether(dst=IN_MAC,
                  src=SRC_MAC,
                  type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN1) / \
            IP(src=SIP, dst=DIP, ttl=10) / \
            TCP() / Raw(load='\xAB\xCD')

        self.egress_rx_pkt = self.ingress_tx_pkt
        self.egress_tx_pkt = self.ingress_rx_pkt

        # This assumes that the test automatically connects ingress-tx -> egress-rx
        self.in_packet = self.ingress_rx_pkt
        self.out_packet = self.egress_tx_pkt

        self.dest_mac = T.mac_addr(IN_MAC)

        self.switch = T.switch(self, self.device, SWITCH_GID)

        self.in_eth_port = T.ethernet_port(
            self,
            self.device,
            INGRESS_RX_SLICE,
            INGRESS_RX_IFG,
            IN_SP_GID,
            INGRESS_RX_SERDES_FIRST,
            INGRESS_RX_SERDES_LAST)
        self.in_ac_port = T.l2_ac_port(self, self.device, IN_AC_GID, None, None, self.in_eth_port, None, VLAN1, VLAN2)

        # Create ingress TX fabric port
        self.in_tx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            INGRESS_TX_SLICE,
            INGRESS_TX_IFG,
            INGRESS_TX_SERDES_FIRST,
            INGRESS_TX_SERDES_LAST)
        in_tx_fabric_port = T.fabric_port(self, self.device, self.in_tx_fabric_mac_port)
        in_tx_fabric_port.set_output_queue_weight_defaults()

        # Create egress RX fabric port
        self.out_rx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            EGRESS_RX_SLICE,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            EGRESS_RX_SERDES_LAST)
        out_rx_fabric_port = T.fabric_port(self, self.device, self.out_rx_fabric_mac_port)
        out_rx_fabric_port.set_output_queue_weight_defaults()

        # Manually set reachability to egress device
        self.device.set_bool_property(sdk.la_device_property_e_LC_ADVERTISE_DEVICE_ON_FABRIC_MODE, False)
        reachable_devices = []
        reachable_devices.append(EGRESS_DEVICE_ID)
        in_tx_fabric_port.hld_obj.set_reachable_lc_devices(reachable_devices)

        self.out_eth_port = T.ethernet_port(
            self,
            self.device,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            OUT_SP_GID,
            EGRESS_TX_SERDES_FIRST,
            EGRESS_TX_SERDES_LAST)
        self.out_ac_port = T.l2_ac_port(self, self.device, OUT_AC_GID, None, None, self.out_eth_port, None, VLAN1, VLAN2)
        self.lc_fc_model_config()

    def lc_fc_model_config(self):
        # Dynamic memory configuration to support ingress LC traffic
        in_tx_fabric_port_num = self.get_fabric_port_num(self.in_tx_fabric_mac_port)
        out_rx_fabric_port_num = self.get_fabric_port_num(self.out_rx_fabric_mac_port)

        # Configure that the route to the egress device, is through the ingress_tx fabric port
        fabric_routing_table_value = 1 << in_tx_fabric_port_num
        self.ll_device.write_memory(self.tree.dmc.pier.fabric_routing_table, EGRESS_DEVICE_ID, fabric_routing_table_value)

        # Configure that the link "delay" on the fabric ports
        # The entry is configured with 0xb1:
        #   link_peer_delay_valid [0:0] = 0x1
        #   link_peer_delay [13:1] = 0x0058
        #   link_peer_device_id [23:14] = 0x000
        #   link_peer_link_num [31:24] = 0x000
        self.ll_device.write_memory(self.tree.dmc.fte.peer_delay_mem, in_tx_fabric_port_num, 0xb1)
        self.ll_device.write_memory(self.tree.dmc.fte.peer_delay_mem, out_rx_fabric_port_num, 0xb1)

        # A LC device needs to know its synced in time with others. The entry is configured with
        #   fabric_time_force_value [31:0] = 0x0f1a804e0    -   some abritrary value
        #   fabric_time_sync_force_value [32:32] = 0x1
        self.ll_device.write_register(self.tree.dmc.fte.fabric_time_force_reg, 0x1f1a804e0)

    def test_nsim_lc_p2p(self):
        self.init_nsim()
        self.lc_p2p_config()

        run_and_compare(
            self,
            self.device,
            self.in_packet,
            INGRESS_RX_SLICE,
            INGRESS_RX_IFG,
            INGRESS_RX_SERDES_FIRST,
            self.ingress_tx_pkt,
            INGRESS_TX_SLICE,
            INGRESS_TX_IFG,
            INGRESS_TX_SERDES_FIRST,
            TS_PLB)
        run_and_compare(
            self,
            self.device,
            self.egress_rx_pkt,
            EGRESS_RX_SLICE,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            self.egress_tx_pkt,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_TX_SERDES_FIRST)

    def test_ra_lc_p2p(self):
        self.init_ra()
        self.lc_p2p_config()

        self.device.get_simulator().set_expected_packet(EGRESS_TX_SLICE, EGRESS_TX_IFG, EGRESS_TX_SERDES_FIRST, self.out_packet)
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            INGRESS_RX_SLICE,
            INGRESS_RX_IFG,
            INGRESS_RX_SERDES_FIRST,
            self.out_packet,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_TX_SERDES_FIRST,
            TS_PLB)

    # Can be a topology global function (or even better - expose the SDK to the API)
    def get_fabric_port_num(self, fabric_mac_port):
        slice_id = fabric_mac_port.hld_obj.get_slice()
        ifg_id = fabric_mac_port.hld_obj.get_ifg()
        serdes_base = fabric_mac_port.hld_obj.get_first_serdes_id()

        # 18=NUM_FABRIC_PORT_PER_NORMAL_SLICE, 9=NUM_FABRIC_PORTS_IN_NORMAL_IFG, 2=NUM_SERDES_PER_FABRIC_PORT
        fabric_port_num = (slice_id * 18) + (ifg_id * 9) + (serdes_base // 2)
        return fabric_port_num


if __name__ == '__main__':

    args_to_remove = []
    sdk_use_socket_patt = re.compile(r'\+SDK_USE_SOCKET=(\d+)')
    for arg in sys.argv:
        match = sdk_use_socket_patt.match(arg)
        if match:
            ra_lc_unit_test.socket_port = int(match.group(1), 10)
            ra_lc_unit_test.use_socket = True
            args_to_remove.append(arg)
            continue

        if 'COMPARE_EXPECTED' in arg:
            ra_lc_unit_test.compare_expected = True
            args_to_remove.append(arg)

        if 'FULL_CHIP' in arg:
            ra_lc_unit_test.is_full_chip = True
            args_to_remove.append(arg)

    for arg in args_to_remove:
        sys.argv.remove(arg)

    unittest.main()
