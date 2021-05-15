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


import decor
from packet_test_utils import *
from scapy.all import *
from scapy.config import conf
conf.ipv6_enabled = False
import unittest
from leaba import sdk
import sim_utils
import topology as T
from sdk_test_case_base import *
import mac_port_helper
import nplapicli
import mtu.mtu_test_utils as MTU
import time

IN_SLICE = 0
IN_IFG = 0
IN_SERDES_FIRST = 4
IN_SERDES_LAST = IN_SERDES_FIRST + 1

OUT_SLICE = 0
OUT_IFG = 1
OUT_SERDES_FIRST = 8
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

OUT_SLICE1 = 1
OUT_IFG1 = 0
OUT_SERDES_FIRST1 = 12
OUT_SERDES_LAST1 = OUT_SERDES_FIRST1 + 1

FABRIC_PORT_SLICE = 3
FABRIC_PORT_IFG = 0
FABRIC_PORT_FIRST_SERDES = 0
FABRIC_PORT_SERDES_COUNT = 2

SYS_PORT_GID_BASE = 23
AC_PORT_GID_BASE = 10

DST_MAC = 'ca:fe:ca:fe:ca:fe'
SRC_MAC = 'de:ad:de:ad:de:ad'
VLAN = 0xAB9

MC_GROUP_GID = 0xab3


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_asic4(), "Only SA mode supported for PL currently.")
@unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
class test_l2_multicast_lc(sdk_test_case_base):
    SLICE_MODES = sim_utils.LINECARD_3N_3F_DEV
    DEVICE_ID = 0

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            for sid in range(T.NUM_SLICES_PER_DEVICE):
                if test_l2_multicast_lc.SLICE_MODES[sid] == sdk.la_slice_mode_e_CARRIER_FABRIC:
                    device.set_fabric_slice_clos_direction(sid, sdk.la_clos_direction_e_DOWN)
            device.set_int_property(sdk.la_device_property_e_MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY, 1)

    @classmethod
    def setUpClass(cls):
        super(
            test_l2_multicast_lc,
            cls).setUpClass(
            device_id=cls.DEVICE_ID,
            slice_modes=cls.SLICE_MODES,
            device_config_func=test_l2_multicast_lc.device_config_func)

    def setUp(self):
        super().setUp(create_default_topology=False)
        self.topology.create_inject_ports()
        self.topology.create_default_profiles()
        self.device.set_is_fabric_time_master(True)
        self.mph = mac_port_helper.mac_port_helper()
        self.mph.verbose = False
        self.mph.init(self.device)
        self.create_fabric_ports()
        self.create_network_ports_and_topology()
        self.create_packets()

    def create_network_ports_and_topology(self):
        # Create multicast group
        self.mc_group = self.device.create_l2_multicast_group(MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(self.mc_group)

        # Create input AC port
        self.in_eth_port = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_SERDES_FIRST, IN_SERDES_LAST)
        self.in_ac_port = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            None,
            self.in_eth_port,
            None,
            VLAN,
            0x0)

        # Create 2 output system-ports
        self.out_mac_port1 = T.mac_port(self, self.device, OUT_SLICE, OUT_IFG, OUT_SERDES_FIRST, OUT_SERDES_LAST)
        self.out_sys_port1 = T.system_port(self, self.device, SYS_PORT_GID_BASE + 1, self.out_mac_port1)

        self.out_mac_port2 = T.mac_port(self, self.device, OUT_SLICE1, OUT_IFG1, OUT_SERDES_FIRST1, OUT_SERDES_LAST1)
        self.out_sys_port2 = T.system_port(self, self.device, SYS_PORT_GID_BASE + 2, self.out_mac_port2)

        self.out_mac_port1.activate()
        self.out_mac_port2.activate()

    def create_fabric_ports(self):
        self.fabric_mac_port = self.mph.create_fabric_mac_port(
            FABRIC_PORT_SLICE,
            FABRIC_PORT_IFG,
            FABRIC_PORT_FIRST_SERDES,
            FABRIC_PORT_SERDES_COUNT,
            sdk.la_mac_port.port_speed_e_E_100G,
            sdk.la_mac_port.fc_mode_e_NONE,
            sdk.la_mac_port.loopback_mode_e_PMA_CORE_CLK)
        self.fabric_mac_port.activate()
        self.fabric_port = self.device.create_fabric_port(self.fabric_mac_port)

        # Activating the fabric protocol works in hardware only.
        if (decor.is_hw_device()):
            # wait for the mac port to go up.
            time.sleep(0.2)
            if self.fabric_mac_port.get_state() != sdk.la_mac_port.state_e_LINK_UP:
                time.sleep(1)
                if self.fabric_mac_port.get_state() != sdk.la_mac_port.state_e_LINK_UP:
                    raise Exception('The mac port is not going up.')
            self.activate_peer_discovery(self.fabric_port)
            self.fabric_port.activate(sdk.la_fabric_port.link_protocol_e_LINK_KEEPALIVE)

        self.fabric_port.set_reachable_lc_devices([self.DEVICE_ID])

    def activate_peer_discovery(self, fabric_port):
        # Try to activate PEER_DISCOVERY 10 times to be sure it's activated successfully. If no success raise an exception.
        for i in range(10):
            success = True
            try:
                fabric_port.activate(sdk.la_fabric_port.link_protocol_e_PEER_DISCOVERY)
            except sdk.AgainException:
                success = False
            if success:
                break
            time.sleep(0.05)

        if not success:
            raise sdk.la_status_e_E_AGAIN

    def create_packets(self):
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        self.in_packet, self.out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_p2p(self):
        self.in_ac_port.hld_obj.set_destination(self.mc_group)
        # Create 2 output AC ports
        eth_port1 = T.sa_ethernet_port(self, self.device, self.out_sys_port1)
        ac_port1 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE +
                                1, self.topology.filter_group_def, None, eth_port1, None, VLAN, 0x0)

        eth_port2 = T.sa_ethernet_port(self, self.device, self.out_sys_port2)
        ac_port2 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE +
                                2, self.topology.filter_group_def, None, eth_port2, None, VLAN, 0x0)

        # Add the output AC ports to the MC group
        self.mc_group.add(ac_port1.hld_obj, self.out_sys_port1.hld_obj)
        self.mc_group.add(ac_port2.hld_obj, self.out_sys_port2.hld_obj)

        # Run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)


if __name__ == '__main__':
    unittest.main()
