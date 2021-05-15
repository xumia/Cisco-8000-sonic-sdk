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
from scapy.config import conf
conf.ipv6_enabled = False
import unittest
from leaba import sdk
import sim_utils
import decor
import topology as T
from sdk_test_case_base import *
import mac_port_helper
import time

IN_SLICE = 0
IN_IFG = 0
IN_SERDES_FIRST = 4
IN_SERDES_LAST = IN_SERDES_FIRST + 1

OUT_SLICE1 = 0
OUT_IFG1 = 1
OUT_SERDES_FIRST1 = 8
OUT_SERDES_LAST1 = OUT_SERDES_FIRST1 + 1

OUT_SLICE2 = 1
OUT_IFG2 = 0
OUT_SERDES_FIRST2 = 12
OUT_SERDES_LAST2 = OUT_SERDES_FIRST2 + 1

FABRIC_PORT_SLICE = 3
FABRIC_PORT_IFG = 0
FABRIC_PORT_FIRST_SERDES = 0
FABRIC_PORT_SERDES_COUNT = 2

SYS_PORT_GID_BASE = 23
AC_PORT_GID_BASE = 10

VLAN1 = 0xAB9
VLAN2 = 0xAB9
PACKET_LOAD = 0xfedcba9876543210

MC_GROUP_GID = 0xab3
VRF_GID = 0x3aa

MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')
L3_AC_MAC = T.mac_addr('72:74:76:78:80:82')
SA = T.mac_addr('be:ef:5d:35:7a:35')
TTL = 127
SIP = T.ipv4_addr('12.10.12.10')


@unittest.skipIf(decor.is_asic4(), "Only SA mode supported for PL currently.")
@unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
@unittest.skipIf(decor.is_matilda(), "only SA is supported by Matilda.")
class test_ip_multicast_lc(sdk_test_case_base):
    SLICE_MODES = sim_utils.LINECARD_3N_3F_DEV
    DEVICE_ID = 0

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            for sid in range(T.NUM_SLICES_PER_DEVICE):
                if test_ip_multicast_lc.SLICE_MODES[sid] == sdk.la_slice_mode_e_CARRIER_FABRIC:
                    device.set_fabric_slice_clos_direction(sid, sdk.la_clos_direction_e_DOWN)
            device.set_int_property(sdk.la_device_property_e_MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY, 1)
            # device.set_bool_property(sdk.la_device_property_e_LC_FORCE_FORWARD_THROUGH_FABRIC_MODE, True)

    @classmethod
    def setUpClass(cls):
        super(test_ip_multicast_lc, cls).setUpClass(device_id=cls.DEVICE_ID,
                                                    slice_modes=cls.SLICE_MODES,
                                                    device_config_func=test_ip_multicast_lc.device_config_func)

    @staticmethod
    def get_mc_sa_addr_str(ip_addr):
        octets = ip_addr.addr_str.split('.')
        assert(len(octets) == 4)
        sa_addr_str = '01:00:5e'
        sa_addr_str += ':%02x' % (0x7f & int(octets[1]))
        for o in octets[2:]:
            sa_addr_str += ':%02x' % (int(o))
        return sa_addr_str

    def setUp(self):
        super().setUp(create_default_topology=False)
        self.topology.create_inject_ports()
        self.topology.create_default_profiles()
        self.device.set_is_fabric_time_master(True)
        self.mph = mac_port_helper.mac_port_helper()
        self.mph.verbose = False
        self.mph.init(self.device)
        self.create_fabric_ports()

        if self.device.get_ll_device().get_device_revision() == sdk.la_device_revision_e_PACIFIC_B1:
            # needed for mcg counters
            silent_rcy_port = T.recycle_sys_port(self, self.device, 0, 1, 100)
            silent_rcy_port = T.recycle_sys_port(self, self.device, 1, 1, 101)
            silent_rcy_port = T.recycle_sys_port(self, self.device, 2, 1, 102)

        self.create_network_ports_and_topology()
        self.create_packets()

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
        self.fabric_port.set_reachable_lc_devices([self.DEVICE_ID])

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

    def create_network_ports_and_topology(self):
        self.vrf = T.vrf(self, self.device, VRF_GID)

        # Create input AC port
        self.in_eth_port = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_SERDES_FIRST, IN_SERDES_LAST)
        self.in_ac_port = T.l3_ac_port(self, self.device, AC_PORT_GID_BASE, self.in_eth_port, self.vrf, L3_AC_MAC, VLAN1, VLAN2)
        self.in_ac_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        self.out_eth_port1 = T.ethernet_port(
            self,
            self.device,
            OUT_SLICE1,
            OUT_IFG1,
            SYS_PORT_GID_BASE + 1,
            OUT_SERDES_FIRST1,
            OUT_SERDES_LAST1)
        self.out_ac_port1 = T.l3_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 1,
            self.out_eth_port1,
            self.vrf,
            L3_AC_MAC,
            VLAN1,
            VLAN2)

        self.out_eth_port2 = T.ethernet_port(
            self,
            self.device,
            OUT_SLICE2,
            OUT_IFG2,
            SYS_PORT_GID_BASE + 2,
            OUT_SERDES_FIRST2,
            OUT_SERDES_LAST2)
        self.out_ac_port2 = T.l3_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 2,
            self.out_eth_port2,
            self.vrf,
            L3_AC_MAC,
            VLAN1 + 1,
            VLAN2)

        # Create multicast group
        self.device.set_int_property(sdk.la_device_property_e_MULTICAST_MCID_SCALE_THRESHOLD, 1 << 15)
        self.mc_group = self.device.create_ip_multicast_group(MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(self.mc_group)

        self.vrf.hld_obj.add_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, MC_GROUP_ADDR.hld_obj,
                                                  self.mc_group, None, False, False, None)

        # Add the output AC ports to the MC group
        self.out_sys_port1 = self.out_eth_port1.hld_obj.get_system_port()
        self.out_sys_port2 = self.out_eth_port2.hld_obj.get_system_port()
        self.mc_group.add(self.out_ac_port1.hld_obj, None, self.out_sys_port1)
        self.mc_group.add(self.out_ac_port2.hld_obj, None, self.out_sys_port2)

    def create_packets(self):
        in_packet_base = Ether(dst=test_ip_multicast_lc.get_mc_sa_addr_str(MC_GROUP_ADDR),
                               src=SA.addr_str,
                               type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=VLAN1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN2) / \
            IP(src=SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=TTL) / \
            TCP() / Raw(load=PACKET_LOAD)

        out_packet_base = Ether(dst=test_ip_multicast_lc.get_mc_sa_addr_str(MC_GROUP_ADDR), src=L3_AC_MAC.addr_str) / \
            IP(src=SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=TTL - 1) / \
            TCP() / Raw(load=PACKET_LOAD)

        self.in_packet, self.out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

    def do_test_route(self):
        # Run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE1, 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
        expected_packets.append({'data': self.out_packet, 'slice': OUT_SLICE2, 'ifg': OUT_IFG2, 'pif': OUT_SERDES_FIRST2})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def test_ip_multicast(self):
        self.do_test_route()

        # Ingress Replication tests
        # test1 - cannot create ingress replication group with scaled mcid
        # with self.assertRaises(sdk.InvalException):
        #self.mc_ingress_group = self.device.create_ip_multicast_group(0x10ab3, sdk.la_replication_paradigm_e_INGRESS)

        # test2 - cannot add member with scaled mcid to ingress replication group
        self.mc_ingress_group = self.device.create_ip_multicast_group(0x13, sdk.la_replication_paradigm_e_INGRESS)
        self.sub_group = self.device.create_ip_multicast_group(0x10ab3, sdk.la_replication_paradigm_e_EGRESS)
        with self.assertRaises(sdk.InvalException):
            self.mc_ingress_group.add(self.sub_group)
        self.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, MC_GROUP_ADDR.hld_obj)

        # test3 - with ingress and sub groups
        self.vrf.hld_obj.add_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, MC_GROUP_ADDR.hld_obj,
                                                  self.mc_ingress_group, None, False, False, None)
        # test empty ingress group
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # test empty member group
        self.sub_group1 = self.device.create_ip_multicast_group(0x14, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_ingress_group.add(self.sub_group1)
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # test port addition/removal notification in member group
        self.sub_group1.add(self.out_ac_port1.hld_obj, None, self.out_sys_port1)
        self.sub_group1.add(self.out_ac_port2.hld_obj, None, self.out_sys_port2)
        self.do_test_route()
        self.mc_ingress_group.remove(self.sub_group1)
        self.device.destroy(self.sub_group1)

        # test with non-empty member group
        self.mc_ingress_group.add(self.mc_group)
        self.do_test_route()
        self.mc_ingress_group.remove(self.mc_group)

        # test4 - with ingress and ports
        self.mc_ingress_group.add(self.out_ac_port1.hld_obj, None, self.out_sys_port1)
        self.mc_ingress_group.add(self.out_ac_port2.hld_obj, None, self.out_sys_port2)
        self.do_test_route()
        self.mc_ingress_group.set_replication_paradigm(sdk.la_replication_paradigm_e_EGRESS)
        self.do_test_route()
        self.mc_ingress_group.remove(self.out_ac_port1.hld_obj, None)
        self.mc_ingress_group.remove(self.out_ac_port2.hld_obj, None)

        self.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, MC_GROUP_ADDR.hld_obj)
        self.device.destroy(self.mc_ingress_group)

        # test5 - Change replication paradigm
        # with self.assertRaises(sdk.InvalException):
        #    self.sub_group.set_replication_paradigm(sdk.la_replication_paradigm_e_INGRESS)

        self.vrf.hld_obj.add_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, MC_GROUP_ADDR.hld_obj,
                                                  self.mc_group, None, False, False, None)
        self.do_test_route()

        self.mc_group.set_replication_paradigm(sdk.la_replication_paradigm_e_INGRESS)
        self.do_test_route()

        self.mc_group.set_replication_paradigm(sdk.la_replication_paradigm_e_EGRESS)
        self.do_test_route()

        self.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, MC_GROUP_ADDR.hld_obj)


if __name__ == '__main__':
    unittest.main()
