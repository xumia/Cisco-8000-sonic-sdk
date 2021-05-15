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

import sys

import unittest
from leaba import sdk

import hld_sim_utils
import sim_utils
from scapy.all import *
import topology as T
from packet_test_utils import *
import rtl_test_utils
from ip_test_base import *

import pdb
import nplapicli
from npu_db_access_utils import npu_db_access_header_template

IN_SLICE = 0
IN_IFG = 0
IN_SERDES = 0
IN_SP_GID = 17
IN_AC_GID = 260

OUT_SLICE = 1
OUT_IFG = 1
OUT_SERDES = 2
OUT_SP_GID = 29
OUT_AC_GID = 300

OUT_SLICE2 = 2
OUT_IFG2 = 0
OUT_SERDES2 = 0
OUT_SP_GID2 = 30
OUT_SPA_GID2 = 50
OUT_AC_GID2 = 301

SWITCH_GID = 490
VRF_GID = 555
NH_GID = 49

PUNT_INJECT_SLICE = OUT_SLICE  # must be an even number
PUNT_INJECT_IFG = OUT_IFG
PUNT_INJECT_PIF_FIRST = OUT_SERDES
PUNT_INJECT_SP_GID = OUT_SP_GID
PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xA13

VLAN1 = 0xBB7
VLAN2 = 0x0
VLAN3 = 0xAA3

SRC_MAC = "00:33:44:55:b5:84"
IN_MAC = "00:bd:89:0f:b5:84"
IN_MAC2 = "00:bd:89:0f:b5:85"
OUT_MAC = "00:be:38:f3:f7:56"
DEST_MAC = "00:af:83:3f:cc:aa"

SIP = '12.10.12.10'
DIP = '82.81.95.250'


class ra_unit_test(unittest.TestCase):

    socket_port = 0
    use_socket = False
    compare_expected = False
    is_full_chip = False
    inject_from_npu_host = False
    restore_mems_init = False  # Used for run-restore option with socket
    restore_full_init = False  # Used for run-restore option with socket
    skip_arc_microcode = False  # Used for skipping ARC microcode - used for init sequence debug only
    debug_mode = False

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
        if (ra_unit_test.debug_mode):
            import pdb
            print('Enterring debug mode. use \'interact\' to enter interactive mode')
            pdb.set_trace()
        if getattr(self, 'is_rtl', False):
            # Inform RTL to stop simulation
            self.device.sim.stop_simulation()
            # Set logger off (before destroy - no need the destroy writes on RTL)
            self.device.logger_off()
        # Destroy inject ports and device
        if self.topology_created:
            self.topo.destroy_inject_ports()
        self.device.tearDown()

    def init_device(self):
        self.device = sim_utils.create_hw_device('/dev/uio0', 0)

        self.topo = T.topology(self, self.device, create_default_topology=False)
        self.topo.create_inject_ports()
        self.topology_created = True

        self.ll_device = self.device.get_ll_device()
        self.tree = sim_utils.get_device_tree(self.ll_device)

    def ra_device_config_func(device, init_phase):
        print('ra_device_config_func called, init_phase={}'.format(init_phase))

        if (init_phase is sdk.la_device.init_phase_e_CREATED):
            device.set_bool_property(sdk.la_device_property_e_RTL_SIMULATION_WORKAROUNDS, True)
            device.set_bool_property(sdk.la_device_property_e_PROCESS_INTERRUPTS, False)

        return

    def init_ra(self):
        self.device = hld_sim_utils.create_ra_device('/dev/testdev/rtl',
                                                     dev_id=1,
                                                     use_socket=ra_unit_test.use_socket,
                                                     port=ra_unit_test.socket_port,
                                                     block_filter_getter=self.block_filter_getter,
                                                     create_sim=True,
                                                     device_config_func=ra_unit_test.ra_device_config_func,
                                                     inject_from_npu_host=ra_unit_test.inject_from_npu_host,
                                                     restore_full_init=ra_unit_test.restore_full_init,
                                                     restore_mems_init=ra_unit_test.restore_mems_init,
                                                     skip_arc_microcode=ra_unit_test.skip_arc_microcode,
                                                     add_inject_up_header_if_inject_from_npuh=True)
        # Set device handlers
        self.ll_device = self.device.get_ll_device()
        self.tree = sim_utils.get_device_tree(self.ll_device)

        # Set local learning (not system)
        self.device.set_learn_mode(sdk.la_device.learn_mode_e_LOCAL)

        self.topo = T.topology(self, self.device, create_default_topology=False)
        self.topo.create_inject_ports()
        self.topology_created = True
        setattr(self, 'is_rtl', True)

    def init_nsim(self):
        self.device = sim_utils.create_test_device('/dev/testdev', 1, enable_logging=True)

        self.topo = T.topology(self, self.device, create_default_topology=False)
        self.topo.create_inject_ports()
        self.topology_created = True

        self.ll_device = self.device.get_ll_device()
        self.tree = sim_utils.get_device_tree(self.ll_device)
        setattr(self, 'is_rtl', False)

    def init_ra_for_udc(self):
        # put inject up header as false since we do not need inject up header for non-network/fabric application
        self.device = hld_sim_utils.create_ra_device('/dev/testdev/rtl',
                                                     dev_id=1,
                                                     use_socket=ra_unit_test.use_socket,
                                                     port=ra_unit_test.socket_port,
                                                     block_filter_getter=self.block_filter_getter,
                                                     create_sim=True,
                                                     device_config_func=ra_unit_test.ra_device_config_func,
                                                     inject_from_npu_host=ra_unit_test.inject_from_npu_host,
                                                     restore_full_init=ra_unit_test.restore_full_init,
                                                     restore_mems_init=ra_unit_test.restore_mems_init,
                                                     slice_modes=6 * [sdk.la_slice_mode_e_UDC],
                                                     skip_arc_microcode=True,
                                                     add_inject_up_header_if_inject_from_npuh=False)
        # Set device handlers
        self.ll_device = self.device.get_ll_device()
        self.tree = sim_utils.get_device_tree(self.ll_device)

        self.topo = T.topology(self, self.device, create_default_topology=False)
        self.topo.create_inject_ports()
        self.topology_created = True

    def init_nsim_for_udc(self):
        self.device = sim_utils.create_test_device('/dev/testdev', 1, slice_modes=6 *
                                                   [sdk.la_slice_mode_e_UDC], enable_logging=True)

        self.topo = T.topology(self, self.device, create_default_topology=False)
        self.topo.create_inject_ports()
        self.topology_created = True

        self.ll_device = self.device.get_ll_device()
        self.tree = sim_utils.get_device_tree(self.ll_device)

    def perform_simple_read_write(self):
        self.ll_device.read_register(self.tree.cdb.top.learn_manager_cfg_max_learn_type)
        self.ll_device.write_register(self.tree.cdb.top.learn_manager_cfg_max_learn_type, 0x1)
        self.ll_device.read_register(self.tree.cdb.top.learn_manager_cfg_max_learn_type)
        self.ll_device.write_register(self.tree.cdb.top.learn_manager_cfg_max_learn_type, 0x2)

    def p2p_config(self):

        self.in_packet = \
            Ether(dst=IN_MAC, src=SRC_MAC, type=0x8100) / \
            Dot1Q(vlan=VLAN1) / \
            IP(src=SIP, dst=DIP, ttl=10) / \
            TCP() / Raw(load='\xAB\xCD')

        self.out_packet = self.in_packet

        self.in_eth_port = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, IN_SP_GID, IN_SERDES, IN_SERDES)
        self.out_eth_port = T.ethernet_port(self, self.device, OUT_SLICE, OUT_IFG, OUT_SP_GID, OUT_SERDES, OUT_SERDES)

        self.in_ac_port = T.l2_ac_port(self, self.device, IN_AC_GID, None, None, self.in_eth_port, None, VLAN1, VLAN2)
        self.out_ac_port = T.l2_ac_port(self, self.device, OUT_AC_GID, None, None, self.out_eth_port, None, VLAN1, VLAN2)

        self.in_ac_port.hld_obj.set_destination(self.out_ac_port.hld_obj)
        self.out_ac_port.hld_obj.set_destination(self.in_ac_port.hld_obj)

    def p2p_trap_config(self):
        # The expected packet in this test assumes that the injection is not from NPU host. i.e. when running the "ra" flavor, there the INJECT_FROM_NPU_HOST flag is off.
        # When punting, the whole original packet is punted. So if the original packet has inject header, it'll also be punted. But this function doesn't know the flavor.
        # So to fix, need to fix the set_expected_packet to plant the same inject
        # header that it adds to the in_packet, also to the out_packet,
        # specifically  between the Eth->Dot1Q->Punt and the Ether->Dot1Q->IP

        # This should trap in SA==DA
        self.in_packet = \
            Ether(dst=IN_MAC, src=IN_MAC, type=0x8100) / \
            Dot1Q(vlan=VLAN1) / \
            IP(src=SIP, dst=DIP, ttl=10) / \
            TCP() / Raw(load='\xAB\xCD')

        # This is the punt packet
        self.out_packet = Ether(dst=HOST_MAC_ADDR,
                                src=PUNT_INJECT_PORT_MAC_ADDR,
                                type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0,
                  id=0,
                  vlan=PUNT_VLAN,
                  type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                 next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                 code=sdk.LA_EVENT_ETHERNET_SA_DA_ERROR + 32,
                 source_sp=IN_SP_GID,
                 destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=IN_AC_GID,
                 destination_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID,
                 relay_id=0,
                 lpts_flow_type=0) / \
            Ether(dst=IN_MAC,
                  src=IN_MAC,
                  type=0x8100) / \
            Dot1Q(vlan=VLAN1) / \
            IP(src=SIP,
               dst=DIP,
               ttl=10) / \
            TCP() / \
            Raw(load='\xAB\xCD')

        self.in_eth_port = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, IN_SP_GID, IN_SERDES, IN_SERDES)

        self.in_ac_port = T.l2_ac_port(self, self.device, IN_AC_GID, None, None, self.in_eth_port, None, VLAN1, VLAN2)

        self.in_ac_port.hld_obj.set_destination(self.in_ac_port.hld_obj)

        pi_port = T.punt_inject_port(
            self,
            self.device,
            PUNT_INJECT_SLICE,
            PUNT_INJECT_IFG,
            PUNT_INJECT_SP_GID,
            PUNT_INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID, pi_port, HOST_MAC_ADDR, PUNT_VLAN)

        priority = 0
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR, priority, None, punt_dest, False, False, True, 0)

    def p2p_eve_config(self):

        self.in_packet = \
            Ether(dst=IN_MAC, src=SRC_MAC, type=0x8100) / \
            Dot1Q(vlan=VLAN1) / \
            IP(src=SIP, dst=DIP, ttl=10) / \
            TCP() / Raw(load='\xAB\xCD')

        self.out_packet = \
            Ether(dst=IN_MAC, src=SRC_MAC, type=0x8100) / \
            Dot1Q(vlan=VLAN3) / \
            IP(src=SIP, dst=DIP, ttl=10) / \
            TCP() / Raw(load='\xAB\xCD')

        self.in_eth_port = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, IN_SP_GID, IN_SERDES, IN_SERDES)
        self.out_eth_port = T.ethernet_port(self, self.device, OUT_SLICE, OUT_IFG, OUT_SP_GID, OUT_SERDES, OUT_SERDES)

        self.in_ac_port = T.l2_ac_port(self, self.device, IN_AC_GID, None, None, self.in_eth_port, None, VLAN1, VLAN2)
        self.out_ac_port = T.l2_ac_port(self, self.device, OUT_AC_GID, None, None, self.out_eth_port, None, VLAN1, VLAN2)

        self.in_ac_port.hld_obj.set_destination(self.out_ac_port.hld_obj)
        self.out_ac_port.hld_obj.set_destination(self.in_ac_port.hld_obj)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 1
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN3
        self.out_ac_port.hld_obj.set_egress_vlan_edit_command(eve)

    def p2p_spa_config(self):
        self.in_packet1 = \
            Ether(dst=IN_MAC, src=SRC_MAC, type=0x8100) / \
            Dot1Q(vlan=VLAN1) / \
            IP(src=SIP, dst=DIP, ttl=10) / \
            TCP() / Raw(load='\xAB\xCD')

        self.in_packet2 = \
            Ether(dst=IN_MAC2, src=SRC_MAC, type=0x8100) / \
            Dot1Q(vlan=VLAN1) / \
            IP(src=SIP, dst=DIP, ttl=10) / \
            TCP() / Raw(load='\xAB\xCD')

        self.out_packet1 = self.in_packet1
        self.out_packet2 = self.in_packet2

        # create RX L2 service port
        self.in_eth_port = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, IN_SP_GID, IN_SERDES, IN_SERDES)
        self.in_ac_port = T.l2_ac_port(self, self.device, IN_AC_GID, None, None, self.in_eth_port, None, VLAN1, VLAN2)

        # create TX L2 serivce port over SPA
        self.out_mac_port1 = T.mac_port(self, self.device, OUT_SLICE, OUT_IFG, OUT_SERDES, OUT_SERDES)
        self.out_mac_port2 = T.mac_port(self, self.device, OUT_SLICE2, OUT_IFG2, OUT_SERDES2, OUT_SERDES2)

        self.out_sys_port1 = T.system_port(self, self.device, OUT_SP_GID, self.out_mac_port1)
        self.out_sys_port2 = T.system_port(self, self.device, OUT_SP_GID2, self.out_mac_port2)

        self.out_spa_port = T.spa_port(self, self.device, OUT_SPA_GID2)
        self.out_spa_port.add(self.out_sys_port1)
        self.out_spa_port.add(self.out_sys_port2)

        self.out_eth_port = T.sa_ethernet_port(self, self.device, self.out_spa_port)
        self.out_ac_port = T.l2_ac_port(self, self.device, OUT_AC_GID, None, None, self.out_eth_port, None, VLAN1, VLAN2)

        # create p2p forwarder
        self.in_ac_port.hld_obj.set_destination(self.out_ac_port.hld_obj)
        self.out_ac_port.hld_obj.set_destination(self.in_ac_port.hld_obj)

        lb_vec1 = sdk.la_lb_vector_t()
        dst_mac1 = T.mac_addr(self.in_packet1[Ether].dst)
        src_mac1 = T.mac_addr(self.in_packet1[Ether].src)
        lb_vec1.type = sdk.LA_LB_VECTOR_ETHERNET_VLAN_TAG
        lb_vec1.ethernet.vlan_id = VLAN1
        lb_vec1.ethernet.da = dst_mac1.hld_obj
        lb_vec1.ethernet.sa = src_mac1.hld_obj

        out_dest_chain1 = self.device.get_forwarding_load_balance_chain(self.out_spa_port.hld_obj, lb_vec1)
        self.assertEqual(out_dest_chain1[-1].type(), sdk.la_object.object_type_e_SYSTEM_PORT)
        self.out_dsp1 = out_dest_chain1[-1].downcast()

        lb_vec2 = sdk.la_lb_vector_t()
        dst_mac2 = T.mac_addr(self.in_packet2[Ether].dst)
        src_mac2 = T.mac_addr(self.in_packet2[Ether].src)
        lb_vec2.type = sdk.LA_LB_VECTOR_ETHERNET_VLAN_TAG
        lb_vec2.ethernet.vlan_id = VLAN1
        lb_vec2.ethernet.da = dst_mac2.hld_obj
        lb_vec2.ethernet.sa = src_mac2.hld_obj

        out_dest_chain2 = self.device.get_forwarding_load_balance_chain(self.out_spa_port.hld_obj, lb_vec2)
        self.assertEqual(out_dest_chain2[-1].type(), sdk.la_object.object_type_e_SYSTEM_PORT)
        self.out_dsp2 = out_dest_chain2[-1].downcast()

    def bridging_config(self):

        self.in_packet = \
            Ether(dst=IN_MAC, src=SRC_MAC, type=0x8100) / \
            Dot1Q(vlan=VLAN1) / \
            IP(src=SIP, dst=DIP, ttl=10) / \
            TCP() / Raw(load='\xAB\xCD')

        self.out_packet = \
            Ether(dst=IN_MAC, src=SRC_MAC, type=0x8100) / \
            Dot1Q(vlan=VLAN3) / \
            IP(src=SIP, dst=DIP, ttl=10) / \
            TCP() / Raw(load='\xAB\xCD')

        self.dest_mac = T.mac_addr(IN_MAC)

        self.switch = T.switch(self, self.device, SWITCH_GID)

        self.in_eth_port = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, IN_SP_GID, IN_SERDES, IN_SERDES)
        self.out_eth_port = T.ethernet_port(self, self.device, OUT_SLICE, OUT_IFG, OUT_SP_GID, OUT_SERDES, OUT_SERDES)

        # configure input AC port with IVE
        self.in_ac_port = T.l2_ac_port(self, self.device, IN_AC_GID, None, self.switch, self.in_eth_port, None, VLAN1, VLAN2)

        # TODO: this command does not work. Once fixed, need to uncomment and change
        # the expected output packet accordingly
        #       ive = sdk.la_vlan_edit_command()
        #       ive.num_tags_to_push = 0
        #       ive.num_tags_to_pop = 1
        #       status = self.in_ac_port.hld_obj.set_ingress_vlan_edit_command(ive)
        #       self.assertEqual(status, sdk.la_status_e_SUCCESS)

        # configure output AC port with EVE
        self.out_ac_port = T.l2_ac_port(self, self.device, OUT_AC_GID, None, self.switch, self.out_eth_port, None, VLAN1, VLAN2)
        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 1
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = VLAN3
        self.out_ac_port.hld_obj.set_egress_vlan_edit_command(eve)

        self.switch.hld_obj.set_mac_entry(
            self.dest_mac.hld_obj,
            self.out_ac_port.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

    def routing_config(self):

        self.in_packet = \
            Ether(dst=IN_MAC, src=SRC_MAC, type=0x8100) / \
            Dot1Q(vlan=VLAN1) / \
            IP(src=SIP, dst=DIP, ttl=10) / \
            TCP() / Raw(load='\xAB\xCD\xAB\xCD\xAB\xCD\xAB\xCD\xAB\xCD\xAB\xCD\xAB\xCD')

        self.out_packet = \
            Ether(dst=DEST_MAC, src=OUT_MAC) / \
            IP(src=SIP, dst=DIP, ttl=9) / \
            TCP() / Raw(load='\xAB\xCD\xAB\xCD\xAB\xCD\xAB\xCD\xAB\xCD\xAB\xCD\xAB\xCD')

        # mac addresses
        self.in_mac = T.mac_addr(IN_MAC)
        self.out_mac = T.mac_addr(OUT_MAC)
        self.dest_mac = T.mac_addr(DEST_MAC)
        self.src_mac = T.mac_addr(SRC_MAC)

        # IP addresses
        self.SIP = T.ipv4_addr(SIP)
        self.DIP = T.ipv4_addr(DIP)

        self.vrf = T.vrf(self, self.device, VRF_GID)

        self.in_eth_port = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, IN_SP_GID, IN_SERDES, IN_SERDES)
        self.out_eth_port = T.ethernet_port(self, self.device, OUT_SLICE, OUT_IFG, OUT_SP_GID, OUT_SERDES, OUT_SERDES)

        self.in_ac_port = T.l3_ac_port(self, self.device, IN_AC_GID, self.in_eth_port, self.vrf, self.in_mac, VLAN1, VLAN2)
        self.in_ac_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        self.out_ac_port = T.l3_ac_port(self, self.device, OUT_AC_GID, self.out_eth_port, self.vrf, self.out_mac, VLAN1, VLAN2)
        self.out_ac_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        self.next_hop = T.next_hop(self, self.device, NH_GID, self.dest_mac, self.out_ac_port)

        self.prefix = sdk.la_ipv4_prefix_t()
        self.prefix.length = 32
        self.prefix.addr.s_addr = ipv4_test_base.apply_prefix_mask(self.DIP.to_num(), self.prefix.length)

        self.vrf.hld_obj.add_ipv4_route(self.prefix, self.next_hop.hld_obj, 0, True)

    def check_valid_trap_mem(self):
        for npe_eng in ["rxpp_term", "rxpp_fwd", "txpp"]:
            valid_line = 0
            valid_range = False
            for line in range(128):
                npe = self.tree.slice[0].npu.__getattribute__(npe_eng).npe
                (k, m, valid) = self.ll_device.read_tcam(npe.traps_tcam, line)

                if valid and not valid_range:
                    valid_range = True
                    valid_line = line

                self.assertEqual(valid, valid_range)

    def test_ra_bridging(self):
        self.init_ra()
        self.bridging_config()

        # Enable only for RA testing
        if ra_unit_test.compare_expected:
            expected_dir = os.path.dirname(os.path.realpath(__file__))
            expected_file = expected_dir + '/ra_unit_test.bridging.expected.gz'

            rtl_test_utils.compare_vs_expected(self.device.get_ll_device(), expected_file)

        self.device.get_simulator().set_expected_packet(OUT_SLICE, OUT_IFG, OUT_SERDES, self.out_packet)
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES)

    def test_nsim_bridging(self):
        self.init_nsim()
        self.bridging_config()

        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES)

    def _test_device_bridging(self):
        self.init_device()
        self.bridging_config()

        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES)

    def test_ra_simple_read_write_with_rtl(self):
        self.init_ra()
        self.perform_simple_read_write()

    def test_ra_p2p(self):
        self.init_ra()
        self.p2p_config()

        self.device.get_simulator().set_expected_packet(OUT_SLICE, OUT_IFG, OUT_SERDES, self.out_packet)
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES)

    def test_nsim_p2p(self):
        self.init_nsim()
        self.p2p_config()

        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES)

    def test_ra_udc_nop(self):
        self.init_ra_for_udc()

        self.udc_nop_config()

        self.device.get_simulator().set_expected_packet(OUT_SLICE, OUT_IFG, OUT_SERDES, self.out_packet)

        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES)

    def _test_nsim_udc_nop(self):
        self.init_nsim_for_udc()

        self.udc_nop_config()

        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES)

    def test_ra_udc_db_access(self):
        self.init_ra_for_udc()

        self.udc_db_access_config()

        self.device.get_simulator().set_expected_packet(OUT_SLICE, OUT_IFG, OUT_SERDES, self.out_packet)

        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES)

    def test_nsim_udc_db_access(self):
        self.init_nsim_for_udc()

        self.udc_db_access_config()

        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES)

    def test_ra_p2p_eve(self):
        self.init_ra()
        self.p2p_eve_config()

        self.device.get_simulator().set_expected_packet(OUT_SLICE, OUT_IFG, OUT_SERDES, self.out_packet)
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES)

    def test_nsim_p2p_eve(self):
        self.init_nsim()
        self.p2p_eve_config()

        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES)

    def test_ra_p2p_spa(self):
        self.init_ra()
        self.p2p_spa_config()

        self.device.get_simulator().set_expected_packet(
            self.out_dsp1.get_slice(),
            self.out_dsp1.get_ifg(),
            self.out_dsp1.get_base_serdes(),
            self.out_packet1)
        run_and_compare(
            self,
            self.device,
            self.in_packet1,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet1,
            self.out_dsp1.get_slice(),
            self.out_dsp1.get_ifg(),
            self.out_dsp1.get_base_serdes())

        self.device.get_simulator().set_expected_packet(
            self.out_dsp2.get_slice(),
            self.out_dsp2.get_ifg(),
            self.out_dsp2.get_base_serdes(),
            self.out_packet2)
        run_and_compare(
            self,
            self.device,
            self.in_packet2,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet2,
            self.out_dsp2.get_slice(),
            self.out_dsp2.get_ifg(),
            self.out_dsp2.get_base_serdes())

    def test_nsim_p2p_spa(self):
        self.init_nsim()
        self.p2p_spa_config()

        run_and_compare(
            self,
            self.device,
            self.in_packet1,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet1,
            self.out_dsp1.get_slice(),
            self.out_dsp1.get_ifg(),
            self.out_dsp1.get_base_serdes())

        run_and_compare(
            self,
            self.device,
            self.in_packet2,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet2,
            self.out_dsp2.get_slice(),
            self.out_dsp2.get_ifg(),
            self.out_dsp2.get_base_serdes())

    unittest.skipIf(True, "Test fails due to differences in actual and expected punt packet")

    def test_nsim_p2p_trap(self):
        self.init_nsim()
        self.p2p_trap_config()

        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES)

    def test_ra_p2p_trap(self):
        self.init_ra()
        self.p2p_trap_config()

        self.device.get_simulator().set_expected_packet(OUT_SLICE, OUT_IFG, OUT_SERDES, self.out_packet)

        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES)

    def udc_nop_config(self):

        self.in_packet = \
            Ether(dst=IN_MAC, src=SRC_MAC, type=0x8100) / \
            Dot1Q(vlan=VLAN1) / \
            IP(src=SIP, dst=DIP, ttl=10) / \
            TCP() / Raw(load='\xAB\xCD')

        self.out_packet = self.in_packet

        self.in_eth_port = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, IN_SP_GID, IN_SERDES, IN_SERDES)
        self.out_eth_port = T.ethernet_port(self, self.device, OUT_SLICE, OUT_IFG, OUT_SP_GID, OUT_SERDES, OUT_SERDES)

        tabs = self.device.get_device_tables()
        first_macro_table = tabs.source_pif_hw_table
        # Rx First macro table config for nop application
        rx_k = nplapicli.npl_source_pif_hw_table_key_t()
        rx_v = nplapicli.npl_source_pif_hw_table_value_t()
        if self.ll_device.is_pacific():
            udc_pif_num = 20
        else:  # Gibraltar
            udc_pif_num = 26

        for slice in range(6):
            rx_macro_table = tabs.source_pif_hw_table[slice]
            for ifg in range(2):
                for pif in range(udc_pif_num):
                    rx_k.rxpp_npu_input_ifg = ifg
                    rx_k.rxpp_npu_input_ifg_rx_fd_source_pif = pif
                    rx_v.payloads.init_rx_data.fi_macro_id = nplapicli.NPL_FI_MACRO_ID_ETH
                    rx_v.payloads.init_rx_data.np_macro_id = nplapicli.NPL_NOP_USER_APPLICATION_RX_TERM_NOP_MACRO
                    if (self.ll_device.is_gibraltar()):
                        rx_v.payloads.init_rx_data.first_header_is_layer = 1
            # rx_v.payloads.init_rx_data.initial_layer_index = ... <Put whatever you need here..>
            # rx_v.payloads.init_rx_data.initial_rx_data = ... <Put whatever you need here..>
                    rx_macro_table.set(rx_k, rx_v)

        dest_k = nplapicli.npl_per_port_destination_table_key_t()
        dest_v = nplapicli.npl_per_port_destination_table_value_t()

        # config destination
        dest_table = tabs.per_port_destination_table[IN_SLICE]
        dest_k.device_rx_source_if_ifg = self.get_actual_ifg(IN_SLICE, IN_IFG)
        dest_k.device_rx_source_if_pif = IN_SERDES
        dest_v.payloads.destination_local_vars_fwd_destination = nplapicli.NPL_DESTINATION_MASK_DSP | OUT_SP_GID
        dest_table.set(dest_k, dest_v)

        ## Tx First macro table config example ##
        tx_k = nplapicli.npl_txpp_initial_npe_macro_table_key_t()
        tx_m = nplapicli.npl_txpp_initial_npe_macro_table_key_t()
        tx_v = nplapicli.npl_txpp_initial_npe_macro_table_value_t()

        for slice in range(1):
            tx_macro_table = tabs.txpp_initial_npe_macro_table[slice]
            # Hit all ...
            if (self.ll_device.is_pacific()):
                tx_k.txpp_first_macro_table_key.fwd_type = 0
                tx_m.txpp_first_macro_table_key.fwd_type = 0
                tx_k.txpp_first_macro_table_key.first_encap_type = 0
                tx_m.txpp_first_macro_table_key.first_encap_type = 0
                tx_k.txpp_first_macro_table_key.is_mc = 0
                tx_m.txpp_first_macro_table_key.is_mc = 0
                tx_k.txpp_first_macro_table_key.second_encap_type = 0
                tx_m.txpp_first_macro_table_key.second_encap_type = 0
            else:  # Gibraltar
                tx_k.txpp_first_macro_table_key.fwd_type = 0
                tx_m.txpp_first_macro_table_key.fwd_type = 0
                tx_k.txpp_first_macro_table_key.encap_type = 0
                tx_m.txpp_first_macro_table_key.encap_type = 0
                tx_k.txpp_first_macro_table_key.is_mc = 0
                tx_m.txpp_first_macro_table_key.is_mc = 0
                tx_k.txpp_first_macro_table_key.field_a = 0
                tx_m.txpp_first_macro_table_key.field_a = 0
                tx_k.txpp_first_macro_table_key.field_b = 0
                tx_m.txpp_first_macro_table_key.field_b = 0
            tx_v.payloads.init_tx_data.np_macro_id = nplapicli.NPL_NOP_USER_APPLICATION_TX_TRANSMIT_MACRO
            tx_macro_table.set(0, tx_k, tx_m, tx_v)

    def udc_db_access_config(self):

        # Incoming packet
        raw_in_term_common_header = npu_db_access_header_template.npu_db_access_app_get_common_header(1)
        raw_in_term_access_header = npu_db_access_header_template.npu_db_access_app_get_term_lu_header(nplapicli.NPL_LU_A_TERM_NOP,
                                                                                                       nplapicli.NPL_LU_B_TERM_NOP,
                                                                                                       nplapicli.NPL_LU_C_TERM_NOP,
                                                                                                       nplapicli.NPL_LU_D_TERM_NOP,
                                                                                                       nplapicli.NPL_RES_A_TERM_NOP,
                                                                                                       nplapicli.NPL_RES_B_TERM_NOP,
                                                                                                       nplapicli.NPL_RES_C_TERM_NOP,
                                                                                                       nplapicli.NPL_RES_D_TERM_NOP,
                                                                                                       0,
                                                                                                       0,
                                                                                                       0,
                                                                                                       0)

        raw_in_fwd_common_header = npu_db_access_header_template.npu_db_access_app_get_common_header(2)
        raw_in_fwd_access_header = npu_db_access_header_template.npu_db_access_app_get_fwd_lu_header(nplapicli.NPL_LU_A_FWD_NOP,
                                                                                                     nplapicli.NPL_LU_B_FWD_NOP,
                                                                                                     nplapicli.NPL_LU_C_FWD_NOP,
                                                                                                     nplapicli.NPL_LU_D_FWD_NOP,
                                                                                                     nplapicli.NPL_RES_A_FWD_NOP,
                                                                                                     nplapicli.NPL_RES_B_FWD_NOP,
                                                                                                     nplapicli.NPL_RES_C_FWD_NOP,
                                                                                                     nplapicli.NPL_RES_D_FWD_NOP,
                                                                                                     0,
                                                                                                     0,
                                                                                                     0,
                                                                                                     0)

        raw_in_trans_common_header = npu_db_access_header_template.npu_db_access_app_get_common_header(3)
        raw_in_trans_access_header = npu_db_access_header_template.npu_db_access_app_get_tran_lu_header(
            nplapicli.NPL_LU_A_TRANS_NOP,
            nplapicli.NPL_LU_B_TRANS_NOP,
            nplapicli.NPL_LU_C_TRANS_NOP,
            nplapicli.NPL_LU_D_TRANS_NOP,
            nplapicli.NPL_RES_A_TRANS_NOP,
            nplapicli.NPL_RES_B_TRANS_NOP,
            nplapicli.NPL_RES_C_TRANS_NOP,
            nplapicli.NPL_RES_D_TRANS_NOP,
            0,
            0,
            0,
            0)

        hex_in_header = raw_in_trans_common_header + 5 * raw_in_trans_access_header + raw_in_term_common_header + \
            5 * raw_in_term_access_header + raw_in_fwd_common_header + 5 * raw_in_fwd_access_header
        self.in_packet = Raw(load=unhexlify(hex_in_header.encode("ascii")))
        self.out_packet = self.in_packet

        print(hex_in_header)
        self.in_packet.show()
        self.out_packet.show()

        # set the current ports (ready for snake)
        self.in_eth_port = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, IN_SP_GID, IN_SERDES, IN_SERDES)
        self.out_eth_port = T.ethernet_port(self, self.device, OUT_SLICE, OUT_IFG, OUT_SP_GID, OUT_SERDES, OUT_SERDES)

        tabs = self.device.get_device_tables()
        first_macro_table = tabs.source_pif_hw_table
        # Rx First macro table config for nop application
        rx_k = nplapicli.npl_source_pif_hw_table_key_t()
        rx_v = nplapicli.npl_source_pif_hw_table_value_t()
        if self.ll_device.is_pacific():
            udc_pif_num = 20
        else:  # Gibraltar
            udc_pif_num = 26

        # config first macro for termination
        for slice in range(6):
            rx_macro_table = tabs.source_pif_hw_table[slice]
            for ifg in range(2):
                for pif in range(udc_pif_num):
                    rx_k.rxpp_npu_input_ifg = ifg
                    rx_k.rxpp_npu_input_ifg_rx_fd_source_pif = pif
                    rx_v.payloads.init_rx_data.fi_macro_id = nplapicli.NPL_UDC_FI_MACRO_ID_DB_ACCESS_COMMON_TRANS
                    rx_v.payloads.init_rx_data.np_macro_id = nplapicli.NPL_DB_ACCESS_TERMINATION_MACRO
                    if (self.ll_device.is_gibraltar()):
                        rx_v.payloads.init_rx_data.first_header_is_layer = 1
            # rx_v.payloads.init_rx_data.initial_layer_index = ... <Put whatever you need here..>
            # rx_v.payloads.init_rx_data.initial_rx_data = ... <Put whatever you need here..>
                    rx_macro_table.set(rx_k, rx_v)

        dest_k = nplapicli.npl_db_access_per_port_destination_table_key_t()
        dest_v = nplapicli.npl_db_access_per_port_destination_table_value_t()

        # config destination
        dest_table = tabs.db_access_per_port_destination_table[IN_SLICE]
        dest_k.pd_source_if_ifg = self.get_actual_ifg(IN_SLICE, IN_IFG)
        dest_k.pd_source_if_pif = IN_SERDES
        dest_v.payloads.db_access_destination_local_vars_fwd_destination = nplapicli.NPL_DESTINATION_MASK_DSP | OUT_SP_GID
        dest_table.set(dest_k, dest_v)

        ## Tx First macro table config example ##
        tx_k = nplapicli.npl_txpp_initial_npe_macro_table_key_t()
        tx_m = nplapicli.npl_txpp_initial_npe_macro_table_key_t()
        tx_v = nplapicli.npl_txpp_initial_npe_macro_table_value_t()

        for slice in range(1):
            tx_macro_table = tabs.txpp_initial_npe_macro_table[slice]
            # Hit all ...
            if (self.ll_device.is_pacific()):
                tx_k.txpp_first_macro_table_key.fwd_type = 0
                tx_m.txpp_first_macro_table_key.fwd_type = 0
                tx_k.txpp_first_macro_table_key.first_encap_type = 0
                tx_m.txpp_first_macro_table_key.first_encap_type = 0
                tx_k.txpp_first_macro_table_key.is_mc = 0
                tx_m.txpp_first_macro_table_key.is_mc = 0
                tx_k.txpp_first_macro_table_key.second_encap_type = 0
                tx_m.txpp_first_macro_table_key.second_encap_type = 0
            else:  # Gibraltar
                tx_k.txpp_first_macro_table_key.fwd_type = 0
                tx_m.txpp_first_macro_table_key.fwd_type = 0
                tx_k.txpp_first_macro_table_key.encap_type = 0
                tx_m.txpp_first_macro_table_key.encap_type = 0
                tx_k.txpp_first_macro_table_key.is_mc = 0
                tx_m.txpp_first_macro_table_key.is_mc = 0
                tx_k.txpp_first_macro_table_key.field_a = 0
                tx_m.txpp_first_macro_table_key.field_a = 0
                tx_k.txpp_first_macro_table_key.field_b = 0
                tx_m.txpp_first_macro_table_key.field_b = 0
            tx_v.payloads.init_tx_data.np_macro_id = nplapicli.NPL_DB_ACCESS_TRANSMIT_MACRO
            tx_macro_table.set(0, tx_k, tx_m, tx_v)

        ## Tx First macro table config example ##
        tx_k = nplapicli.npl_db_access_transmit_per_dest_port_npu_host_macro_stamping_table_key_t()
        tx_v = nplapicli.npl_db_access_transmit_per_dest_port_npu_host_macro_stamping_table_value_t()

        for slice in range(6):
            tx_per_dest_pif_ifg_npu_host_stamp = tabs.db_access_transmit_per_dest_port_npu_host_macro_stamping_table[slice]
            for ifg in range(2):
                tx_k.dest_ifg = ifg
                tx_k.dest_pif = 24
                tx_v.payloads.db_access_transmit_per_dest_port_npu_host_macro_stamping.stamp_npu_host_macro_on_packet = 1
                tx_v.payloads.db_access_transmit_per_dest_port_npu_host_macro_stamping.npu_host_macro = nplapicli.NPL_NPU_HOST_TRAFFIC_GEN_RCV_DROP_MACRO
                tx_per_dest_pif_ifg_npu_host_stamp.set(tx_k, tx_v)

    def device_send_packet(self):
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES)

    def test_ra_routing(self):
        self.init_ra()
        self.routing_config()

        self.device.get_simulator().set_expected_packet(OUT_SLICE, OUT_IFG, OUT_SERDES, self.out_packet)
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES)

    def test_nsim_routing(self):
        self.init_nsim()
        self.routing_config()

        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES)

    def test_traps(self):
        self.init_ra()

        self.check_valid_trap_mem()

        trap_config_pairs = []
        for trap in range(sdk.LA_EVENT_ETHERNET_FIRST, sdk.LA_EVENT_APP_LAST + 1):
            try:
                trap_config = self.device.get_trap_configuration(trap)
                trap_config_pairs.append({'trap': trap, 'trap_config': trap_config})
            except sdk.NotFoundException as STATUS:
                pass

        # Pop first, last and one in the middle
        popped_pairs = []
        last_idx = len(trap_config_pairs) - 1
        for idx in [last_idx, 0, 22]:
            popped_pairs.append(trap_config_pairs[idx])
            trap = trap_config_pairs[idx]['trap']
            self.device.clear_trap_configuration(trap)

        self.check_valid_trap_mem()

        # Push first, last and one in the middle
        for trap_config_pair in popped_pairs:
            trap = trap_config_pair['trap']
            trap_config = trap_config_pair['trap_config']
            self.device.set_trap_configuration(trap, *trap_config)

        self.check_valid_trap_mem()

        # Erase first, last and one in the middle.
        for idx in [last_idx, 0, 44]:
            trap = trap_config_pairs[idx]['trap']
            self.device.clear_trap_configuration(trap)

        self.check_valid_trap_mem()

        # Insert into middle.
        trap_config_pair = trap_config_pairs[44]
        trap = trap_config_pair['trap']
        trap_config = trap_config_pair['trap_config']
        self.device.set_trap_configuration(trap, *trap_config)

        self.check_valid_trap_mem()

    def test_fabric_init_flow(self):
        self.device = hld_sim_utils.create_ra_device('/dev/testdev/rtl',
                                                     dev_id=1,
                                                     use_socket=ra_unit_test.use_socket,
                                                     port=ra_unit_test.socket_port,
                                                     slice_modes=hld_sim_utils.FABRIC_ELEMENT_DEV,
                                                     block_filter_getter=self.block_filter_getter,
                                                     create_sim=True,
                                                     device_config_func=ra_unit_test.ra_device_config_func,
                                                     inject_from_npu_host=False,
                                                     restore_full_init=ra_unit_test.restore_full_init,
                                                     restore_mems_init=ra_unit_test.restore_mems_init,
                                                     skip_arc_microcode=ra_unit_test.skip_arc_microcode,
                                                     add_inject_up_header_if_inject_from_npuh=True)
        self.topology_created = False

    def get_actual_ifg(self, slice_id, ifg):
        if self.ll_device.is_pacific():
            slices_to_flip = [0, 3, 4]
        elif self.ll_device.is_gibraltar():
            slices_to_flip = [1, 2, 5]
        else:
            slices_to_flip = []

        if slice_id in slices_to_flip:
            return (1 ^ ifg)
        return ifg


if __name__ == '__main__':

    args_to_remove = []
    sdk_use_socket_patt = re.compile(r'\+SDK_USE_SOCKET=(\d+)')
    for arg in sys.argv:
        match = sdk_use_socket_patt.match(arg)
        if match:
            ra_unit_test.socket_port = int(match.group(1))
            ra_unit_test.use_socket = True
            args_to_remove.append(arg)
            continue

        if 'COMPARE_EXPECTED' in arg:
            ra_unit_test.compare_expected = True
            args_to_remove.append(arg)

        if 'FULL_CHIP' in arg:
            ra_unit_test.is_full_chip = True
            args_to_remove.append(arg)

        if 'INJECT_FROM_NPU_HOST' in arg:
            ra_unit_test.inject_from_npu_host = True
            args_to_remove.append(arg)

        match = re.search(r'RESTORE_FULL_INIT', arg)
        if match:
            ra_unit_test.restore_full_init = True
            args_to_remove.append(arg)

        match = re.search(r'RESTORE_MEMS_INIT', arg)
        if match:
            ra_unit_test.restore_mems_init = True
            args_to_remove.append(arg)

        match = re.search(r'SKIP_ARC_MICROCODE', arg)
        if match:
            ra_unit_test.skip_arc_microcode = True
            args_to_remove.append(arg)

        match = re.search(r'DEBUG_MODE', arg)
        if match:
            ra_unit_test.debug_mode = True
            args_to_remove.append(arg)

    for arg in args_to_remove:
        sys.argv.remove(arg)

    unittest.main()
