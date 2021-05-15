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
import sim_utils
from scapy.all import *
from ingress_scale_lc_multicast_base import *
import unittest
from leaba import sdk
import ip_test_base
import topology as T
import time
import decor


@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
class ingress_scale_lc_multicast(ingress_scale_lc_multicast_base):
    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_scale_multicast_e_to_i_no_main_port_member(self):
        # create the multicast group
        self.init_misc()
        self.mc_group = self.device.create_ip_multicast_group(MC_GROUP_ID, sdk.la_replication_paradigm_e_EGRESS)

        # add the multicast route
        self.vrf.hld_obj.add_ipv4_multicast_route(
            self.mc_sip.hld_obj, self.mc_group_addr.hld_obj, self.mc_group, None, False, False, None)

        # change to ingress replication
        self.mc_group.set_replication_paradigm(sdk.la_replication_paradigm_e_INGRESS)

        # Add a non-scale ip egress multicast group
        # XR might not add ip subgroup
        self.mc_group2 = self.device.create_ip_multicast_group(self.non_scale_mcid, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group2.add(self.l3ac_port01.hld_obj, None, self.l3ac_ethport01.sys_port.hld_obj)
        # Add this non-scale egress mc group as a member to the scale mode ingress mc group
        # local mcid is allocated here for main group
        self.mc_group.add(self.mc_group2)
        self.add_l3ac_port01_packet(self.egress_packets)

        # Verify that 1 IP packet is generated
        # For this new non-scale egress mc group
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # Create a non-scale mpls egress multicast group, and associated nh, and prefix object
        self.mpls_mcg = self.device.create_mpls_multicast_group(self.non_scale_mcid + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.l3ac_port21_prefix_object, self.l3ac_port21_nh  = self.create_nh_pfx_obj(self.mpls_label_num,
                                                                                      self.pfx_obj_gid,
                                                                                      self.nh_gid,
                                                                                      self.l3ac_port21.hld_obj)
        # Add the prefix object to the mpls mc group
        sys_port = self.l3ac_ethport21.hld_obj.get_system_port()
        self.mpls_mcg.add(self.l3ac_port21_prefix_object, sys_port)

        # Add this non-scale egress mc group as a member to the scale mode ingress mc group
        self.mc_group.add(self.mpls_mcg)

        # Create an egress packet matching the expected output
        self.add_l3ac_port21_mpls_packet(self.egress_packets, self.mpls_label_num)

        # Run a verify that 2 packets are output, the first 1 ip multicast packet, plus a new
        # MPLS multicast packet
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # Remove the non-scale ip mcg as a member of the scale mode ingress mcp, and
        # Verify the associated packet is no longer generated.
        self.mc_group.remove(self.mc_group2)
        self.mc_group2.remove(self.l3ac_port01.hld_obj, None)
        self.device.destroy(self.mc_group2)
        self.remove_l3ac_port01_packet(self.egress_packets)
        # verfiy only mpls packet is out
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # Remove the non-scale mpls mcg as a member of the scale mode ingress mcp, and
        # Verify the associated packet is no longer generated.
        self.mc_group.remove(self.mpls_mcg)
        self.mpls_mcg.remove(self.l3ac_port21_prefix_object)
        self.device.destroy(self.mpls_mcg)
        self.remove_l3ac_port21_mpls_packet(self.egress_packets)
        # verify no packet is out
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # delete route and main group
        self.vrf.hld_obj.delete_ipv4_multicast_route(self.mc_sip.hld_obj, self.mc_group_addr.hld_obj)

        # change back to egress paradigm
        self.mc_group.set_replication_paradigm(sdk.la_replication_paradigm_e_EGRESS)
        # destroy the main group
        self.device.destroy(self.mc_group)

    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_scale_multicast_e_to_i_with_main_port_member(self):
        # create the multicast group
        self.init_misc()
        self.mc_group = self.device.create_ip_multicast_group(MC_GROUP_ID, sdk.la_replication_paradigm_e_EGRESS)
        # add local receiver port
        # local mcid is allocated here
        self.mc_group.add(self.out_l3_ac.hld_obj, None, self.out_tx_eth_port.sys_port.hld_obj)
        # add the multicast route
        self.vrf.hld_obj.add_ipv4_multicast_route(
            self.mc_sip.hld_obj, self.mc_group_addr.hld_obj, self.mc_group, None, False, False, None)
        # add ip packet
        self.add_l3ac_default_tx_packet()

        # Verify that 1 IP packet is generated
        # For this new scale egress mc group
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # change to ingress replication
        self.mc_group.set_replication_paradigm(sdk.la_replication_paradigm_e_INGRESS)

        # Add a non-scale ip egress multicast group
        # XR might not do this way, they won't add IP subgroup, we still test it here
        self.mc_group2 = self.device.create_ip_multicast_group(self.non_scale_mcid, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group2.add(self.l3ac_port01.hld_obj, None, self.l3ac_ethport01.sys_port.hld_obj)
        # Add this non-scale egress mc group as a member to the scale mode ingress mc group
        self.mc_group.add(self.mc_group2)
        self.add_l3ac_port01_packet(self.egress_packets)

        # Verify that 2 IP packets are generated
        # For this new non-scale egress mc group
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # Create a non-scale mpls egress multicast group, and associated nh, and prefix object
        self.mpls_mcg = self.device.create_mpls_multicast_group(self.non_scale_mcid + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.l3ac_port21_prefix_object, self.l3ac_port21_nh  = self.create_nh_pfx_obj(self.mpls_label_num,
                                                                                      self.pfx_obj_gid,
                                                                                      self.nh_gid,
                                                                                      self.l3ac_port21.hld_obj)
        # Add the prefix object to the mpls mc group
        sys_port = self.l3ac_ethport21.hld_obj.get_system_port()
        self.mpls_mcg.add(self.l3ac_port21_prefix_object, sys_port)

        # Add this non-scale egress mc group as a member to the scale mode ingress mc group
        self.mc_group.add(self.mpls_mcg)

        # Create an egress packet matching the expected output
        self.add_l3ac_port21_mpls_packet(self.egress_packets, self.mpls_label_num)

        # Run a verify that 3 packets are output, the first 1 ip multicast packet, plus a new
        # MPLS multicast packet
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # Remove the non-scale ip mcg as a member of the scale mode ingress mcp, and
        # Verify the associated packet is no longer generated.
        # XR might not do this way, as they won't allocate ip subgroup
        self.mc_group.remove(self.mc_group2)
        self.mc_group2.remove(self.l3ac_port01.hld_obj, None)
        self.device.destroy(self.mc_group2)
        self.remove_l3ac_port01_packet(self.egress_packets)
        # verify 2 packets out, 1 for ip, 1 for mpls
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # Remove the non-scale mpls mcg as a member of the scale mode ingress mcp, and
        # Verify the associated packet is no longer generated.
        self.mc_group.remove(self.mpls_mcg)
        self.mpls_mcg.remove(self.l3ac_port21_prefix_object)
        self.device.destroy(self.mpls_mcg)
        self.remove_l3ac_port21_mpls_packet(self.egress_packets)
        # verify 1 ip packet is out
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # remove local receiver
        # local mcid is released here
        self.mc_group.remove(self.out_l3_ac.hld_obj, None)

        self.remove_l3ac_default_tx_packet(self.egress_packets)
        # verify no ip packet is out
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # delete route and main group
        self.vrf.hld_obj.delete_ipv4_multicast_route(self.mc_sip.hld_obj, self.mc_group_addr.hld_obj)

        # change back to egress paradigm
        self.mc_group.set_replication_paradigm(sdk.la_replication_paradigm_e_EGRESS)
        # destroy the main group
        self.device.destroy(self.mc_group)

    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_scale_multicast_i_to_e_no_main_port_member(self):
        # create the multicast group
        self.init_misc()
        self.mc_group = self.device.create_ip_multicast_group(MC_GROUP_ID, sdk.la_replication_paradigm_e_INGRESS)
        # add the multicast route
        self.vrf.hld_obj.add_ipv4_multicast_route(
            self.mc_sip.hld_obj, self.mc_group_addr.hld_obj, self.mc_group, None, False, False, None)

        # Add a non-scale ip egress multicast group
        # XR might not add ip subgroup
        self.mc_group2 = self.device.create_ip_multicast_group(self.non_scale_mcid, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group2.add(self.l3ac_port01.hld_obj, None, self.l3ac_ethport01.sys_port.hld_obj)
        # Add this non-scale egress mc group as a member to the scale mode ingress mc group
        # local mcid is allocated here
        self.mc_group.add(self.mc_group2)
        self.add_l3ac_port01_packet(self.egress_packets)

        # Verify that 1 IP packet is generated
        # For this new non-scale egress mc group
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # Create a non-scale mpls egress multicast group, and associated nh, and prefix object
        self.mpls_mcg = self.device.create_mpls_multicast_group(self.non_scale_mcid + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.l3ac_port21_prefix_object, self.l3ac_port21_nh  = self.create_nh_pfx_obj(self.mpls_label_num,
                                                                                      self.pfx_obj_gid,
                                                                                      self.nh_gid,
                                                                                      self.l3ac_port21.hld_obj)
        # Add the prefix object to the mpls mc group
        sys_port = self.l3ac_ethport21.hld_obj.get_system_port()
        self.mpls_mcg.add(self.l3ac_port21_prefix_object, sys_port)

        # Add this non-scale egress mc group as a member to the scale mode ingress mc group
        self.mc_group.add(self.mpls_mcg)

        # Create an egress packet matching the expected output
        self.add_l3ac_port21_mpls_packet(self.egress_packets, self.mpls_label_num)

        # Run a verify that 2 packets are output, the first 1 ip multicast packet, plus a new
        # MPLS multicast packet
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # Remove the non-scale ip mcg as a member of the scale mode ingress mcp, and
        # Verify the associated packet is no longer generated.
        self.mc_group.remove(self.mc_group2)
        self.mc_group2.remove(self.l3ac_port01.hld_obj, None)
        self.device.destroy(self.mc_group2)
        self.remove_l3ac_port01_packet(self.egress_packets)
        # verify only 1 mpls packet is out
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # Remove the non-scale mpls mcg as a member of the scale mode ingress mcp, and
        # Verify the associated packet is no longer generated.
        self.mc_group.remove(self.mpls_mcg)
        self.mpls_mcg.remove(self.l3ac_port21_prefix_object)
        self.device.destroy(self.mpls_mcg)
        self.remove_l3ac_port21_mpls_packet(self.egress_packets)
        # verify no packet is out
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # delete route
        self.vrf.hld_obj.delete_ipv4_multicast_route(self.mc_sip.hld_obj, self.mc_group_addr.hld_obj)

        # change to egress paradigm
        self.mc_group.set_replication_paradigm(sdk.la_replication_paradigm_e_EGRESS)
        # destroy the main group
        self.device.destroy(self.mc_group)

    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_scale_multicast_i_to_e_with_main_port_member(self):
        # create the multicast group
        self.init_misc()
        self.mc_group = self.device.create_ip_multicast_group(MC_GROUP_ID, sdk.la_replication_paradigm_e_INGRESS)
        # add local receiver port
        # local mcid is allocated here for main group
        self.mc_group.add(self.out_l3_ac.hld_obj, None, self.out_tx_eth_port.sys_port.hld_obj)
        # add the multicast route
        self.vrf.hld_obj.add_ipv4_multicast_route(
            self.mc_sip.hld_obj, self.mc_group_addr.hld_obj, self.mc_group, None, False, False, None)
        # add ip packet
        self.add_l3ac_default_tx_packet()

        # Verify that 1 IP packet is generated
        # For this new scale egress mc group
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # Add a non-scale ip egress multicast group
        # XR might not add though
        self.mc_group2 = self.device.create_ip_multicast_group(self.non_scale_mcid, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group2.add(self.l3ac_port01.hld_obj, None, self.l3ac_ethport01.sys_port.hld_obj)
        # Add this non-scale egress mc group as a member to the scale mode ingress mc group
        self.mc_group.add(self.mc_group2)
        self.add_l3ac_port01_packet(self.egress_packets)

        # Verify that 2 IP packets are generated
        # For this new non-scale egress mc group
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # Create a non-scale mpls egress multicast group, and associated nh, and prefix object
        self.mpls_mcg = self.device.create_mpls_multicast_group(self.non_scale_mcid + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.l3ac_port21_prefix_object, self.l3ac_port21_nh  = self.create_nh_pfx_obj(self.mpls_label_num,
                                                                                      self.pfx_obj_gid,
                                                                                      self.nh_gid,
                                                                                      self.l3ac_port21.hld_obj)
        # Add the prefix object to the mpls mc group
        sys_port = self.l3ac_ethport21.hld_obj.get_system_port()
        self.mpls_mcg.add(self.l3ac_port21_prefix_object, sys_port)

        # Add this non-scale egress mc group as a member to the scale mode ingress mc group
        self.mc_group.add(self.mpls_mcg)

        # Create an egress packet matching the expected output
        self.add_l3ac_port21_mpls_packet(self.egress_packets, self.mpls_label_num)

        # Run a verify that 3 packets are output, the first 1 ip multicast packet, plus a new
        # MPLS multicast packet
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # Remove the non-scale ip mcg as a member of the scale mode ingress mcp, and
        # Verify the associated packet is no longer generated.
        self.mc_group.remove(self.mc_group2)
        self.mc_group2.remove(self.l3ac_port01.hld_obj, None)
        self.device.destroy(self.mc_group2)
        self.remove_l3ac_port01_packet(self.egress_packets)
        # verify 1 ip and 1 mpls packets are out
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # Remove the non-scale mpls mcg as a member of the scale mode ingress mcp, and
        # Verify the associated packet is no longer generated.
        self.mc_group.remove(self.mpls_mcg)
        self.mpls_mcg.remove(self.l3ac_port21_prefix_object)
        self.device.destroy(self.mpls_mcg)
        self.remove_l3ac_port21_mpls_packet(self.egress_packets)
        # verify 1 ip packet is out
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # change back to egress paradigm
        self.mc_group.set_replication_paradigm(sdk.la_replication_paradigm_e_EGRESS)
        # verify local receiver packet is still generated
        run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # remove local receiver
        self.mc_group.remove(self.out_l3_ac.hld_obj, None)
        # delete route
        self.vrf.hld_obj.delete_ipv4_multicast_route(self.mc_sip.hld_obj, self.mc_group_addr.hld_obj)
        # destroy the main group
        self.device.destroy(self.mc_group)


if __name__ == '__main__':
    unittest.main()
