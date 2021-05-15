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

from sdk_test_case_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class L2ServicePortGetters (sdk_test_case_base):
    '''
      Testing the python API for the la_l2_service_port
    '''

    VLAN_ID1 = 121
    VLAN_ID2 = 232
    VLAN_ID3 = 190
    VLAN_ID4 = 191
    VLAN_ID5 = 192

    def setUp(self):
        super().setUp()

        self.ac_service_port = self.device.create_ac_l2_service_port(1, self.topology.rx_eth_port.hld_obj,
                                                                     self.VLAN_ID1,
                                                                     self.VLAN_ID2,
                                                                     self.topology.filter_group_def,
                                                                     self.topology.ingress_qos_profile_def.hld_obj,
                                                                     self.topology.egress_qos_profile_def.hld_obj)

    def tearDown(self):
        self.device.destroy(self.ac_service_port)
        super().tearDown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_ingress_qos_profile(self):
        '''
          Test getting the ingress qos profile
        '''

        topo_profile = self.topology.ingress_qos_profile_def.hld_obj
        profile = self.ac_service_port.get_ingress_qos_profile()

        # ensure the profile is the same as the configured one
        self.assertEqual(profile.oid(), topo_profile.oid())

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_egress_qos_profile(self):
        '''
          Test getting the egress qos profile
        '''

        topo_profile = self.topology.egress_qos_profile_def.hld_obj
        profile = self.ac_service_port.get_egress_qos_profile()

        # ensure the profile is the same as the configured one
        self.assertEqual(profile.oid(), topo_profile.oid())

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_get_mac_learning_mode(self):
        '''
          Test set_mac_learning_mode and get_mac_learning_mode APIs
        '''
        learning_mode = self.ac_service_port.get_mac_learning_mode()
        self.assertEqual(learning_mode, sdk.la_lp_mac_learning_mode_e_NONE)

        self.ac_service_port.set_mac_learning_mode(sdk.la_lp_mac_learning_mode_e_STANDALONE)

        learning_mode = self.ac_service_port.get_mac_learning_mode()
        self.assertEqual(learning_mode, sdk.la_lp_mac_learning_mode_e_STANDALONE)

        self.ac_service_port.set_mac_learning_mode(sdk.la_lp_mac_learning_mode_e_NONE)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_get_service_mapping_vids(self):
        '''
          Test set_service_mapping_vids and get_service_mapping_vids
        '''
        (vlan_id1, vlan_id2) = self.ac_service_port.get_service_mapping_vids()
        self.assertEqual(vlan_id1, self.VLAN_ID1)
        self.assertEqual(vlan_id2, self.VLAN_ID2)

        self.ac_service_port.set_service_mapping_vids(self.VLAN_ID3, self.VLAN_ID4)
        (vlan_id1, vlan_id2) = self.ac_service_port.get_service_mapping_vids()
        self.assertEqual(vlan_id1, self.VLAN_ID3)
        self.assertEqual(vlan_id2, self.VLAN_ID4)

        self.ac_service_port.set_service_mapping_vids(self.VLAN_ID5, 0)
        (vlan_id1, vlan_id2) = self.ac_service_port.get_service_mapping_vids()
        self.assertEqual(vlan_id1, self.VLAN_ID5)
        self.assertEqual(vlan_id2, 0)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_ethernet_port(self):
        '''
          Test get ethernet port
        '''
        topo_eth_port = self.topology.rx_eth_port.hld_obj
        eth_port = self.ac_service_port.get_ethernet_port()

        self.assertEqual(eth_port.oid(), topo_eth_port.oid())

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_ingress_mirror_command(self):
        '''
          Test get ingress mirror command
        '''
        (mirror, cond) = self.ac_service_port.get_ingress_mirror_command()

        self.assertEqual(mirror, None)
        self.assertEqual(cond, True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_egress_mirror_command(self):
        '''
          Test get egress mirror command
        '''
        (mirror, cond) = self.ac_service_port.get_egress_mirror_command()

        self.assertEqual(mirror, None)
        self.assertEqual(cond, True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_get_stp_state(self):
        '''
          Test set_stp_state and get_stp_state APIs
        '''
        state = self.ac_service_port.get_stp_state()
        self.assertEqual(state, sdk.la_port_stp_state_e_BLOCKING)

        self.ac_service_port.set_stp_state(sdk.la_port_stp_state_e_LISTENING)

        state = self.ac_service_port.get_stp_state()
        self.assertEqual(state, sdk.la_port_stp_state_e_LISTENING)

        self.ac_service_port.set_stp_state(sdk.la_port_stp_state_e_BLOCKING)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_filter_group(self):
        '''
          Test get filter group
        '''
        topo_group = self.topology.filter_group_def
        group = self.ac_service_port.get_filter_group()

        self.assertEqual(group.oid(), topo_group.oid())

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_event_enabled(self):
        '''
          Test get event enabled
        '''
        with self.assertRaises(sdk.NotImplementedException):
            enabled = self.ac_service_port.get_event_enabled(sdk.LA_EVENT_ETHERNET_UNKNOWN_UC)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_ingress_vlan_edit_command(self):
        '''
          Test setting and getting the vlan edit command
        '''

        def assertVlanEqual(tag1, tag2):
            '''
              Function to assert vlan tags are equal
            '''
            self.assertEqual(tag1.tci.fields.vid, tag2.tci.fields.vid)
            self.assertEqual(tag1.tpid, tag2.tpid)

        # set/get the vlan command with no tags
        cmd = sdk.la_vlan_edit_command(0)
        self.ac_service_port.set_ingress_vlan_edit_command(cmd)
        result = self.ac_service_port.get_ingress_vlan_edit_command()

        # Verify equality
        self.assertEqual(result.num_tags_to_pop, cmd.num_tags_to_pop)
        self.assertEqual(result.num_tags_to_push, cmd.num_tags_to_push)
        self.assertEqual(result.pcpdei_rewrite_only, cmd.pcpdei_rewrite_only)

        # set/get the vlan command with one tags
        tag1 = sdk.la_vlan_tag_t()
        tag1.tci.fields.vid = 100
        tag1.tpid = 0x8100
        cmd = sdk.la_vlan_edit_command(1, tag1)
        self.ac_service_port.set_ingress_vlan_edit_command(cmd)
        result = self.ac_service_port.get_ingress_vlan_edit_command()

        # Verify equality
        self.assertEqual(result.num_tags_to_pop, cmd.num_tags_to_pop)
        self.assertEqual(result.num_tags_to_push, cmd.num_tags_to_push)
        self.assertEqual(result.pcpdei_rewrite_only, cmd.pcpdei_rewrite_only)
        assertVlanEqual(result.tag0, cmd.tag0)

        # set/get the vlan command with two tags
        tag2 = sdk.la_vlan_tag_t()
        tag2.tci.fields.vid = 200
        tag2.tpid = 0x8100
        tag3 = sdk.la_vlan_tag_t()
        tag3.tci.fields.vid = 300
        tag3.tpid = 0x8100
        cmd = sdk.la_vlan_edit_command(0, tag2, tag3)
        self.ac_service_port.set_ingress_vlan_edit_command(cmd)
        result = self.ac_service_port.get_ingress_vlan_edit_command()

        # Verify equality
        self.assertEqual(result.num_tags_to_pop, cmd.num_tags_to_pop)
        self.assertEqual(result.num_tags_to_push, cmd.num_tags_to_push)
        self.assertEqual(result.pcpdei_rewrite_only, cmd.pcpdei_rewrite_only)
        assertVlanEqual(result.tag0, cmd.tag0)
        assertVlanEqual(result.tag1, cmd.tag1)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_egress_vlan_edit_command(self):
        '''
          Test setting and getting the egress vlan edit command
        '''

        def assertVlanEqual(tag1, tag2):
            '''
              Function to assert vlan tags are equal
            '''
            self.assertEqual(tag1.tci.fields.vid, tag2.tci.fields.vid)
            self.assertEqual(tag1.tpid, tag2.tpid)

        # set/get the vlan command with no tags
        cmd = sdk.la_vlan_edit_command(0)
        self.ac_service_port.set_egress_vlan_edit_command(cmd)
        result = self.ac_service_port.get_egress_vlan_edit_command()

        # Verify equality
        self.assertEqual(result.num_tags_to_pop, cmd.num_tags_to_pop)
        self.assertEqual(result.num_tags_to_push, cmd.num_tags_to_push)
        self.assertEqual(result.pcpdei_rewrite_only, cmd.pcpdei_rewrite_only)

        # set/get the vlan command with one tags
        tag1 = sdk.la_vlan_tag_t()
        tag1.tci.fields.vid = 100
        tag1.tpid = 0x8100
        cmd = sdk.la_vlan_edit_command(1, tag1)
        self.ac_service_port.set_egress_vlan_edit_command(cmd)
        result = self.ac_service_port.get_egress_vlan_edit_command()

        # Verify equality
        self.assertEqual(result.num_tags_to_pop, cmd.num_tags_to_pop)
        self.assertEqual(result.num_tags_to_push, cmd.num_tags_to_push)
        self.assertEqual(result.pcpdei_rewrite_only, cmd.pcpdei_rewrite_only)
        assertVlanEqual(result.tag0, cmd.tag0)

        # set/get the vlan command with two tags
        tag2 = sdk.la_vlan_tag_t()
        tag2.tci.fields.vid = 200
        tag2.tpid = 0x8100
        tag3 = sdk.la_vlan_tag_t()
        tag3.tci.fields.vid = 300
        tag3.tpid = 0x8100
        cmd = sdk.la_vlan_edit_command(0, tag2, tag3)
        self.ac_service_port.set_egress_vlan_edit_command(cmd)
        result = self.ac_service_port.get_egress_vlan_edit_command()

        # Verify equality
        self.assertEqual(result.num_tags_to_pop, cmd.num_tags_to_pop)
        self.assertEqual(result.num_tags_to_push, cmd.num_tags_to_push)
        self.assertEqual(result.pcpdei_rewrite_only, cmd.pcpdei_rewrite_only)
        assertVlanEqual(result.tag0, cmd.tag0)
        assertVlanEqual(result.tag1, cmd.tag1)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_destination(self):
        '''
          Test get destination
        '''
        dest = self.ac_service_port.get_destination()
        self.assertEqual(dest, None)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_attached_switch(self):
        '''
          Test get attached switch
        '''
        switch = self.ac_service_port.get_attached_switch()
        self.assertEqual(switch, None)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_acl(self):
        '''
          Test get acl
        '''
        acl = self.ac_service_port.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl, None)

        acl = self.ac_service_port.get_acl_group(sdk.la_acl_direction_e_EGRESS)
        self.assertEqual(acl, None)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_ingress_counter(self):
        '''
          Test get ingress counter
        '''
        counter = self.ac_service_port.get_ingress_counter(sdk.la_counter_set.type_e_PORT)
        self.assertEqual(counter, None)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_egress_counter(self):
        '''
          Test get egress counter
        '''
        counter = self.ac_service_port.get_egress_counter(sdk.la_counter_set.type_e_PORT)
        self.assertEqual(counter, None)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_meter(self):
        '''
          Test get meter
        '''
        meter = self.ac_service_port.get_meter()
        self.assertEqual(meter, None)


if __name__ == '__main__':
    unittest.main()
