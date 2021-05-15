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
from scapy.all import *
import sim_utils
import topology as T
import packet_test_utils as U

# Constants
IN_SLICE = T.get_device_slice(2)
IN_IFG = 0
IN_SERDES_FIRST = T.get_device_first_serdes(4)
IN_SERDES_LAST = IN_SERDES_FIRST + 1

OUT_SLICE = T.get_device_slice(4)
OUT_IFG = T.get_device_ifg(1)
OUT_SERDES_FIRST = T.get_device_next_first_serdes(8)
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

OUT_SLICE1 = T.get_device_slice(1)
OUT_IFG1 = 0
OUT_SERDES_FIRST1 = T.get_device_out_first_serdes(12)
OUT_SERDES_LAST1 = OUT_SERDES_FIRST1 + 1

OUT_SLICE2 = OUT_SLICE
OUT_IFG2 = OUT_IFG
OUT_SERDES_FIRST2 = T.get_device_out_next_first_serdes(12)
OUT_SERDES_LAST2 = OUT_SERDES_FIRST2 + 1

SYS_PORT_GID_BASE = 23
AC_PORT_GID_BASE = 10

SWITCH_GID = 100

DST_MAC = 'ca:fe:ca:fe:ca:fe'
SRC_MAC = 'de:ad:de:ad:de:ad'
VLAN = 0xAB9

MC_GROUP_GID = 0x13

L3_AC_MAC_ADDR = T.mac_addr('11:22:33:dd:ee:ff')
L3_AC_MAC_ADDR2 = T.mac_addr('01:02:03:dd:ee:ff')


class npu_getters_base:

    def setUp(self):
        self.maxDiff = None  # Show whole strings on failures (unittest variable)

        self.counter_set_size = 1
        self.device = U.sim_utils.create_device(1)

        # MATILDA_SAVE -- need review
        global OUT_SLICE, IN_SLICE, OUT_SLICE1, OUT_SLICE2
        IN_SLICE = T.choose_active_slices(self.device, IN_SLICE, [2, 3])
        OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [4, 0])
        OUT_SLICE1 = T.choose_active_slices(self.device, OUT_SLICE1, [1, 5])
        OUT_SLICE2 = OUT_SLICE
        self.IN_SLICE, self.OUT_SLICE, self.OUT_SLICE1, self.OUT_SLICE2 = IN_SLICE, OUT_SLICE, OUT_SLICE1, OUT_SLICE2

        self.topology = T.topology(self, self.device)
        self.objects_to_destroy = []
        self.objects_to_destroy.append(self.topology)
        if hasattr(self, 'init'):
            self.init()

    def tearDown(self):
        self.device.tearDown()

    def set_get_counter(self, hld_object):
        # Create counter
        counter = self.device.create_counter(self.counter_set_size)
        hld_object.set_counter(counter)

        # Verify
        res_counter = hld_object.get_counter()
        self.assertEqual(res_counter.this, counter.this)

        # Cleanup
        hld_object.set_counter(None)
        self.device.destroy(counter)

    def set_get_egress_counter(self, hld_object):
        # Create counter
        counter = self.device.create_counter(self.counter_set_size)

        # Verify
        hld_object.set_egress_counter(sdk.la_counter_set.type_e_PORT, counter)
        res_counter = hld_object.get_egress_counter(sdk.la_counter_set.type_e_PORT)
        self.assertEqual(res_counter.this, counter.this)

        # Cleanup
        hld_object.set_egress_counter(sdk.la_counter_set.type_e_PORT, None)
        self.device.destroy(counter)

    def set_get_ingress_counter(self, hld_object):
        # Create counter
        counter = self.device.create_counter(self.counter_set_size)

        # Verify
        hld_object.set_ingress_counter(sdk.la_counter_set.type_e_PORT, counter)
        res_counter = hld_object.get_ingress_counter(sdk.la_counter_set.type_e_PORT)
        self.assertEqual(res_counter.this, counter.this)

        # Cleanup
        hld_object.set_ingress_counter(sdk.la_counter_set.type_e_PORT, None)
        self.device.destroy(counter)

    def set_get_egress_vlan_tag(self, port_impl):
        # Create tag
        tag = sdk.la_vlan_tag_t()
        res_tag1 = sdk.la_vlan_tag_t()
        res_tag2 = sdk.la_vlan_tag_t()

        for tag_values in [[0x8000, 1, 2], [0x8100, 3, 4]]:
            (tag.tpid, tag.tci.fields.pcp, tag.tci.fields.dei) = tag_values
            port_impl.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)
            (res_tag1, res_tag2) = port_impl.get_egress_vlan_tag()
            self.assertEqual(res_tag1.tpid, tag.tpid)
            self.assertEqual(res_tag1.tci.fields.pcp, tag.tci.fields.pcp)
            self.assertEqual(res_tag1.tci.fields.dei, tag.tci.fields.dei)

    def get_service_mapping_vids(self, hld_object):
        (res_vid1, res_vid2) = hld_object.get_service_mapping_vids()

        # Topology creates ac_port with vid1 = vid2 = 0
        self.assertEqual(res_vid1, self.vid1)
        self.assertEqual(res_vid2, self.vid2)
