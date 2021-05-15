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

import decor
import sys
import unittest
from leaba import sdk
from scapy.all import *
from meter_getters_base import *
import sim_utils
import topology as T
import packet_test_utils as U

METER_SET_SIZE = 4
FIRST_METER = 0
RATE = 114000000000
DEFAULT_RATE = 0
AC_PORT_GID_BASE = 10

DEFAULT_SLICE_IFG = sdk.la_slice_ifg()
DEFAULT_SLICE_IFG.ifg = 0
DEFAULT_SLICE_IFG.slice = 0


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class meter_set_base(meter_getters_base):
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    PUNT_SLICE = T.get_device_slice(2)
    PUNT_DEST_GID = 0x22
    PUNT_DEST_VID = 0x22
    HOST_MAC_ADDR = 'fe:dc:ba:98:76:54'
    IPV4_DIP = T.ipv4_addr('82.81.95.250')
    IPV6_DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

    def setUp(self):
        super().setUp()
        self.slice_ifg = sdk.la_slice_ifg()
        self.slice_ifg.ifg = 0
        self.slice_ifg.slice = T.get_device_slice(1)

    def create_attach_user_meter_set(self, is_aggregate=False):
        self.meter_set = T.create_meter_set(self, self.device, is_aggregate, set_size=METER_SET_SIZE)

        # Create a MAC port
        self.mac_port = T.mac_port(self, self.device, IN_SLICE, IN_IFG, IN_SERDES_FIRST, IN_SERDES_LAST)

        # Create an ethernet port on top of a system port, on top of a MAC port
        self.sys_port = T.system_port(self, self.device, SYS_PORT_GID_BASE, self.mac_port)
        self.spa_port = T.spa_port(self, self.device, SYS_PORT_GID_BASE + 1)
        if(is_aggregate):
            self.spa_port.add(self.sys_port)
        underlying_port = self.sys_port if (not is_aggregate) else self.spa_port
        self.eth_port = T.sa_ethernet_port(self, self.device, underlying_port)

        # Create ingress port over the ethernet port
        self.ac_port = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            None,
            self.eth_port,
            None,
            VLAN,
            0x0)

        # attach ac_port to the meter set
        self.ac_port.hld_obj.set_meter(self.meter_set)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_get_meter_action_profile(self):

        self.create_attach_user_meter_set()

        # Create default meter action profile
        meter_action_profiles = [self.device.create_meter_action_profile() for i in range(2)]

        for meter_action_profile in meter_action_profiles:
            for meter_index in range(METER_SET_SIZE):
                # Should fail when meter is bound to a user
                with self.assertRaises(sdk.BusyException):
                    self.meter_set.set_meter_action_profile(meter_index, meter_action_profile)

                # Unbind and try again
                self.ac_port.hld_obj.set_meter(None)
                self.meter_set.set_meter_action_profile(meter_index, meter_action_profile)
                res_meter_action_profile = self.meter_set.get_meter_action_profile(meter_index)
                self.assertEqual(res_meter_action_profile.this, meter_action_profile.this)

                # Bind the meter set again
                self.ac_port.hld_obj.set_meter(self.meter_set)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_create_set_get_meter(self):

        self.create_attach_user_meter_set()

        # Create meter set
        meter_set = T.create_meter_set(self, self.device)

        # Attach to L3 port
        self.topology.rx_l3_ac.hld_obj.set_meter(meter_set)

        # Get the meter
        _meter_set = self.topology.rx_l3_ac.hld_obj.get_meter()
        self.assertEqual(_meter_set.this, meter_set.this)

        # Change meter profile while in use - should fail
        profile = meter_set.get_meter_profile(0)
        try:
            profile.set_cbs(10)
            self.assertFail()
        except sdk.BaseException:
            pass

        # Cleanup
        self.topology.rx_l3_ac.hld_obj.set_meter(None)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_attach_detach_user(self):

        self.create_attach_user_meter_set()
        self.ac_port.destroy()
        self.ac_port = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            None,
            self.eth_port,
            None,
            VLAN,
            0x0)
        self.ac_port.hld_obj.set_meter(self.meter_set)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_create_get_meter_set(self):

        # Create meter set
        for type in self.meter_set_types:
            for size in range(1, 8, 2):               # create several meter set sizes
                meter_set = self.device.create_meter(type, size)
                res_meter_set_type = meter_set.get_type()
                self.assertEqual(type, res_meter_set_type)

                # Verify attribiutes
                res_meter_set_size = meter_set.get_set_size()
                self.assertEqual(size, res_meter_set_size)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_get_cir_eir(self):

        self.create_attach_user_meter_set()

        for meter_index in range(METER_SET_SIZE):
            self.meter_set.set_cir(meter_index, RATE)
            res_cir = self.meter_set.get_cir(meter_index)
            self.assertAlmostEqual(res_cir / RATE, 1.0, places=1)

            self.meter_set.set_eir(meter_index, RATE)
            res_eir = self.meter_set.get_eir(meter_index)
            self.assertAlmostEqual(res_eir / RATE, 1.0, places=1)

        # For EXACT, cannot pass specific ifg to set_cir/eir function
        try:
            self.meter_set.set_cir(FIRST_METER, self.slice_ifg, RATE)
            self.assertFail()
        except sdk.BaseException:
            pass

        try:
            self.meter_set.set_eir(FIRST_METER, self.slice_ifg, RATE)
            self.assertFail()
        except sdk.BaseException:
            pass

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_get_cir_eir_per_ifg(self):

        self.create_attach_user_meter_set(is_aggregate=True)  # per ifg meter

        for meter_index in range(METER_SET_SIZE):
            self.meter_set.set_cir(meter_index, self.slice_ifg, RATE)
            res_cir = self.meter_set.get_cir(meter_index, self.slice_ifg)
            self.assertAlmostEqual(res_cir / RATE, 1.0, places=1)

            self.meter_set.set_eir(meter_index, self.slice_ifg, RATE)
            res_eir = self.meter_set.get_eir(meter_index, self.slice_ifg)
            self.assertAlmostEqual(res_eir / RATE, 1.0, places=1)

        # For IFG EXACT, have to pass ifg to set_cir/eir function
        try:
            self.meter_set.set_cir(FIRST_METER, RATE)
            self.assertFail()
        except sdk.BaseException:
            pass

        try:
            self.meter_set.set_eir(FIRST_METER, RATE)
            self.assertFail()
        except sdk.BaseException:
            pass

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_get_committed_bucket_coupling_mode(self):

        self.create_attach_user_meter_set()

        for meter_index in range(METER_SET_SIZE):
            coupling_mode = sdk.la_meter_set.coupling_mode_e_NOT_COUPLED
            with self.assertRaises(sdk.NotImplementedException):
                # SR-TCM meters must be coupled to excess bucket
                self.meter_set.set_committed_bucket_coupling_mode(meter_index, coupling_mode)

            coupling_mode = sdk.la_meter_set.coupling_mode_e_TO_EXCESS_BUCKET
            self.meter_set.set_committed_bucket_coupling_mode(meter_index, coupling_mode)
            res_coupling_mode = self.meter_set.get_committed_bucket_coupling_mode(meter_index)
            self.assertEqual(res_coupling_mode, coupling_mode)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_meter_multi_user(self):
        # meter
        meter = T.create_meter_set(self, self.device, is_statistical=True, set_size=1)

        # LPTS
        punt_dest = T.create_l2_punt_destination(self, self.device,
                                                 self.PUNT_DEST_GID,
                                                 self.topology.inject_ports[self.PUNT_SLICE],
                                                 self.HOST_MAC_ADDR, self.PUNT_DEST_VID)

        lpts_entries_num = 4

        ipv4_keys = []
        ipv6_keys = []
        results = []
        for i in range(lpts_entries_num):
            ipv4_k = sdk.la_lpts_key()
            ipv4_k.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
            ipv4_k.val.ipv4.relay_id = 0x400 + i
            ipv4_k.mask.ipv4.relay_id = 0xfff + i
            ipv4_keys.append(ipv4_k)

            ipv6_k = sdk.la_lpts_key()
            ipv6_k.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
            ipv6_k.val.ipv6.relay_id = 0x600 + i
            ipv6_keys.append(ipv6_k)

            result = sdk.la_lpts_result()
            result.flow_type = 10 + i
            result.punt_code = 110 + i
            result.dest = punt_dest
            results.append(result)

        results[0].meter = meter
        results[1].meter = meter
        results[2].meter = meter
        results[3].meter = meter

        ipv4_lpts = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV4)
        ipv6_lpts = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV6)

        for i in range(lpts_entries_num):
            result = results[i]
            result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True, set_size=1)
            ipv4_lpts.append(ipv4_keys[i], result)
            result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True, set_size=1)
            ipv6_lpts.append(ipv6_keys[i], result)

        for _ in range(lpts_entries_num):
            ipv4_lpts.pop(0)
            ipv6_lpts.pop(0)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_meter_profile(self):

        self.create_attach_user_meter_set()
        meter_set_size = self.meter_set.get_set_size()
        self.assertEqual(meter_set_size, METER_SET_SIZE)

        for meter_index in range(meter_set_size):
            res_meter_profile = self.meter_set.get_meter_profile(meter_index)
            self.assertEqual(res_meter_profile.this, self.topology.global_meter_profile_def.this)


if __name__ == '__main__':
    unittest.main()
