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
from packet_test_utils import *
import sim_utils
import topology as T
from scapy.all import *
from binascii import hexlify, unhexlify
from sdk_test_case_base import *
import decor

# This tests has 2 main purposes:
# 1) Check that ACL profile, configured for exactly 20 byte UDK, has key size 320 bit
# 2) Insertion entries to mentioned ACL doesn't cause any error


@unittest.skip("Skipped until correct behaviour for IPV6_UDK 160b is enabled")
class test_udk_20_bytes(sdk_test_case_base):
    acl_profile_ipv6_20_bytes = None

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:

            udk = []

            udf0 = sdk.la_acl_field_def()
            udf0.type = sdk.la_acl_field_type_e_IPV6_SIP
            udk.append(udf0)

            udf5 = sdk.la_acl_field_def()
            udf5.type = sdk.la_acl_field_type_e_SPORT
            udk.append(udf5)

            udf6 = sdk.la_acl_field_def()
            udf6.type = sdk.la_acl_field_type_e_TOS
            udk.append(udf6)

            key_type = sdk.la_acl_key_type_e_IPV6
            direction = sdk.la_acl_direction_e_INGRESS
            tcam_pool_id = 0
            test_udk_20_bytes.acl_profile_ipv6_20_bytes = device.create_acl_key_profile(
                key_type, direction, udk, tcam_pool_id)

    @classmethod
    def setUpClass(cls):
        super(test_udk_20_bytes, cls).setUpClass(
            device_config_func=test_udk_20_bytes.device_config_func)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_tcl_profile_ipv6_20_bytes(self):
        profile = test_udk_20_bytes.acl_profile_ipv6_20_bytes
        self.assertNotEqual(profile, None)

        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        ipv6_acls = []
        ipv6_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        k1 = []
        commands = []

        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = is_drop
        commands.append(action1)

        acl1.insert(0, k1, commands)

        count = acl1.get_count()
        self.assertEqual(count, 1)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)


if __name__ == '__main__':
    unittest.main()
