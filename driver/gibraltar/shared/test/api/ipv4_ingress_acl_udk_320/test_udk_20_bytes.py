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

# This tests checks fix for issue, which discribed in ticket CSCvs05610
# and has 2 main purposes:
# 1) Check that ACL profile, configured for exactly 20 byte UDK, has key size 320 bit
# 2) Insertion entries to mentioned ACL doesn't cause any error


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
class test_udk_20_bytes(sdk_test_case_base):
    acl_profile_ipv4_20_bytes = None

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:

            udk = []

            udf0 = sdk.la_acl_field_def()
            udf0.type = sdk.la_acl_field_type_e_IPV4_SIP
            udf0.udf_desc.index = 0
            udf0.udf_desc.protocol_layer = 0
            udf0.udf_desc.header = 0
            udf0.udf_desc.offset = 0
            udf0.udf_desc.width = 0
            udf0.udf_desc.is_relative = False
            udk.append(udf0)

            udf1 = sdk.la_acl_field_def()
            udf1.type = sdk.la_acl_field_type_e_IPV4_DIP
            udf1.udf_desc.index = 0
            udf1.udf_desc.protocol_layer = 0
            udf1.udf_desc.header = 0
            udf1.udf_desc.offset = 0
            udf1.udf_desc.width = 0
            udf1.udf_desc.is_relative = False
            udk.append(udf1)

            udf2 = sdk.la_acl_field_def()
            udf2.type = sdk.la_acl_field_type_e_PROTOCOL
            udf2.udf_desc.index = 0
            udf2.udf_desc.protocol_layer = 0
            udf2.udf_desc.header = 0
            udf2.udf_desc.offset = 0
            udf2.udf_desc.width = 0
            udf2.udf_desc.is_relative = False
            udk.append(udf2)

            udf3 = sdk.la_acl_field_def()
            udf3.type = sdk.la_acl_field_type_e_TTL
            udf3.udf_desc.index = 0
            udf3.udf_desc.protocol_layer = 0
            udf3.udf_desc.header = 0
            udf3.udf_desc.offset = 0
            udf3.udf_desc.width = 0
            udf3.udf_desc.is_relative = False
            udk.append(udf3)

            udf4 = sdk.la_acl_field_def()
            udf4.type = sdk.la_acl_field_type_e_TOS
            udf4.udf_desc.index = 0
            udf4.udf_desc.protocol_layer = 0
            udf4.udf_desc.header = 0
            udf4.udf_desc.offset = 0
            udf4.udf_desc.width = 0
            udf4.udf_desc.is_relative = False
            udk.append(udf4)

            udf5 = sdk.la_acl_field_def()
            udf5.type = sdk.la_acl_field_type_e_UDF
            udf5.udf_desc.index = 0
            udf5.udf_desc.protocol_layer = 0
            udf5.udf_desc.header = 0
            udf5.udf_desc.offset = 4
            udf5.udf_desc.width = 2
            udf5.udf_desc.is_relative = True
            udk.append(udf5)

            udf6 = sdk.la_acl_field_def()
            udf6.type = sdk.la_acl_field_type_e_UDF
            udf6.udf_desc.index = 1
            udf6.udf_desc.protocol_layer = 1
            udf6.udf_desc.header = 0
            udf6.udf_desc.offset = 4
            udf6.udf_desc.width = 2
            udf6.udf_desc.is_relative = True
            udk.append(udf6)

            udf7 = sdk.la_acl_field_def()
            udf7.type = sdk.la_acl_field_type_e_UDF
            udf7.udf_desc.index = 2
            udf7.udf_desc.protocol_layer = 1
            udf7.udf_desc.header = 0
            udf7.udf_desc.offset = 8
            udf7.udf_desc.width = 1
            udf7.udf_desc.is_relative = True
            udk.append(udf7)

            udf8 = sdk.la_acl_field_def()
            udf8.type = sdk.la_acl_field_type_e_UDF
            udf8.udf_desc.index = 3
            udf8.udf_desc.protocol_layer = 1
            udf8.udf_desc.header = 1
            udf8.udf_desc.offset = 0
            udf8.udf_desc.width = 2
            udf8.udf_desc.is_relative = True
            udk.append(udf8)

            udf9 = sdk.la_acl_field_def()
            udf9.type = sdk.la_acl_field_type_e_UDF
            udf9.udf_desc.index = 4
            udf9.udf_desc.protocol_layer = 1
            udf9.udf_desc.header = 1
            udf9.udf_desc.offset = 2
            udf9.udf_desc.width = 2
            udf9.udf_desc.is_relative = True
            udk.append(udf9)

            key_type = sdk.la_acl_key_type_e_IPV4
            direction = sdk.la_acl_direction_e_INGRESS
            tcam_pool_id = 0
            test_udk_20_bytes.acl_profile_ipv4_20_bytes = device.create_acl_key_profile(
                key_type, direction, udk, tcam_pool_id)

    @classmethod
    def setUpClass(cls):
        super(test_udk_20_bytes, cls).setUpClass(
            device_config_func=test_udk_20_bytes.device_config_func)

    @unittest.skipUnless(decor.is_hw_device(), "Skip for simulation until correct behavour of place_udk() is enabled")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_acl_profile_ipv4_20_bytes(self):
        profile = test_udk_20_bytes.acl_profile_ipv4_20_bytes
        self.assertNotEqual(profile, None)

        acl1 = self.device.create_acl(profile, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        ipv4_acls = []
        ipv4_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        k1 = []
        commands = []

        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = False
        commands.append(action1)

        acl1.insert(0, k1, commands)

        count = acl1.get_count()
        self.assertEqual(count, 1)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)


if __name__ == '__main__':
    unittest.main()
