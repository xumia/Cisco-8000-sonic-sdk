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

import unittest
from leaba import sdk
from packet_test_utils import *
from scapy.all import *
from pcl_lpts_v4_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class pcl_lpts_functions(pcl_lpts_v4_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pcl_lpts_functions(self):
        pcl = self.create_pcl_instance()
        feature = pcl.get_feature()
        self.assertEqual(feature, sdk.pcl_feature_type_e_LPTS)

        v4vec = sdk.pcl_v4_vector()
        pcl.get_prefixes(v4vec)

        v4vec_add = sdk.pcl_v4_vector()
        entry = sdk.la_pcl_v4()
        entry.prefix.addr.s_addr = SIP_NO_PCL.to_num()
        entry.prefix.length = 32
        entry.bincode = SBINCODE3
        v4vec_add.append(entry)
        pcl.add_prefixes(v4vec_add)

        v4vec_out = sdk.pcl_v4_vector()
        pcl.get_prefixes(v4vec_out)
        self.assertEqual(len(v4vec) + 1, len(v4vec_out))

        pcl.remove_prefixes(v4vec_add)
        pcl.get_prefixes(v4vec_out)
        self.assertEqual(len(v4vec), len(v4vec_out))

        # modify_prefixes
        modified_v4_vec = sdk.pcl_v4_vector()
        for prefix_obj in v4vec:
            entry = sdk.la_pcl_v4()
            entry.bincode = SBINCODE3
            entry.prefix.addr.s_addr = prefix_obj.prefix.addr.s_addr
            entry.prefix.length = prefix_obj.prefix.length
            modified_v4_vec.append(entry)
        pcl.modify_prefixes(modified_v4_vec)
        pcl.get_prefixes(v4vec_out)
        self.assertEqual(len(v4vec), len(v4vec_out))
        for prefix_obj in v4vec_out:
            self.assertEqual(SBINCODE3, prefix_obj.bincode)

        pcl.replace_prefixes(v4vec)
        pcl.get_prefixes(v4vec_out)
        for prefix_obj in v4vec_out:
            self.assertNotEqual(SBINCODE3, prefix_obj.bincode)

        self.device.destroy(pcl)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_empty_pcl(self):
        pcl_entry_vec = sdk.pcl_v4_vector()
        src_pclEntry1 = sdk.la_pcl_v4()
        src_pclEntry1.prefix.addr.s_addr = 0
        src_pclEntry1.prefix.length = 0
        src_pclEntry1.bincode = 0xdead
        pcl_entry_vec.append(src_pclEntry1)
        pcl = self.device.create_pcl(pcl_entry_vec, sdk.pcl_feature_type_e_LPTS)
        self.assertNotEqual(pcl, None)
        pcl2 = None
        try:
            pcl_entry_vec = sdk.pcl_v4_vector()
            pcl2 = self.device.create_pcl(pcl_entry_vec, sdk.pcl_feature_type_e_ACL)
            self.assertEqual(pcl2, None)
        except BaseException:
            self.assertEqual(pcl2, None)


if __name__ == '__main__':
    unittest.main()
