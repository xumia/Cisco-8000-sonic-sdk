#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import lldcli
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class traversal_tree_test(unittest.TestCase):

    def setUp(self):
        pass

    def test_get_leaf_blocks_rev1(self):
        self.do_test_get_leaf_blocks(lldcli.la_device_revision_e_PACIFIC_A0)

    def test_get_leaf_blocks_rev1(self):
        self.do_test_get_leaf_blocks(lldcli.la_device_revision_e_PACIFIC_B0)

    def do_test_get_leaf_blocks(self, revision):
        pacific_tree = lldcli.pacific_tree.create(revision)
        all_leaf_blocks = pacific_tree.get_leaf_blocks()
        pacific_sub_blocks = pacific_tree.get_blocks()

        total_leaf_count = 0
        for sub_block in pacific_sub_blocks:
            total_leaf_count += len(sub_block.get_leaf_blocks())

        self.assertEqual(len(all_leaf_blocks), total_leaf_count)


if __name__ == '__main__':
    unittest.main()
