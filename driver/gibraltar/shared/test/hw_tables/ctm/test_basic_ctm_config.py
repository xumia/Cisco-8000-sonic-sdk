# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import ctm_config_base
import test_hw_tables_ctmcli as ctm_cli
import decor


class simple_ctm_config_test(ctm_config_base.ctm_config_base):
    LPM_NUM_BANKSETS = 1
    STAND_ALONE_MODE = True

    def test_simple_fw0(self):
        fw0_group = ctm_cli.group_desc(0, ctm_cli.group_desc.GROUP_IFS_FW0_NARROW)

        for tcam_idx in range(10):
            tcam = self.config.allocate_tcam_for_group(fw0_group)

    def test_pre_dynamic_ring0_config(self):
        num_of_subrings = 1 if decor.is_pacific() else 2
        fw0_group = ctm_cli.group_desc(0, ctm_cli.group_desc.GROUP_IFS_FW0_NARROW)
        fw_wide_group = ctm_cli.group_desc(0, ctm_cli.group_desc.GROUP_IFS_FW_WIDE)
        tx0_group = ctm_cli.group_desc(0, ctm_cli.group_desc.GROUP_IFS_TX0_NARROW)
        tx_wide_group = ctm_cli.group_desc(0, ctm_cli.group_desc.GROUP_IFS_TX_WIDE)

        for subring_idx in range(num_of_subrings):
            self.config.allocate_tcam_for_group(fw_wide_group)
            self.config.allocate_tcam_for_group(fw_wide_group)
            self.config.allocate_tcam_for_group(fw_wide_group)
            self.config.allocate_tcam_for_group(tx_wide_group)
        for _ in range(2 * num_of_subrings):
            self.config.allocate_tcam_for_group(fw0_group)

    @unittest.skipUnless(decor.is_pacific(), "Test is relevant only for pacific.")
    def test_pre_dynamic_config_pacific(self):
        NUMBER_OF_FW_WIDE_TCAMS_PER_GROUP = 3
        NUMBER_OF_FW0_NARROW_TCAMS_PER_GROUP = 4
        NUMBER_OF_TX_WIDE_TCAMS_PER_GROUP = 1
        NUMBER_OF_TERM_TCAMS_PER_GROUP = 3

        for slice_idx in range(ctm_config_base.NUMBER_OF_SLICES):
            fw0_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_FW0_NARROW)
            fw_wide_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_FW_WIDE)
            tx0_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_TX0_NARROW)
            tx_wide_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_TX_WIDE)
            term_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_TERM)
            for idx in range(NUMBER_OF_FW_WIDE_TCAMS_PER_GROUP):
                self.config.allocate_tcam_for_group(fw_wide_group)

            for idx in range(NUMBER_OF_TX_WIDE_TCAMS_PER_GROUP):
                self.config.allocate_tcam_for_group(tx_wide_group)

            while len(self.config.get_eligible_tcams_for_group(fw0_group)) < NUMBER_OF_FW0_NARROW_TCAMS_PER_GROUP:
                self.config.allocate_tcam_for_group(fw0_group)

            while len(self.config.get_eligible_tcams_for_group(term_group)) < NUMBER_OF_TERM_TCAMS_PER_GROUP:
                self.config.allocate_tcam_for_group(term_group)

            self.assertEqual(len(self.config.get_eligible_tcams_for_group(term_group)), NUMBER_OF_TERM_TCAMS_PER_GROUP)
            self.assertEqual(len(self.config.get_eligible_tcams_for_group(tx_wide_group)), NUMBER_OF_TX_WIDE_TCAMS_PER_GROUP)
            self.assertEqual(len(self.config.get_eligible_tcams_for_group(fw_wide_group)), NUMBER_OF_FW_WIDE_TCAMS_PER_GROUP)
            self.assertEqual(len(self.config.get_eligible_tcams_for_group(
                fw0_group)), NUMBER_OF_FW0_NARROW_TCAMS_PER_GROUP)


if __name__ == "__main__":
    unittest.main()
