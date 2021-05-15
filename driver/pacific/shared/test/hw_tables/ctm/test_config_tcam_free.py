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

    def test_pre_dynamic_ring0_config(self):
        num_of_subrings = 1 if decor.is_pacific() else 2

    def test_simple_tcam_free(self):
        slice_idx = 0
        fw0_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_FW0_NARROW)
        tcamA = self.config.allocate_tcam_for_group(fw0_group)
        self.config.free_tcam(tcamA)
        for idx in range(30):  # Make sure SRAM is not exhausted.
            tcamB = self.config.allocate_tcam_for_group(fw0_group)
            self.assertEqual(tcamA, tcamB)
            self.config.free_tcam(tcamB)

    def test_tx_free(self):
        slice_idx = 0
        tx_wide_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_TX_WIDE)
        tx0_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_TX0_NARROW)
        tx1_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_TX1_NARROW)

        lsb_tcam = self.config.allocate_tcam_for_group(tx_wide_group)

        self.assertTrue(len(self.config.get_eligible_tcams_for_group(tx_wide_group)) == 1)
        self.assertTrue(len(self.config.get_eligible_lsb_tcams_for_wide_group(tx_wide_group)) == 1)
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(tx0_group)) == 1)
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(tx1_group)) == 0)

        self.config.free_tcam(lsb_tcam)
        # self.assertTrue(self.config.is_tcam_free(lsb_tcam.ring_idx, lsb_tcam.subring_idx, lsb_tcam.tcam_idx)) # TODO
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(tx_wide_group)) == 0)
        self.assertTrue(len(self.config.get_eligible_lsb_tcams_for_wide_group(tx_wide_group)) == 0)
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(tx0_group)) == 1)
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(tx1_group)) == 0)

        self.config.free_tcam(self.config.get_eligible_tcams_for_group(tx0_group)[0])

        self.assertTrue(len(self.config.get_eligible_tcams_for_group(tx0_group)) == 0)

        lsb_tcam = self.config.allocate_tcam_for_group(tx_wide_group)

        self.assertTrue(len(self.config.get_eligible_tcams_for_group(tx_wide_group)) == 1)
        self.assertTrue(len(self.config.get_eligible_lsb_tcams_for_wide_group(tx_wide_group)) == 1)
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(tx0_group)) == 1)
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(tx1_group)) == 0)

        self.config.free_tcam(self.config.get_eligible_tcams_for_group(tx0_group)[0])

        self.assertTrue(len(self.config.get_eligible_tcams_for_group(tx_wide_group)) == 0)
        self.assertTrue(len(self.config.get_eligible_lsb_tcams_for_wide_group(tx_wide_group)) == 0)
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(tx0_group)) == 0)
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(tx1_group)) == 0)

    def test_wide_tcam_free(self):
        slice_idx = 0
        fw_wide_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_FW_WIDE)
        fw0_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_FW0_NARROW)
        fw1_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_FW1_NARROW)

        msb_tcam = self.config.allocate_tcam_for_group(fw0_group)
        lsb_tcam = self.config.allocate_tcam_for_group(fw1_group)

        self.assertTrue(len(self.config.get_eligible_tcams_for_group(fw0_group)) == 1)
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(fw1_group)) == 1)
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(fw_wide_group)) == 1)
        self.assertTrue(len(self.config.get_eligible_lsb_tcams_for_wide_group(fw_wide_group)) == 1)

        self.config.free_tcam(msb_tcam)

        self.assertTrue(len(self.config.get_eligible_tcams_for_group(fw_wide_group)) == 0)
        self.assertTrue(len(self.config.get_eligible_lsb_tcams_for_wide_group(fw_wide_group)) == 0)
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(fw0_group)) == 0)
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(fw1_group)) == 1)

        self.config.free_tcam(lsb_tcam)

        self.assertTrue(len(self.config.get_eligible_tcams_for_group(fw1_group)) == 0)

        self.config.allocate_tcam_for_group(fw_wide_group)

        self.assertTrue(len(self.config.get_eligible_tcams_for_group(fw0_group)) == 1)
        # FW1 is assumed to be enabled as narrow group.
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(fw1_group)) == 1)
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(fw_wide_group)) == 1)
        self.assertTrue(len(self.config.get_eligible_lsb_tcams_for_wide_group(fw_wide_group)) == 1)

        lsb_tcam = self.config.get_eligible_tcams_for_group(fw1_group)[0]
        msb_tcam = self.config.get_eligible_tcams_for_group(fw0_group)[0]

        self.config.free_tcam(lsb_tcam)
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(fw_wide_group)) == 0)
        self.assertTrue(len(self.config.get_eligible_lsb_tcams_for_wide_group(fw_wide_group)) == 0)
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(fw0_group)) == 1)
        self.assertTrue(len(self.config.get_eligible_tcams_for_group(fw1_group)) == 0)

        self.config.free_tcam(msb_tcam)

        self.assertTrue(len(self.config.get_eligible_tcams_for_group(fw0_group)) == 0)


if __name__ == "__main__":
    unittest.main()
