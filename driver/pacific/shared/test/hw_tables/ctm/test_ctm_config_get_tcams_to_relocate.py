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


class test_ctm_config_get_tcams_to_relocate(ctm_config_base.ctm_config_base):
    LPM_NUM_BANKSETS = 1
    STAND_ALONE_MODE = True

    def test_tx0(self):
        slice_idx = 0
        fw0_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_FW0_NARROW)
        tx0_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_TX0_NARROW)
        tx_wide_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_TX_WIDE)
        fw_wide_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_FW_WIDE)
        self.config.allocate_tcam_for_group(tx_wide_group)
        self.config.allocate_tcam_for_group(fw_wide_group)
        while True:
            try:
                self.config.allocate_tcam_for_group(tx0_group)
            except ctm_cli.ResourceException:
                break
        self.config.get_tcams_to_relocate_for_group(fw0_group)

    def test_get_eligible_tcams_to_relocate_wide(self):
        slice_idx = 0
        fw0_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_FW0_NARROW)
        fw_wide_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_FW_WIDE)
        while True:
            try:
                self.config.allocate_tcam_for_group(fw0_group)
            except ctm_cli.ResourceException:
                break

        try:
            self.config.allocate_tcam_for_group(fw_wide_group)
            self.assertTrue(False)
        except ctm_cli.ResourceException:
            pass

        tcams_to_relocate_per_prio = self.config.get_tcams_to_relocate_for_group(fw_wide_group)

        flat_tcams_to_relocate = [
            tcam for tcams_vec_prio in tcams_to_relocate_per_prio for tcam in tcams_to_relocate_per_prio[tcams_vec_prio]]

        self.assertGreater(len(flat_tcams_to_relocate), 0)  # We know for sure that FW1 SRAM occupies only one half.

        self.assertEqual(len(flat_tcams_to_relocate[0]), 1)  # We don't expect to free pair when asking for narrow group.

        self.config.free_tcam(flat_tcams_to_relocate[0][0])

        self.config.allocate_tcam_for_group(fw_wide_group)

    def test_get_eligible_tcams_to_relocate_narrow(self):
        slice_idx = 0
        fw0_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_FW0_NARROW)
        fw1_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_FW1_NARROW)
        tx0_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_TX0_NARROW)
        self.config.allocate_tcam_for_group(fw1_group)
        while True:
            try:
                self.config.allocate_tcam_for_group(fw0_group)
            except ctm_cli.ResourceException:
                break

        try:
            self.config.allocate_tcam_for_group(tx0_group)
            self.assertTrue(False)
        except ctm_cli.ResourceException:
            pass

        tcams_to_relocate_per_prio = self.config.get_tcams_to_relocate_for_group(tx0_group)

        flat_tcams_to_relocate = [
            tcam for tcams_vec_prio in tcams_to_relocate_per_prio for tcam in tcams_to_relocate_per_prio[tcams_vec_prio]]

        self.assertGreater(len(flat_tcams_to_relocate), 0)  # We know for sure that FW1 SRAM occupies only one half.

        self.assertEqual(len(flat_tcams_to_relocate[0]), 1)  # We don't expect to free pair when asking for narrow group.

        self.config.free_tcam(flat_tcams_to_relocate[0][0])

        self.config.allocate_tcam_for_group(tx0_group)

    def test_term(self):
        term_group0 = ctm_cli.group_desc(0, ctm_cli.group_desc.GROUP_IFS_TERM)
        term_group1 = ctm_cli.group_desc(1, ctm_cli.group_desc.GROUP_IFS_TERM)
        while True:
            try:
                self.config.allocate_tcam_for_group(term_group0)
            except ctm_cli.ResourceException:
                break
        try:
            self.config.allocate_tcam_for_group(term_group1)
            self.assertTrue(False)
        except ctm_cli.ResourceException:
            pass

        tcams_to_relocate_per_prio = self.config.get_tcams_to_relocate_for_group(term_group1)

        flat_tcams_to_relocate = [
            tcam for tcams_vec_prio in tcams_to_relocate_per_prio for tcam in tcams_to_relocate_per_prio[tcams_vec_prio]]

        self.assertGreater(len(flat_tcams_to_relocate), 0)

        self.assertEqual(len(flat_tcams_to_relocate[0]), 1)  # We don't expect to free pair when asking for narrow group.

        self.config.free_tcam(flat_tcams_to_relocate[0][0])

        self.config.allocate_tcam_for_group(term_group1)

    def test_free_tx_wide(self):
        slice_idx = 0
        fw_wide_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_FW_WIDE)
        tx_wide_group = ctm_cli.group_desc(slice_idx, ctm_cli.group_desc.GROUP_IFS_TX_WIDE)
        while True:
            try:
                self.config.allocate_tcam_for_group(tx_wide_group)
            except ctm_cli.ResourceException:
                break

        try:
            self.config.allocate_tcam_for_group(fw_wide_group)
            self.assertTrue(False)
        except ctm_cli.ResourceException:
            pass

        tcams_to_relocate_per_prio = self.config.get_tcams_to_relocate_for_group(fw_wide_group)

        flat_tcams_to_relocate = [
            tcam for tcams_vec_prio in tcams_to_relocate_per_prio for tcam in tcams_to_relocate_per_prio[tcams_vec_prio]]

        self.assertGreater(len(flat_tcams_to_relocate), 0)  # We know for sure that FW1 SRAM occupies only one half.

        self.assertEqual(len(flat_tcams_to_relocate[0]), 2)  # We expect to free TX pair.

        self.config.free_tcam(flat_tcams_to_relocate[0][0])
        self.config.free_tcam(flat_tcams_to_relocate[0][1])

        self.config.allocate_tcam_for_group(fw_wide_group)


if __name__ == "__main__":
    unittest.main()
