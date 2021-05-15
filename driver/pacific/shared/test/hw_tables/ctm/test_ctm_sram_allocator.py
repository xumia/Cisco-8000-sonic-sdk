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
# [wabomock] Temnporary WA for undefined serialization symbol for
# udk_translation_info which is defined (implemented) in hld.
import test_hw_tables_ctmcli


class ctm_sram_allocator_test(unittest.TestCase):

    def init_result_channels_payload(self, allocator, num_of_rings, number_of_channels, channel_to_num_srams_map):
        for channel_idx in range(number_of_channels):
            for ring_idx in range(num_of_rings):
                allocator.set_result_channel_payload_width(ring_idx, channel_idx, channel_to_num_srams_map[channel_idx])

    def test_allocate_and_free_one_sram(self):
        num_of_rings = 1
        num_of_sram_blocks_per_ring = 1
        num_of_tcams_per_ring = 4
        num_of_channels_per_ring = 2
        channel_to_num_srams = {0: test_hw_tables_ctmcli.num_srams_ONE_SRAM,
                                1: test_hw_tables_ctmcli.num_srams_ONE_SRAM,
                                }

        allocator = test_hw_tables_ctmcli.ctm_sram_allocator(
            num_of_rings, num_of_tcams_per_ring, num_of_sram_blocks_per_ring, num_of_channels_per_ring)

        self.init_result_channels_payload(allocator, num_of_rings, num_of_channels_per_ring, channel_to_num_srams)

        ring_idx = 0
        allocator.allocate_srams(ring_idx, 0, 0)
        allocator.allocate_srams(ring_idx, 1, 0)
        try:
            # Should fail due to the lack of available SRAMs.
            allocator.allocate_srams(ring_idx, 2, 1)
            self.assertTrue(False)
        except test_hw_tables_ctmcli.ResourceException:
            pass
        allocator.free_srams(ring_idx, 0)
        allocator.free_srams(ring_idx, 1)
        allocator.allocate_srams(ring_idx, 2, 1)
        allocator.allocate_srams(ring_idx, 3, 1)

        try:
            # Should fail due to the lack of available SRAMs.
            allocator.allocate_srams(ring_idx, 0, 1)
            self.assertTrue(False)
        except test_hw_tables_ctmcli.ResourceException:
            pass

    def test_allocate_and_free_sram_pairs(self):
        num_of_rings = 1
        num_of_sram_blocks_per_ring = 2
        num_of_tcams_per_ring = 3
        num_of_channels_per_ring = 1

        channel_to_num_srams = {0: test_hw_tables_ctmcli.num_srams_TWO_SRAMS,
                                }

        allocator = test_hw_tables_ctmcli.ctm_sram_allocator(
            num_of_rings, num_of_tcams_per_ring, num_of_sram_blocks_per_ring, num_of_channels_per_ring)

        self.init_result_channels_payload(allocator, num_of_rings, num_of_channels_per_ring, channel_to_num_srams)

        allocator.allocate_srams(0, 0, 0)
        allocator.allocate_srams(0, 1, 0)

        try:
            # Should fail due to the lack of available SRAMs.
            allocator.allocate_srams(0, 2, 0)
            self.assertTrue(False)
        except test_hw_tables_ctmcli.ResourceException:
            pass

        allocator.free_srams(0, 0)
        allocator.allocate_srams(0, 2, 0)
        try:
            # Should fail due to the lack of available SRAMs.
            allocator.allocate_srams(0, 0, 0)
            self.assertTrue(False)
        except test_hw_tables_ctmcli.ResourceException:
            pass
        allocator.free_srams(0, 1)
        allocator.free_srams(0, 2)

    def test_fill_two_rings(self):
        num_of_rings = 2
        num_of_sram_blocks_per_ring = 12
        num_of_tcams_per_ring = num_of_sram_blocks_per_ring + 1
        num_of_channels_per_ring = 5

        channel_to_num_srams = {0: test_hw_tables_ctmcli.num_srams_TWO_SRAMS,
                                1: test_hw_tables_ctmcli.num_srams_ONE_SRAM,
                                2: test_hw_tables_ctmcli.num_srams_TWO_SRAMS,
                                3: test_hw_tables_ctmcli.num_srams_TWO_SRAMS,
                                4: test_hw_tables_ctmcli.num_srams_TWO_SRAMS}

        allocator = test_hw_tables_ctmcli.ctm_sram_allocator(
            num_of_rings, num_of_tcams_per_ring, num_of_sram_blocks_per_ring, num_of_channels_per_ring)

        self.init_result_channels_payload(allocator, num_of_rings, num_of_channels_per_ring, channel_to_num_srams)

        for ring_idx in range(num_of_rings):
            for tcam_idx in range(num_of_sram_blocks_per_ring):  # Every TCAM occupy two halves.
                allocator.allocate_srams(ring_idx, tcam_idx, 0)

            try:
                # Should fail due to the lack of available SRAMs.
                allocator.allocate_srams(ring_idx, num_of_tcams_per_ring - 1, 0)
                self.assertTrue(False)
            except test_hw_tables_ctmcli.ResourceException:
                pass

            try:
                # Should fail due to the lack of available SRAMs.
                allocator.allocate_srams(ring_idx, num_of_tcams_per_ring - 1, 1)
                self.assertTrue(False)
            except test_hw_tables_ctmcli.ResourceException:
                pass

            for tcam_idx in range(num_of_sram_blocks_per_ring):
                allocator.free_srams(ring_idx, tcam_idx)

    def test_two_res_channels_one_sram(self):
        num_of_rings = 1
        num_of_tcams_per_ring = 5
        num_of_sram_blocks_per_ring = 2
        num_of_channels_per_ring = 4  # 0,1,2 have one SRAM, 3 has two SRAMs

        channel_to_num_srams = {0: test_hw_tables_ctmcli.num_srams_ONE_SRAM,
                                1: test_hw_tables_ctmcli.num_srams_ONE_SRAM,
                                2: test_hw_tables_ctmcli.num_srams_ONE_SRAM,
                                3: test_hw_tables_ctmcli.num_srams_TWO_SRAMS}

        allocator = test_hw_tables_ctmcli.ctm_sram_allocator(
            num_of_rings, num_of_tcams_per_ring, num_of_sram_blocks_per_ring, num_of_channels_per_ring)

        self.init_result_channels_payload(allocator, num_of_rings, num_of_channels_per_ring, channel_to_num_srams)

        ring_idx = 0

        allocator.allocate_srams(ring_idx, 0, 0)
        allocator.allocate_srams(ring_idx, 1, 1)
        allocator.allocate_srams(ring_idx, 2, 0)
        allocator.allocate_srams(ring_idx, 3, 1)

        for res_ch in range(2):
            try:
                # Should fail due to the lack of available SRAMs.
                allocator.allocate_srams(0, 4, res_ch)
                self.assertTrue(False)
            except test_hw_tables_ctmcli.ResourceException:
                pass

        # Free a whole SRAM block
        allocator.free_srams(ring_idx, 0)  # Free TCAM 0's SRAMS
        allocator.free_srams(ring_idx, 2)  # Free TCAM 2's SRAMS

        allocator.allocate_srams(ring_idx, 0, 2)
        allocator.allocate_srams(ring_idx, 2, 2)

        allocator.free_srams(ring_idx, 0)
        allocator.free_srams(ring_idx, 1)
        allocator.free_srams(ring_idx, 2)
        allocator.free_srams(ring_idx, 3)

        allocator.allocate_srams(ring_idx, 0, 3)
        allocator.allocate_srams(ring_idx, 1, 3)

        try:
            # Should fail due to the lack of available SRAMs.
            allocator.allocate_srams(ring_idx, 2, 0)
            self.assertTrue(False)
        except test_hw_tables_ctmcli.ResourceException:
            pass

        try:
            # Should fail due to the lack of available SRAMs.
            allocator.allocate_srams(ring_idx, 2, 3)
            self.assertTrue(False)
        except test_hw_tables_ctmcli.ResourceException:
            pass


if __name__ == "__main__":
    unittest.main()
