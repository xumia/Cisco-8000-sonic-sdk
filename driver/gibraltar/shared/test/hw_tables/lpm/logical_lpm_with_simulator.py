#!/usr/bin/env python3
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

import hw_tablescli
import lldcli
from argument_parser import args_parser
from logical_lpm_base import logical_lpm_base
import lpm_hw_source_pacific
import lpm_hw_source_gb
import decor


DEVICE_PATH = "/dev/testdev"


class logical_lpm_with_simulator(logical_lpm_base):
    """
        This class activate the simulator and invalidate all the tcams registers- core_tcam, distributor_tcam.
        You have to activate the simulator in logical_lpm_base for delete this file as soon as the bug has fixed.
    """

    def setUp(self):
        hw_tablescli.set_logging_level(args_parser.logging_level)
        self.lld = lldcli.ll_device_create(0, DEVICE_PATH)
        assert self.lld is not None, "ll_device_create failed"
        print(" * Simulator is on")
        self.lld.set_device_simulator(hw_tablescli.create_lpm_device_simulator())
        self.invalidate_tcams_for_shadow_read()

        self.logical_lpm = self.create_logical_lpm()
        hw_tablescli.set_logging_level(args_parser.logging_level)

    def invalidate_tcams_for_shadow_read(self):
        '''
        There is a bug with shadow read. The initialization of default value is 0 (means valid),
        Instead of 1 (means not valid).
        This is happening only with lld device.
        '''
        is_gb = decor.is_gibraltar()
        is_pacific = decor.is_pacific()
        check = is_gb or is_pacific
        self.assertTrue(check, "Simulator support only GB or PACIFIC device")
        if is_pacific:
            tcam_to_invalidate = self.get_tcams_to_invalidate_pacific()
        else:
            tcam_to_invalidate = self.get_tcams_to_invalidate_gb()

        for (param, index) in tcam_to_invalidate:
            self.lld.invalidate_tcam(param, index)

    def get_tcams_to_invalidate_gb(self):
        invalidate_list = []
        tree = self.lld.get_gibraltar_tree()
        cores = lpm_hw_source_gb.get_device_cores_mems(tree)
        for distr_tcam in tree.cdb.top.clpm_group_map_tcam:
            distr_entries = distr_tcam.get_desc().entries // 2
            assert distr_entries == 128
            for i in range(distr_entries):
                invalidate_list.append((distr_tcam, i))

        for core_idx in range(16):
            entries = cores[core_idx].lpm_tcams[1].get_desc().entries // 2
            for idx in range(len(cores[core_idx].lpm_tcams)):
                tcam = cores[core_idx].lpm_tcams[idx]
                for i in range(entries):
                    invalidate_list.append((tcam, i))

        return invalidate_list

    def get_tcams_to_invalidate_pacific(self):
        invalidate_list = []
        tree = self.lld.get_pacific_tree()
        cores = lpm_hw_source_pacific.get_device_cores_mems(tree)
        distr_entries = tree.cdb.top.clpm_group_map_regs.get_desc().entries
        for distr_tcam in tree.cdb.top.clpm_group_map_tcam:
            for i in range(distr_entries):
                invalidate_list.append((distr_tcam, i))

        for core_idx in range(16):
            entries = cores[core_idx].trie_mems[0].get_desc().entries
            for idx in range(len(cores[core_idx].lpm_tcams)):
                tcam = cores[core_idx].lpm_tcams[idx]
                for i in range(entries):
                    invalidate_list.append((tcam, i))

        return invalidate_list
