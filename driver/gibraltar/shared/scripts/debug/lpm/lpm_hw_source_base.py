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

from abc import abstractmethod, ABC


# @brief Reader class for reading LPM's memory
class lpm_hw_source_base(ABC):

    # @brief Reads the cdb.top.clpm_group_map_regs
    #
    # param[in]  mem_line       Entry index to read from.
    # param[in] replica         Table replica number to read from.
    # param[out] ret_val        Return value bit vector.
    @abstractmethod
    def read_tcam_line_to_group_table(self, mem_line, replica=0):
        pass

    # @brief Reads the cdb.top.clpm_group_map_tcam register
    #
    # param[in] mem_line    Entry index to read from.
    # param[in] replica     Replica number to read from. Pacific supports 12 lookup per clock. Each lookup reach to different distributor replication.
    # param[out] (k,m,v)    Key,mask and valid values of the given memory line.
    @abstractmethod
    # def read_cdb_top_clpm_group_map_tcam(self, replica, mem_line):
    def read_group_map_tcam(self, mem_line, replica=0):
        pass

    # @brief Reads the cdb.top.lpm_group_map_table
    #
    # param[in]  mem_line       Entry index to read from.
    # param[in] replica         Table replica number to read from.
    # param[out] ret_val        Return value bit vector.
    @abstractmethod
    def read_group_to_core_table(self, mem_line, replica=0):
        pass

    # @brief Reads the in core tcam.
    #
    # param[in] core_idx        Index of the core to read from.
    # param[in] tcam_idx        Index of the tcam to read from.
    # param[in] mem_line        Entry index to read from.
    # param[out] (k,m,v)        Key,mask and valid values of the given memory line.
    @abstractmethod
    def read_core_lpm_tcam(self, core_idx, tcam_idx, mem_line):
        pass

    # @brief Reads the in core tcam memory.
    #
    # param[in] core_idx        Index of the core to read from.
    # param[in] tcam_idx        Index of the tcam memory to read from.
    # param[in] mem_line        Entry index to read from.
    # param[out] ret_val        Return value bit vecotr.
    @abstractmethod
    def read_core_trie_mem(self, core_idx, tcam_idx, mem_line):
        pass

    # @brief Reads the subtrie memory.
    #
    # param[in] core_idx        Index of the core to read from.
    # param[in] mem_line        Entry index to read from.
    # param[out] ret_val        Return value bit vecotr.
    @abstractmethod
    def read_core_subtrie_mem(self, core_idx, mem_line):
        pass

    # @brief Reads the srams_groups memory.
    #
    # param[in] core_idx        Index of the core to read from.
    # param[in] bank_idx        Index of the bank to read from.
    # param[in] mem_line        Entry index to read from.
    # param[out] ret_val        Return value bit vecotr.
    @abstractmethod
    def read_core_sram_group(self, core_idx, bank_idx, mem_line):
        pass

    # @brief Reads the HBM memory.
    #
    # param[in] core_idx        Index of the core to read from.
    # param[in] mem_line        Entry index to read from.
    # param[in] replica         Table replica number to read from.
    # param[out] ret_val        Return value bit vecotr.
    @abstractmethod
    def read_hbm_line(self, core_idx, mem_line, replica=0):
        pass
