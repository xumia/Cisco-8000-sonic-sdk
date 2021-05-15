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


import re
import csv
from lpm_hw_source_base import lpm_hw_source_base
from bit_utils import get_bits, set_bits

NUMBER_OF_CORES = 16
NUMBER_OF_L2_SRAM_BANKS = 16
HBM_NUM_REPLICATIONS = 4
HBM_START_INDEX = 4096
HBM_NUM_OF_BUCKETS = 12 * 1024
WARNING_COLOR = '\033[93m'
END_COLOR = '\033[0m'


# @brief Class implements the lpm_hw_source_base interface for reading LPM's memory from CSV dump.
class lpm_hw_csv_parser(lpm_hw_source_base):

    # @brief Initialize the reader class by parsing the CSV dump.
    #
    # param[in] csv_fname      Name of the CSV dump.
    def __init__(self, csv_fname):
        self.clpm_group_map_tcam = {}
        self.top_clpm_group_map_regs = {}
        self.top_lpm_group_map_table = {}

        self.cores = [self.core() for _ in range(NUMBER_OF_CORES)]
        self.load_csv_to_lpm_csv_reader(csv_fname)

    def read_tcam_line_to_group_table(self, mem_line, replica=0):
        if replica > 0:
            print(WARNING_COLOR + "WARNING: Pacific don't have tcam_line -> group table replicas" + END_COLOR)
        return self.top_clpm_group_map_regs[mem_line]

    def read_group_map_tcam(self, mem_line, replica=0):
        return self.clpm_group_map_tcam[replica][mem_line]

    def read_group_to_core_table(self, mem_line, replica=0):
        if replica > 0:
            print(WARNING_COLOR + "WARNING: Pacific don't have group -> core table replicas" + END_COLOR)
        return self.top_lpm_group_map_table[mem_line]

    def read_core_lpm_tcam(self, core_idx, tcam_idx, mem_line):
        return self.cores[core_idx].lpm_tcam[tcam_idx][mem_line]

    def read_core_trie_mem(self, core_idx, tcam_idx, mem_line):
        return self.cores[core_idx].trie_mem[tcam_idx][mem_line]

    def read_core_subtrie_mem(self, core_idx, mem_line):
        if mem_line < len(self.cores[core_idx].subtrie_mem):
            return self.cores[core_idx].subtrie_mem[mem_line]
        else:
            mem_line -= len(self.cores[core_idx].subtrie_mem)
            return self.cores[core_idx].extnd_subtrie_mem[mem_line]

    def read_core_sram_group(self, core_idx, bank_idx, mem_line):
        return self.cores[core_idx].sram_groups[bank_idx][mem_line]

    def read_hbm_line(self, core_idx, mem_line, replica=0):
        return self.cores[core_idx].hbm.get(mem_line, 0)

    # @brief private data structures for storing the parsed CSV.
    class core:
        def __init__(self):
            self.lpm_tcam = [{} for _ in range(4)]  # TCAM
            self.trie_mem = [{}, {}]  # TCAM memory
            self.subtrie_mem = {}  # L1
            self.extnd_subtrie_mem = {}  # Extended L1
            self.sram_groups = [{} for _ in range(NUMBER_OF_L2_SRAM_BANKS)]  # L2
            self.hbm = {}

    # line template:
    # "type, core_idx, memory, line, value, key, mask, valid"
    def load_csv_to_lpm_csv_reader(self, fp):

        with open(fp, "r") as file:
            reader = csv.DictReader(file, skipinitialspace=True)
            for line in reader:
                # Distributor TCAM row -> group mapping
                if "cdb.top.clpm_group_map_regs" in line["memory"]:
                    regex_pattern = "cdb.top.clpm_group_map_regs"
                    m = re.search(regex_pattern, line["memory"])
                    if m is not None:
                        line_idx = int(line["line"])
                        self.top_clpm_group_map_regs[line_idx] = int(line["value"], 16)
                        continue

                # Distributor TCAM keys table
                if "cdb.top.clpm_group_map_tcam" in line["memory"]:
                    regex_pattern = "cdb.top.clpm_group_map_tcam\[(?P<replica_number>[0-9]+)\]"
                    m = re.search(regex_pattern, line["memory"])
                    if m is not None:
                        distributor_tcam_id = int(m["replica_number"])
                        key = int(line["key"], 16)
                        mask = int(line["mask"], 16)
                        valid = int(line["valid"])
                        if distributor_tcam_id not in self.clpm_group_map_tcam.keys():
                            self.clpm_group_map_tcam[distributor_tcam_id] = {}
                        line_idx = int(line["line"])
                        self.clpm_group_map_tcam[distributor_tcam_id][line_idx] = (key, mask, valid)
                        continue

                # Distributor TCAM group -> core mapping
                if "cdb.top.lpm_group_map_table" in line["memory"]:
                    regex_pattern = "cdb.top.lpm_group_map_table\[(?P<line_idx>[0-9]+)\]"
                    m = re.search(regex_pattern, line["memory"])
                    if m is not None:
                        line_idx = int(m["line_idx"])
                        self.top_lpm_group_map_table[line_idx] = int(line["value"], 16)
                        continue

                # Core TCAM
                if "lpm_tcam" in line["memory"]:
                    regex_pattern = "lpm_tcam\[(?P<tcam_number>[0-9]+)\]"
                    m = re.search(regex_pattern, line["memory"])
                    if m is not None:
                        core_id = int(line["core_idx"])
                        core = self.cores[core_id]

                        # Map TCAM indices to 0..3
                        # Odd reduced lpm cores use TCAMs 4..7
                        # Odd full lpm cores use TCAMs 6..9
                        # All other cores use TCAMs 0..3
                        mod = 4 if "reduced" in line["memory"] else 6
                        tcam_number = ((int(m["tcam_number"]) % mod))

                        key = int(line["key"], 16)
                        mask = int(line["mask"], 16)
                        valid = int(line["valid"])
                        line_idx = int(line["line"])
                        core.lpm_tcam[tcam_number][line_idx] = (key, mask, valid)
                        continue

                # Core TCAM memory
                if ".trie_mem" in line["memory"] or "extnd_trie_mem" in line["memory"]:
                    mem_idx = 1 if "extnd" in line["memory"] else 0
                    line_idx = int(line["line"])
                    core.trie_mem[mem_idx][line_idx] = int(line["value"], 16)
                    continue

                # L1 extended memory
                if "extnd_subtrie_mem" in line["memory"]:
                    regex_pattern = "extnd_subtrie_mem"
                    m = re.search(regex_pattern, line["memory"])
                    if m is not None:
                        core_id = int(line["core_idx"])
                        core = self.cores[core_id]
                        value = int(line["value"], 16)
                        line_idx = int(line["line"])
                        core.extnd_subtrie_mem[line_idx] = value
                        continue

                # L1 memory
                if "subtrie_mem" in line["memory"]:
                    regex_pattern = "subtrie_mem"
                    m = re.search(regex_pattern, line["memory"])
                    if m is not None:
                        core_id = int(line["core_idx"])
                        core = self.cores[core_id]
                        value = int(line["value"], 16)
                        line_idx = int(line["line"])
                        core.subtrie_mem[line_idx] = value
                        continue

                # L2 banks
                if "srams_group" in line["memory"]:
                    regex_pattern = "srams_group[0-1]\[(?P<bank>[0-9]+)\]"
                    m = re.search(regex_pattern, line["memory"])
                    if m is not None:
                        core_id = int(line["core_idx"])
                        core = self.cores[core_id]
                        value = int(line["value"], 16)
                        bank_idx = int(m["bank"])
                        line_idx = int(line["line"])
                        core.sram_groups[bank_idx][line_idx] = value
                        continue

                if "hbm" in line["memory"]:
                    core_id = int(line["core_idx"])
                    core = self.cores[core_id]
                    value = int(line["value"], 16)
                    line_idx = int(line["line"])
                    core.hbm[line_idx] = value
                    continue


def get_device_cores_mems(tree):
    NUM_CDB_CORES = 4
    cores = []
    for cdb_idx in range(NUM_CDB_CORES):
        for core in [tree.cdb.core_reduced[cdb_idx], tree.cdb.core[cdb_idx]]:
            for lpm_idx_within_cdb_core in [0, 1]:
                core_mems = lpm_hw_device.core_mem()
                num_tcams = len(core.lpm_tcam)
                num_tcams_per_lpm_core = num_tcams // 2
                # 4 TCAMs of size 1024 (actually 8 of 512)
                core_mems.lpm_tcams = [core.lpm_tcam[lpm_idx_within_cdb_core * num_tcams_per_lpm_core + i] for i in range(4)]

                # TCAM's memory tables.
                core_mems.trie_mems = []
                core_mems.trie_mems.append(core.trie_mem[lpm_idx_within_cdb_core])
                core_mems.trie_mems.append(core.extnd_trie_mem[lpm_idx_within_cdb_core])

                # L1
                core_mems.subtrie_mem = core.subtrie_mem[lpm_idx_within_cdb_core]
                core_mems.extnd_subtrie_mem = core.extnd_subtrie_mem[lpm_idx_within_cdb_core]

                # L2/CEM banks
                banks = [core.srams_group0, core.srams_group1]
                core_mems.sram_groups = banks[lpm_idx_within_cdb_core]

                cores.append(core_mems)
    return cores


# @brief Wrapper class for reading device's LPM memory on demand.
class lpm_hw_device(lpm_hw_source_base):

    # @brief Initialize the wrapper class with device.
    #
    # param[in] la_device        la_device object.
    def __init__(self, la_device):
        self.ll_device = la_device.get_ll_device()
        self.tree = self.ll_device.get_pacific_tree()
        self.cores = get_device_cores_mems(self.tree)
        # HBM registers:
        self.hbm_regs = []
        is_tall_channel = [False, False, True, True, True, True, False, False]
        for channel_idx, is_tall in enumerate(is_tall_channel):
            if is_tall:
                self.hbm_regs.append(
                    self.tree.hbm.chnl[channel_idx].tall.cpu_mem_access)
            else:
                self.hbm_regs.append(
                    self.tree.hbm.chnl[channel_idx].wide.cpu_mem_access)

    def read_tcam_line_to_group_table(self, mem_line, replica=0):
        if replica > 0:
            print(WARNING_COLOR + "WARNING: Pacific don't have tcam_line -> group table replicas" + END_COLOR)
        distr_sram = self.tree.cdb.top.clpm_group_map_regs
        return self.ll_device.read_memory(distr_sram, mem_line)

    def read_group_map_tcam(self, mem_line, replica=0):
        distr_tcam = self.tree.cdb.top.clpm_group_map_tcam[replica]
        return self.ll_device.read_tcam(distr_tcam, mem_line)

    def read_group_to_core_table(self, mem_line, replica=0):
        if replica > 0:
            print(WARNING_COLOR + "WARNING: Pacific don't have group -> core table replicas" + END_COLOR)
        group_to_core_sram = self.tree.cdb.top.lpm_group_map_table
        return self.ll_device.read_register(group_to_core_sram[mem_line])

    def read_core_lpm_tcam(self, core_idx, tcam_idx, mem_line):
        tcam = self.cores[core_idx].lpm_tcams[tcam_idx]
        return self.ll_device.read_tcam(tcam, mem_line)

    def read_core_trie_mem(self, core_idx, tcam_idx, mem_line):
        mem = self.cores[core_idx].trie_mems[tcam_idx]
        return self.ll_device.read_memory(mem, mem_line)

    def read_core_subtrie_mem(self, core_idx, mem_line):
        if mem_line < self.cores[core_idx].subtrie_mem.get_desc().entries:
            mem = self.cores[core_idx].subtrie_mem
        else:
            mem_line = mem_line - self.cores[core_idx].subtrie_mem.get_desc().entries
            assert mem_line >= 0
            mem = self.cores[core_idx].extnd_subtrie_mem
        return self.ll_device.read_memory(mem, mem_line)

    def read_core_sram_group(self, core_idx, bank_idx, mem_line):
        bank = self.cores[core_idx].sram_groups[bank_idx]
        return self.ll_device.read_memory(bank, mem_line)

    def read_hbm_line(self, core_idx, mem_line, replica=0):
        channel_idx, register_data = self.make_hbm_read_data_request(
            core_idx, mem_line, replica)
        reg = self.hbm_regs[channel_idx]
        self.ll_device.write_register(reg, register_data)
        ready_to_read = 1
        # Ready to read when send_command bit is 0.
        while ready_to_read != 0:
            out_reg = self.ll_device.read_register(reg)
            ready_to_read = get_bits(out_reg, 0, 0)

        hbm_data_width = 1024
        hbm_data_start_offset = 25
        out_value = get_bits(out_reg, hbm_data_start_offset + hbm_data_width - 1, hbm_data_start_offset)
        return out_value

    @staticmethod
    def make_hbm_read_data_request(core_idx, mem_line, replica):
        dest_index = (mem_line << 4) + core_idx

        bank_channel = get_bits(dest_index, 7, 0) + 4 * replica
        bank_row = get_bits(dest_index, 14, 8) + 128 * replica
        column = get_bits(dest_index, 18, 15)

        channel = get_bits(bank_channel, 0, 0)
        channel_idx = get_bits(bank_channel, 3, 1)
        bank_msb = get_bits(bank_channel, 5, 4)
        bank_lsb = get_bits(bank_channel, 7, 6)
        bank = (bank_msb << 2) + bank_lsb

        register_data = 1  # LSB is 1 for send command.
        register_data = set_bits(register_data, 1, 1, channel)
        register_data = set_bits(register_data, 5, 2, bank)
        register_data = set_bits(register_data, 6, 6, 1)  # read/write bit, 1 for read.
        register_data = set_bits(register_data, 20, 7, bank_row)  # read/write bit, 1 for read.
        register_data = set_bits(register_data, 24, 21, column)  # read/write bit, 1 for read.

        return channel_idx, register_data

    class core_mem:
        pass

    def read_lpm_memory(self, filename="./lpm_data.csv", print_hbm=True, print_hbm_replicas=False):
        fd = open(filename, "w")
        print("type, core_idx, memory, line, value, key, mask, valid", file=fd)
        # distributer
        distr_entries = self.tree.cdb.top.clpm_group_map_regs.get_desc().entries
        for i in range(distr_entries):
            v = self.ll_device.read_memory(self.tree.cdb.top.clpm_group_map_regs, i)
            print('%s, , %s, %d, 0x%x' % ("distributor_groups", self.tree.cdb.top.clpm_group_map_regs.get_name(), i, v), file=fd)

        for distr_tcam in self.tree.cdb.top.clpm_group_map_tcam:
            for i in range(distr_entries):
                k, m, valid = self.ll_device.read_tcam(distr_tcam, i)
                print('%s, , %s, %d, ,0x%x, 0x%x, %d' % ("distributor_tcam", distr_tcam.get_name(), i, k, m, valid), file=fd)

        # group to core mapping
        for reg in self.tree.cdb.top.lpm_group_map_table:
            v = self.ll_device.read_register(reg)
            print('%s, , %s, , 0x%x' % ("distributor_cores", reg.get_name(), v), file=fd)

        # Cores data
        for core_idx in range(NUMBER_OF_CORES):

            # TCAM
            entries = self.cores[core_idx].trie_mems[0].get_desc().entries
            for idx in range(len(self.cores[core_idx].lpm_tcams)):
                tcam = self.cores[core_idx].lpm_tcams[idx]
                for i in range(entries):
                    k, m, valid = self.ll_device.read_tcam(tcam, i)
                    print('%s, %d, %s, %d, ,0x%x, 0x%x, %d' % ("core_tcam", core_idx, tcam.get_name(), i, k, m, valid), file=fd)

            # TCAM memory
            for idx in range(len(self.cores[core_idx].trie_mems)):
                entries = self.cores[core_idx].trie_mems[idx].get_desc().entries
                mem = self.cores[core_idx].trie_mems[idx]
                for i in range(entries):
                    v = self.ll_device.read_memory(mem, i)
                    print('%s, %d, %s, %d, 0x%x' % ("core_tcam_memory", core_idx, mem.get_name(), i, v), file=fd)

            mem = self.cores[core_idx].subtrie_mem
            for i in range(mem.get_desc().entries):
                v = self.ll_device.read_memory(mem, i)
                print('%s, %d, %s, %d, 0x%x' % ("l1_memory", core_idx, mem.get_name(), i, v), file=fd)

            mem = self.cores[core_idx].extnd_subtrie_mem
            for i in range(mem.get_desc().entries):
                v = self.ll_device.read_memory(mem, i)
                print('%s, %d, %s, %d, 0x%x' % ("extnd_l1_memory", core_idx, mem.get_name(), i, v), file=fd)

            for bank_idx in range(NUMBER_OF_L2_SRAM_BANKS):
                bank = self.cores[core_idx].sram_groups[bank_idx]
                for i in range(bank.get_desc().entries):
                    v = self.ll_device.read_memory(bank, i)
                    print('%s, %d, %s, %d, 0x%x' % ("l2_bank_memory", core_idx, bank.get_name(), i, v), file=fd)

            if print_hbm:
                for hw_index in range(HBM_START_INDEX, HBM_NUM_OF_BUCKETS + HBM_START_INDEX):
                    value = self.read_hbm_line(core_idx, hw_index)
                    print('%s, %d, hbm[%d], %d, 0x%x' % ("l2_hbm_memory", core_idx, 0, hw_index, value), file=fd)
                    for i in range(1, HBM_NUM_REPLICATIONS):
                        replica_value = self.read_hbm_line(
                            core_idx, hw_index, replica=i)
                        if print_hbm_replicas:
                            print('%s, %d, hbm[%d], %d, 0x%x' % ("l2_hbm_memory", core_idx, i, hw_index, value), file=fd)

        fd.close()
