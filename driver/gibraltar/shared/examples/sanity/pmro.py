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

import lldcli as lld
import time


class Pmro(object):

    pmro_blocks_list = {
        'LLD_BLOCK_ID_FRM__DMC': lld.pacific_tree.LLD_BLOCK_ID_FRM,
        'LLD_BLOCK_ID_IFG1_SERDES_POOL': lld.pacific_tree.LLD_BLOCK_ID_IFG1_SERDES_POOL,
        'LLD_BLOCK_ID_IFG2_SERDES_POOL': lld.pacific_tree.LLD_BLOCK_ID_IFG2_SERDES_POOL,
        'LLD_BLOCK_ID_IFG3_SERDES_POOL': lld.pacific_tree.LLD_BLOCK_ID_IFG3_SERDES_POOL,
        'LLD_BLOCK_ID_IFG4_SERDES_POOL': lld.pacific_tree.LLD_BLOCK_ID_IFG4_SERDES_POOL,
        'LLD_BLOCK_ID_IFG5_SERDES_POOL': lld.pacific_tree.LLD_BLOCK_ID_IFG5_SERDES_POOL,
        'LLD_BLOCK_ID_IFG6_SERDES_POOL': lld.pacific_tree.LLD_BLOCK_ID_IFG6_SERDES_POOL,
        'LLD_BLOCK_ID_IFG7_SERDES_POOL': lld.pacific_tree.LLD_BLOCK_ID_IFG7_SERDES_POOL,
        'LLD_BLOCK_ID_IFG8_SERDES_POOL': lld.pacific_tree.LLD_BLOCK_ID_IFG8_SERDES_POOL,
        'LLD_BLOCK_ID_IFG9_SERDES_POOL': lld.pacific_tree.LLD_BLOCK_ID_IFG9_SERDES_POOL,
        'LLD_BLOCK_ID_IFGA_SERDES_POOL': lld.pacific_tree.LLD_BLOCK_ID_IFGA_SERDES_POOL,
        'LLD_BLOCK_ID_CDB_TOP': lld.pacific_tree.LLD_BLOCK_ID_CDB_TOP,
        'LLD_BLOCK_ID_RXPP0_FWD': lld.pacific_tree.LLD_BLOCK_ID_RXPP0_FWD,
        'LLD_BLOCK_ID_RXPP1_FWD': lld.pacific_tree.LLD_BLOCK_ID_RXPP1_FWD,
        'LLD_BLOCK_ID_RXPP2_FWD': lld.pacific_tree.LLD_BLOCK_ID_RXPP2_FWD,
        'LLD_BLOCK_ID_RXPP3_FWD': lld.pacific_tree.LLD_BLOCK_ID_RXPP3_FWD,
        'LLD_BLOCK_ID_RXPP4_FWD': lld.pacific_tree.LLD_BLOCK_ID_RXPP4_FWD,
        'LLD_BLOCK_ID_RXPP5_FWD': lld.pacific_tree.LLD_BLOCK_ID_RXPP5_FWD,
        'LLD_BLOCK_ID_TXPP0': lld.pacific_tree.LLD_BLOCK_ID_TXPP0,
        'LLD_BLOCK_ID_TXPP1': lld.pacific_tree.LLD_BLOCK_ID_TXPP1,
        'LLD_BLOCK_ID_TXPP2': lld.pacific_tree.LLD_BLOCK_ID_TXPP2,
        'LLD_BLOCK_ID_TXPP3': lld.pacific_tree.LLD_BLOCK_ID_TXPP3,
        'LLD_BLOCK_ID_TXPP4': lld.pacific_tree.LLD_BLOCK_ID_TXPP4,
        'LLD_BLOCK_ID_TXPP5': lld.pacific_tree.LLD_BLOCK_ID_TXPP5,
        'LLD_BLOCK_ID_MMU': lld.pacific_tree.LLD_BLOCK_ID_MMU,
        'LLD_BLOCK_ID_REASSEMBLY': lld.pacific_tree.LLD_BLOCK_ID_REASSEMBLY,
        'LLD_BLOCK_ID_NW_REORDER': lld.pacific_tree.LLD_BLOCK_ID_NW_REORDER,
        'LLD_BLOCK_ID_RX_PDR__PRE_VOQ': lld.pacific_tree.LLD_BLOCK_ID_RX_PDR,
        'LLD_BLOCK_ID_PDVOQ': lld.pacific_tree.LLD_BLOCK_ID_PDVOQ_SHARED_MMA,
        'LLD_BLOCK_ID_ICS_TOP__POST_VOQ': lld.pacific_tree.LLD_BLOCK_ID_ICS_TOP,
        'LLD_BLOCK_ID_TX_CGM_TOP__EGR': lld.pacific_tree.LLD_BLOCK_ID_TX_CGM_TOP,
        'LLD_BLOCK_ID_SCH_TOP': lld.pacific_tree.LLD_BLOCK_ID_SCH_TOP,
        'LLD_BLOCK_ID_PDOQ': lld.pacific_tree.LLD_BLOCK_ID_PDOQ_SHARED_MEM,
        'LLD_BLOCK_ID_FDLL': lld.pacific_tree.LLD_BLOCK_ID_FDLL_SHARED_MEM,
        'LLD_BLOCK_ID_RX_COUNTERS_CNT': lld.pacific_tree.LLD_BLOCK_ID_RX_COUNTERS,
        'LLD_BLOCK_ID_SMS_QUAD0': lld.pacific_tree.LLD_BLOCK_ID_SMS_QUAD0,
        'LLD_BLOCK_ID_SMS_QUAD1': lld.pacific_tree.LLD_BLOCK_ID_SMS_QUAD1,
        'LLD_BLOCK_ID_SMS_QUAD2': lld.pacific_tree.LLD_BLOCK_ID_SMS_QUAD2,
        'LLD_BLOCK_ID_SMS_QUAD3': lld.pacific_tree.LLD_BLOCK_ID_SMS_QUAD3,
        'LLD_BLOCK_ID_DVOQ__DRAM_CTRL': lld.pacific_tree.LLD_BLOCK_ID_DVOQ
    }

    PMRO_CTRL_REG_W = 39
    PMRO_CTRL_REG_ADDR = 0x49
    PMRO_EXECUTE = 0
    PMRO_CMD = 1
    PMRO_SBUS_RESET = 3
    PMRO_ADDR = 4
    PMRO_DATA = 7

    PMRO_STATUS_REG_W = 34
    PMRO_STATUS_REG_ADDR = 0x4A
    PMRO_RDATA = 0
    PMRO_FAILED = 32
    PMRO_FINISHED = 33

    PMRO_CMD_RESET = 0
    PMRO_CMD_WRITE = 1
    PMRO_CMD_READ = 2
    PMRO_CMD_INVALID = 3

    PMRO_SVT_ADDR = 1
    PMRO_LVT_ADDR = 2
    PMRO_ULVT_ADDR = 3
    PMRO_INTERCONNECT_ADDR = 4

    def reset_pmro(self, block_id, reset_val):
        # print("reset_pmro: reset_val = %0d" % reset_val)
        val = 0x0
        val |= reset_val << Pmro.PMRO_SBUS_RESET
        self.ll_device.write_register_raw(block_id, Pmro.PMRO_CTRL_REG_ADDR, Pmro.PMRO_CTRL_REG_W, val)
        time.sleep(0.001)

    def pmro_cmd(self, block_id, cmd_type, addr, data):
        val = 0x0
        val |= addr << Pmro.PMRO_ADDR
        val |= cmd_type << Pmro.PMRO_CMD
        val |= data << Pmro.PMRO_DATA
        self.ll_device.write_register_raw(block_id, Pmro.PMRO_CTRL_REG_ADDR, Pmro.PMRO_CTRL_REG_W, val)
        val |= 1 << Pmro.PMRO_EXECUTE
        self.ll_device.write_register_raw(block_id, Pmro.PMRO_CTRL_REG_ADDR, Pmro.PMRO_CTRL_REG_W, val)
        time.sleep(0.001)
        rval = self.ll_device.read_register_raw(block_id, Pmro.PMRO_STATUS_REG_ADDR, Pmro.PMRO_STATUS_REG_W)
        failed = (rval >> Pmro.PMRO_FAILED) & 0x1
        finished = (rval >> Pmro.PMRO_FINISHED) & 0x1
        rdata = (rval >> Pmro.PMRO_RDATA) & 0xffffffff
        if ((finished == 0) | (failed == 1)):
            print("ERROR: finished = %0d, failed = %0d" % (finished, failed))
            return (0)
        else:
            # print("pmro_cmd: cmd_type = %0d, addr = 0x%0x, data = 0x%0x, finished = %0d, failed = %0d, rdata = 0x%0x" % (cmd_type, addr, data, finished, failed, rdata))
            return (rdata)

    def read_pmro(self, block_id):
        self.reset_pmro(block_id, 1)
        self.reset_pmro(block_id, 0)

        # write interconnect register
        if self.en_interconnect:
            interconnect_val = 0xffff
        else:
            interconnect_val = 0x0
        self.pmro_cmd(block_id, Pmro.PMRO_CMD_WRITE, Pmro.PMRO_INTERCONNECT_ADDR, interconnect_val)

        # write svt register
        if self.en_svt:
            val = 0xffff
        else:
            val = 0x0
        self.pmro_cmd(block_id, Pmro.PMRO_CMD_WRITE, Pmro.PMRO_SVT_ADDR, val)

        # write lvt register
        if self.en_lvt:
            val = 0xffff
        else:
            val = 0x0
        self.pmro_cmd(block_id, Pmro.PMRO_CMD_WRITE, Pmro.PMRO_LVT_ADDR, val)

        # write ulvt register
        if self.en_ulvt:
            val = 0xffff
        else:
            val = 0x0
        self.pmro_cmd(block_id, Pmro.PMRO_CMD_WRITE, Pmro.PMRO_ULVT_ADDR, val)

        # read_registers
        for i in range(5):
            self.pmro_cmd(block_id, Pmro.PMRO_CMD_READ, i + 1, 0)

        # clear oscilator counter
        self.pmro_cmd(block_id, Pmro.PMRO_CMD_WRITE, 6, 0)

        # start test
        self.pmro_cmd(block_id, Pmro.PMRO_CMD_WRITE, 0, 1)

        # wait for end
        time.sleep(0.001)

        # check done
        rdata = self.pmro_cmd(block_id, Pmro.PMRO_CMD_READ, 0, 0)
        if (rdata & 0x1):
            print("ERROR: pmro not done, try prolonging timeout")

        # read oscilator counter
        timer = rdata = self.pmro_cmd(block_id, Pmro.PMRO_CMD_READ, 6, 0)

        # sbus id - need to be 0xb
        sbus_id = self.pmro_cmd(block_id, Pmro.PMRO_CMD_READ, 7, 0)

        if (sbus_id != 0xb):
            print("ERROR: sbus_id = 0x%0x", sbus_id)

        return (timer)

    def read_all_pmros(self):
        # global pmro_blocks_vals
        for name in self.pmro_blocks_list.keys():
            block_id = self.pmro_blocks_list[name]
            timer = self.read_pmro(block_id)
            if self.verbose:
                print("block %s: %0d" % (name, timer))
            self.pmro_blocks_vals[name] = timer

    def __init__(self, ll_device, out_file=None, verbose=False):
        self.ll_device = ll_device
        self.pmro_dict = {}
        self.out_file = out_file
        self.set_pmro_spec()
        self.verbose = verbose

        self.en_svt = 1
        self.en_lvt = 1
        self.en_ulvt = 1
        self.en_interconnect = 1
        self.pmro_blocks_vals = {}

    def get_pmro_all_blocks(self, force_read=False):
        """
        reads the pmro values from all block (if forced and reads the temp during read

        :param force_read:
        :return:  dictionary of pmro values per blocks
        """

        if self.verbose:
            print("en_svt={}, en_lvt={}, en_ulvt={}, en_interconnect={}".format(self.en_svt,
                                                                                self.en_lvt,
                                                                                self.en_ulvt,
                                                                                self.en_interconnect))
        pmro_dict = {}
        # fix - to allow force read need to assine to pmro_dict and not just read pmro_dict
        if force_read:
            self.read_all_pmros()
            for name in self.pmro_blocks_vals.keys():
                pmro_dict[name] = self.pmro_blocks_vals[name]
            # temps = self.get_temp()
            # pmro_dict["PMRO_READ_TEMP"] = round(temps['NP_diode_0'], 3)
            self.pmro_dict = pmro_dict
        else:
            pmro_dict = self.pmro_dict
            if pmro_dict == {}:
                pmro_dict = self.get_pmro_all_blocks(force_read=True)
        return pmro_dict
        # print("n = %0d, avg = %f, max = %0d, min = %0d, pmro_cnt_normalized_to_50mhz_ref = %f" % (n, avg, max, min, ))

    def get_pmro_ref(self, force_read=False):
        avg = self.get_pmro_with_stats(force_read)["AVG"]
        return avg * 6

    def get_pmro_time(self):
        pmro_dict = self.get_pmro_all_blocks(True)
        avg_ref = self.get_pmro_ref()
        # converting the value of the counter to a value in seconds
        pmro_time = 500 / (avg_ref * 50 / 4096)
        pmro_dict["PMRO_COUNT"] = avg_ref
        pmro_dict["TOTAL_TIME"] = pmro_time
        return pmro_dict

    def get_pmro_with_stats(self, force_read=False):
        from math import pow, sqrt
        pmro_dict = self.get_pmro_all_blocks(force_read)

        count = 0
        avg = 0
        max_value = 0
        min_value = 0xffffffffff
        for name in pmro_dict.keys():
            # print("{:<60}: {:0d}".format(name, pmro_blocks_vals[name]))
            avg += pmro_dict[name]
            count += 1
            if max_value < pmro_dict[name]:
                max_value = pmro_dict[name]
            if min_value > pmro_dict[name]:
                min_value = pmro_dict[name]
        avg = avg / count

        # calculating STD
        std_sum = 0
        for name in pmro_dict.keys():
            val = pmro_dict[name]
            std_sum += pow(val - avg, 2)
        std = sqrt(std_sum / count)

        # append stats to dict
        pmro_dict["AVG"] = avg
        pmro_dict["MAX"] = max_value
        pmro_dict["MIN"] = min_value
        pmro_dict["COUNT"] = count
        pmro_dict["STD"] = std

        return pmro_dict

    def change_pmro_state(self, en_svt, en_lvt, en_ulvt, en_interconnect):
        self.en_svt = en_svt
        self.en_lvt = en_lvt
        self.en_ulvt = en_ulvt
        self.en_interconnect = en_interconnect
        time.sleep(0.01)

    def set_pmro_spec(self):
        pmro_spec = {}
        pmro_spec["FAST_BEST"] = [8.86, 7.7, 5.77, 5, 2.56, 29.89]
        pmro_spec["TYPE_BEST"] = [10.92, 9.22, 6.58, 5.73, 3.3, 35.75]
        pmro_spec["SLOW_BEST"] = [13.81, 11.28, 7.63, 6.72, 4.31, 43.75]
        pmro_spec["FAST_WORST"] = [10.65, 9.22, 6.89, 6.14, 3.72, 36.62]
        pmro_spec["TYP_WORST"] = [13.2, 11.1, 7.9, 7.07, 4.66, 43.93]
        pmro_spec["SLOW_WORST"] = [16.78, 13.65, 9.2, 8.33, 5.94, 53.9]
        pmro_spec["FAST_TYP"] = [9.7, 8.41, 6.28, 5.47, 3.04, 32.9]
        pmro_spec["TYP_TYP"] = [12, 10.11, 7.19, 6.29, 3.87, 39.46]
        pmro_spec["SLOW_TYP"] = [15.24, 12.41, 8.37, 7.41, 5.01, 48.44]
        self.pmro_spec = pmro_spec

    def print_pmro_timers(self, force_read=False):
        pmro_dict = self.get_pmro_with_stats(force_read)
        # pmro_blocks_vals = self.get_pmro_all_blocks(force_read)
        n = pmro_dict["COUNT"]
        avg = pmro_dict["AVG"]
        min_val = pmro_dict["MIN"]
        max_val = pmro_dict["MAX"]

        print("n = %0d, avg = %f, max = %0d, min = %0d, pmro_cnt_normalized_to_50mhz_ref = %f" % (
            n, avg, max_val, min_val, avg * 6))

    def pmro_test_all_case(self):
        """
        testing all pmro cases

        :return:
        """
        # all on
        pmro_cases = {}
        self.change_pmro_state(en_svt=0, en_lvt=1, en_ulvt=1, en_interconnect=1)
        pmro_cases["SVT_OFF"] = self.get_pmro_time()
        self.change_pmro_state(en_svt=1, en_lvt=0, en_ulvt=1, en_interconnect=1)
        pmro_cases["LVT_OFF"] = self.get_pmro_time()
        self.change_pmro_state(en_svt=1, en_lvt=1, en_ulvt=0, en_interconnect=1)
        pmro_cases["ULVT_OFF"] = self.get_pmro_time()
        self.change_pmro_state(en_svt=1, en_lvt=1, en_ulvt=1, en_interconnect=0)
        pmro_cases["INTERCONNECT_OFF"] = self.get_pmro_time()
        self.change_pmro_state(en_svt=1, en_lvt=1, en_ulvt=1, en_interconnect=1)
        pmro_cases["ALL_EN"] = self.get_pmro_time()
        overhead = 0
        for case in pmro_cases:
            if case == "ALL_EN":
                continue
            else:
                time_per_case = pmro_cases["ALL_EN"]["TOTAL_TIME"] - pmro_cases[case]["TOTAL_TIME"]
                pmro_cases[case]["TIME"] = time_per_case
                overhead += time_per_case
        pmro_cases["ALL_EN"]["TIME"] = pmro_cases["ALL_EN"]["TOTAL_TIME"] - overhead

        return pmro_cases

    def match_pmro_case(self):
        # instead of pmro log
        pmro_dict = self.pmro_test_all_case()
        # pmro_dict = self.log_pmro()
        pmro_spec = self.pmro_spec

        pmro_measured = {}
        pmro_match = {}
        pmro_measured["SVT"] = pmro_dict["SVT_OFF"]["TIME"]
        pmro_measured["LVT"] = pmro_dict["LVT_OFF"]["TIME"]
        pmro_measured["ULVT"] = pmro_dict["ULVT_OFF"]["TIME"]
        pmro_measured["WIRE"] = pmro_dict["INTERCONNECT_OFF"]["TIME"]
        pmro_measured["OVERHEAD"] = pmro_dict["ALL_EN"]["TIME"]
        pmro_measured["TOTAL"] = pmro_dict["ALL_EN"]["TOTAL_TIME"]

        for process_case in pmro_spec:
            dict_per_type = {}
            sum_of_abs = 0
            for transistor_type, spec_val in zip(pmro_measured, pmro_spec[process_case]):
                val = spec_val - pmro_measured[transistor_type]
                dict_per_type[transistor_type] = val
                sum_of_abs += abs(val)
            pmro_match[process_case] = dict_per_type
            pmro_match[process_case]["SUM"] = sum_of_abs

        best_match_val = 1e3  # big number
        best_match = None
        for process_case in pmro_match:
            if best_match_val > pmro_match[process_case]["SUM"]:
                best_match_val = pmro_match[process_case]["SUM"]
                best_match = process_case
        print(best_match)
        self.matched_pmro = best_match

        pmro_measured["SUM"] = ""
        pmro_match["MEASURED"] = pmro_measured

        return pmro_match

    def log_pmro(self, out_file=None):
        """
        saving all values of pmro to file

        :return:
        """
        if out_file is None:
            out_file = self.out_file
        out_str = ","
        pmro_dict = self.pmro_test_all_case()
        for first in pmro_dict["ALL_EN"]:
            out_str += "{},".format(first)
        out_file.write(out_str + "\n")

        for state in pmro_dict:
            out_str = "{},".format(state)
            for field in pmro_dict[state]:
                out_str += "{},".format(pmro_dict[state][field])
            out_file.write(out_str + "\n")
        return pmro_dict

    def log_best_match_pmro(self, out_file=None):

        if out_file is None:
            out_file = self.out_file

        pmro_match = self.match_pmro_case()

        # appending in order to write

        # create header
        out_str = ","
        for title in pmro_match['FAST_BEST']:
            out_str += "{},".format(title)
        out_file.write(out_str + "\n")

        # writing all match case to file
        for process_case in pmro_match:
            out_str = "{},".format(process_case)
            for value in pmro_match[process_case]:
                out_str += "{},".format(pmro_match[process_case][value])
            out_file.write(out_str + "\n")

    def log_best_match_pmro_spec(self, out_file=None):

        if out_file is None:
            out_file = self.out_file

        pmro_match = self.match_pmro_case()
        pmro_spec = self.pmro_spec
        # appending in order to write

        # create header
        out_str = ","
        for title in pmro_match['FAST_BEST']:
            out_str += "{}[ns],".format(title)
        out_file.write(out_str + "\n")

        # writing spec to file
        for process_case in pmro_spec:
            out_str = "{},".format(process_case)
            for value in pmro_spec[process_case]:
                out_str += "{},".format(value)
            out_file.write(out_str + "\n")

        # writing all match case to file
        out_str = "MEASURED,"
        for value in pmro_match["MEASURED"]:
            out_str += "{},".format(pmro_match["MEASURED"][value])
        out_str += "{},".format(self.matched_pmro)
        out_file.write(out_str + "\n")

    def log_measured_match_pmro(self, out_file=None):
        if out_file is None:
            out_file = self.out_file

        pmro_match = self.match_pmro_case()
        # writing all match case to file
        out_str = "MEASURED,"
        for value in pmro_match["MEASURED"]:
            out_str += "{},".format(pmro_match["MEASURED"][value])
        out_str += "{},".format(self.matched_pmro)
        out_file.write(out_str + "\n")

#############
# per block
#############
    def get_pmro_time_per_block(self):
        pmro_dict = self.get_pmro_all_blocks(True)
        # converting the value of the counter to a value in seconds
        pmro_time_per_block = {}
        for block, block_pmro_count in pmro_dict.items():
            block_time = 500 / (block_pmro_count * 6 * 50 / 4096)
            pmro_time_per_block[block] = block_time

        return pmro_time_per_block

    def pmro_test_all_case_per_block(self):
        """
        testing all pmro cases

        :return:
        """
        # all on
        pmro_cases = {}
        self.change_pmro_state(en_svt=0, en_lvt=1, en_ulvt=1, en_interconnect=1)
        pmro_cases["SVT_OFF"] = self.get_pmro_time_per_block()
        self.change_pmro_state(en_svt=1, en_lvt=0, en_ulvt=1, en_interconnect=1)
        pmro_cases["LVT_OFF"] = self.get_pmro_time_per_block()
        self.change_pmro_state(en_svt=1, en_lvt=1, en_ulvt=0, en_interconnect=1)
        pmro_cases["ULVT_OFF"] = self.get_pmro_time_per_block()
        self.change_pmro_state(en_svt=1, en_lvt=1, en_ulvt=1, en_interconnect=0)
        pmro_cases["INTERCONNECT_OFF"] = self.get_pmro_time_per_block()
        self.change_pmro_state(en_svt=1, en_lvt=1, en_ulvt=1, en_interconnect=1)
        pmro_cases["ALL_EN"] = self.get_pmro_time_per_block()

        pmro_times = {
            "OVERHEAD": {},
            "SVT_OFF": {},
            "LVT_OFF": {},
            "ULVT_OFF": {},
            "INTERCONNECT_OFF": {},
            "ALL_EN": {},
        }
        for block in pmro_cases["ALL_EN"]:
            pmro_times["OVERHEAD"][block] = 0

        # FIXME
        #
        #         time_per_case = pmro_cases["ALL_EN"]["TOTAL_TIME"] - pmro_cases[case]["TOTAL_TIME"]
        #         pmro_cases[case]["TIME"] = time_per_case
        #         overhead += time_per_case
        # pmro_cases["ALL_EN"]["TIME"] = pmro_cases["ALL_EN"]["TOTAL_TIME"] - overhead

        for case in pmro_cases:
            if case == "ALL_EN" or case == "OVERHEAD":
                continue
            else:
                for block in pmro_cases[case]:
                    block_time_per_case = pmro_cases["ALL_EN"][block] - pmro_cases[case][block]
                    pmro_times[case][block] = block_time_per_case
                    pmro_times["OVERHEAD"][block] += block_time_per_case

        for block in pmro_cases["ALL_EN"]:
            pmro_times["ALL_EN"][block] = pmro_cases["ALL_EN"][block] - pmro_times["OVERHEAD"][block]

        return pmro_times

    def pmro_test_all_case_per_block(self):
        """
        testing all pmro cases

        :return:
        """
        # all on
        pmro_cases = {}
        self.change_pmro_state(en_svt=0, en_lvt=1, en_ulvt=1, en_interconnect=1)
        pmro_cases["SVT_OFF"] = self.get_pmro_time_per_block()
        self.change_pmro_state(en_svt=1, en_lvt=0, en_ulvt=1, en_interconnect=1)
        pmro_cases["LVT_OFF"] = self.get_pmro_time_per_block()
        self.change_pmro_state(en_svt=1, en_lvt=1, en_ulvt=0, en_interconnect=1)
        pmro_cases["ULVT_OFF"] = self.get_pmro_time_per_block()
        self.change_pmro_state(en_svt=1, en_lvt=1, en_ulvt=1, en_interconnect=0)
        pmro_cases["INTERCONNECT_OFF"] = self.get_pmro_time_per_block()
        self.change_pmro_state(en_svt=1, en_lvt=1, en_ulvt=1, en_interconnect=1)
        pmro_cases["ALL_EN"] = self.get_pmro_time_per_block()

        pmro_times = {
            "OVERHEAD": {},
            "SVT_OFF": {},
            "LVT_OFF": {},
            "ULVT_OFF": {},
            "INTERCONNECT_OFF": {},
            "ALL_EN": {},
        }
        for block in pmro_cases["ALL_EN"]:
            pmro_times["OVERHEAD"][block] = 0

        # FIXME
        #
        #         time_per_case = pmro_cases["ALL_EN"]["TOTAL_TIME"] - pmro_cases[case]["TOTAL_TIME"]
        #         pmro_cases[case]["TIME"] = time_per_case
        #         overhead += time_per_case
        # pmro_cases["ALL_EN"]["TIME"] = pmro_cases["ALL_EN"]["TOTAL_TIME"] - overhead

        for case in pmro_cases:
            if case == "ALL_EN" or case == "OVERHEAD":
                continue
            else:
                for block in pmro_cases[case]:
                    block_time_per_case = pmro_cases["ALL_EN"][block] - pmro_cases[case][block]
                    pmro_times[case][block] = block_time_per_case
                    pmro_times["OVERHEAD"][block] += block_time_per_case

        for block in pmro_cases["ALL_EN"]:
            pmro_times["ALL_EN"][block] = pmro_cases["ALL_EN"][block] - pmro_times["OVERHEAD"][block]

        return pmro_times

    def pmro_test_all_count_per_block(self):
        """
        testing all pmro cases

        :return:
        """
        # all on
        pmro_cases = {}
        self.change_pmro_state(en_svt=0, en_lvt=1, en_ulvt=1, en_interconnect=1)
        pmro_cases["SVT_OFF"] = self.get_pmro_all_blocks()
        self.change_pmro_state(en_svt=1, en_lvt=0, en_ulvt=1, en_interconnect=1)
        pmro_cases["LVT_OFF"] = self.get_pmro_all_blocks()
        self.change_pmro_state(en_svt=1, en_lvt=1, en_ulvt=0, en_interconnect=1)
        pmro_cases["ULVT_OFF"] = self.get_pmro_all_blocks()
        self.change_pmro_state(en_svt=1, en_lvt=1, en_ulvt=1, en_interconnect=0)
        pmro_cases["INTERCONNECT_OFF"] = self.get_pmro_all_blocks()
        self.change_pmro_state(en_svt=1, en_lvt=1, en_ulvt=1, en_interconnect=1)
        pmro_cases["ALL_EN"] = self.get_pmro_all_blocks()

        pmro_times = {
            "OVERHEAD": {},
            "SVT_OFF": {},
            "LVT_OFF": {},
            "ULVT_OFF": {},
            "INTERCONNECT_OFF": {},
            "ALL_EN": {},
        }
        for block in pmro_cases["ALL_EN"]:
            pmro_times["OVERHEAD"][block] = 0

        # FIXME
        #
        #         time_per_case = pmro_cases["ALL_EN"]["TOTAL_TIME"] - pmro_cases[case]["TOTAL_TIME"]
        #         pmro_cases[case]["TIME"] = time_per_case
        #         overhead += time_per_case
        # pmro_cases["ALL_EN"]["TIME"] = pmro_cases["ALL_EN"]["TOTAL_TIME"] - overhead

        for case in pmro_cases:
            if case == "ALL_EN" or case == "OVERHEAD":
                continue
            else:
                for block in pmro_cases[case]:
                    block_time_per_case = pmro_cases["ALL_EN"][block] - pmro_cases[case][block]
                    pmro_times[case][block] = block_time_per_case
                    pmro_times["OVERHEAD"][block] += block_time_per_case

        for block in pmro_cases["ALL_EN"]:
            pmro_times["ALL_EN"][block] = pmro_cases["ALL_EN"][block] - pmro_times["OVERHEAD"][block]

        return pmro_times

    def match_pmro_case_per_block(self):
        # instead of pmro log
        pmro_dict = self.pmro_test_all_case_per_block()
        pmro_spec = self.pmro_spec

        pmro_measured = {}
        pmro_match = {}
        pmro_measured["SVT"] = pmro_dict["SVT_OFF"]["TIME"]
        pmro_measured["LVT"] = pmro_dict["LVT_OFF"]["TIME"]
        pmro_measured["ULVT"] = pmro_dict["ULVT_OFF"]["TIME"]
        pmro_measured["WIRE"] = pmro_dict["INTERCONNECT_OFF"]["TIME"]
        pmro_measured["OVERHEAD"] = pmro_dict["ALL_EN"]["TIME"]
        pmro_measured["TOTAL"] = pmro_dict["ALL_EN"]["TOTAL_TIME"]

        for process_case in pmro_spec:
            dict_per_type = {}
            sum_of_abs = 0
            for transistor_type, spec_val in zip(pmro_measured, pmro_spec[process_case]):
                val = spec_val - pmro_measured[transistor_type]
                dict_per_type[transistor_type] = val
                sum_of_abs += abs(val)
            pmro_match[process_case] = dict_per_type
            pmro_match[process_case]["SUM"] = sum_of_abs

        best_match_val = 1e3  # big number
        best_match = None
        for process_case in pmro_match:
            if best_match_val > pmro_match[process_case]["SUM"]:
                best_match_val = pmro_match[process_case]["SUM"]
                best_match = process_case
        print(best_match)

        pmro_measured["SUM"] = ""
        pmro_match["MEASURED"] = pmro_measured

        return pmro_match
