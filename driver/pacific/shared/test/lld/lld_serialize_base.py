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

import unittest
import lldcli
import sys
import os
import lld_utils
import time
try:
    import test_nsim_providercli as nsim
except BaseException:
    import test_packet_provider as nsim
from leaba import sdk
import importlib


class lld_serialize_base(unittest.TestCase):

    # some random registers with non-default values
    # dict of reg_name => new_value
    registers = {
        "slice[0].ifg[0].sch.soft_reset_configuration": 0x1,
        "counters.bank_6k[3].bank_config[0]": 0x402800,
        "slice[1].ifg[0].mac_pool8[0].rx_krf_cfg[3]": 0x100,
        "dics.acc_crdt_req_th_reg": 0x2EE0A1F403A0,
        "slice[3].pdoq.top.ifse_pir_shaper_max_bucket_configuration[28]": 0x7,
        "slice[5].pdoq.top.ifse_pir_shaper_configuration[13]": 0xA2,
        "pdvoq.empd[0].emdb_per_bank_reg[1]": 0x0,
        "cdb.top.cem_group_map_table[44]": 0xA,
        "fdll[5].emdb_per_bank_reg[5]": 0x0,
        "nw_reorder.slb_block_configuration[1]": 0x7A6,
        "mmu_buff.soft_reset_configuration": 0x1,
        "csms.rlb_mc_cg_msg_reg": 0x401,
        "dvoq.counter_timer": 0x77359400,
        "pdvoq_shared_mma.cgm_counter_uc_hist_cfg": 0x1,
    }

    # some random memories with non-default values
    # dict of mem_name => (entry_num, new_value)
    memories = {
        "slice[0].pdvoq.buffers_consumption_lut_for_enq": (19, 0xffffff),
        "csms.voq_dst_map_mem[0]": (1032, 0x1),
        "dics.aged_out_queue": (26, 0x1),
        "reassembly.source_port_map_table[0]": (33, 0x1),
        "rx_cgm.profile_map_table[0]": (79, 0x1),
        "rx_counters.bank_config[5]": (25, 0x1),
        "ts_mon.source_link_map[5]": (7, 0x1),
        "slice[5].npu.rxpp_term.npe[2].traps_tcam": (128, 0x1),
        "rx_meter.top.stat_meter_decision_mapping_table[5]": (249, 0x1),
        "npuh.npe.shared_table6": (397, 0x1),
    }

    def setUp(self, create_simulator=False):
        self.device_id = 0
        self.device_path = os.getenv('SDK_DEVICE_NAME')
        if not self.device_path:
            if create_simulator:
                self.nsim_provider = nsim.create_and_run_simulator_server(None, 0, "/dev/testdev")
                if self.nsim_provider is None:
                    self.logger.error("Failed to start nsim")
                    sys.exit(1)

                self.nsim = self.nsim_provider  # do we still need this?

                self.device_path = self.nsim_provider.get_connection_handle()
            else:
                self.device_path = "/dev/testdev"

        self.ll_device = lldcli.ll_device_create(self.device_id, self.device_path)

        if '/socket/' in self.device_path:
            self.connect_to_simulator()

        self.ll_device.reset()
        self.ll_device.reset_access_engines()

        self.timestamp = time.time()

        self.pre_serial_state_file = None
        self.serial_file = None
        self.post_serial_state_file = None

    def tearDown(self):
        self.ll_device = None

        # cleanup tmp files
        if self.pre_serial_state_file and os.path.exists(self.pre_serial_state_file):
            os.remove(self.pre_serial_state_file)
        if self.serial_file and os.path.exists(self.serial_file):
            os.remove(self.serial_file)
        if self.post_serial_state_file and os.path.exists(self.post_serial_state_file):
            os.remove(self.post_serial_state_file)

    def connect_to_simulator(self):
        socket_addr, port = self.device_path.split('/socket/')[-1].split(':')
        simulator = nsim.create_nsim_simulator(socket_addr, int(port), sdk.la_get_version_string())
        self.ll_device.set_device_simulator(simulator, lldcli.ll_device.simulation_mode_e_LBR)

    def write_registers_and_verify(self, ll_device, device_tree):
        for reg_name, new_val in self.registers.items():
            reg = eval("device_tree.{}".format(reg_name))
            mask = lld_utils.bitmask_ones(reg.get_desc().width_in_bits)
            ll_device.write_register(reg, new_val & mask)
            val = ll_device.read_register(reg)
            self.assertEqual(val & mask, new_val & mask)

    def read_registers_and_verify(self, ll_device, device_tree):
        for reg_name, exp_val in self.registers.items():
            reg = eval("device_tree.{}".format(reg_name))
            mask = lld_utils.bitmask_ones(reg.get_desc().width_in_bits)
            val = ll_device.read_register(reg)
            self.assertEqual(val & mask, exp_val & mask)

    def write_memories_and_verify(self, ll_device, device_tree):
        for mem_name, (idx, new_val) in self.memories.items():
            mem = eval("device_tree.{}".format(mem_name))
            mask = lld_utils.bitmask_ones(mem.get_desc().width_bits)
            ll_device.write_memory(mem, idx, new_val & mask)
            val = ll_device.read_memory(mem, idx)
            self.assertEqual(val & mask, new_val & mask)

    def read_memories_and_verify(self, ll_device, device_tree):
        for mem_name, (idx, exp_val) in self.memories.items():
            mem = eval("device_tree.{}".format(mem_name))
            mask = lld_utils.bitmask_ones(mem.get_desc().width_bits)
            val = ll_device.read_memory(mem, idx)
            self.assertEqual(val & mask, exp_val & mask)
