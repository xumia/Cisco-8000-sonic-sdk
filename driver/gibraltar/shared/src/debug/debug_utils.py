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

import json
import sys
import os.path
import types
import re
from leaba import sdk
import test_hldcli as sdk_debug
import hw_tablescli as hw_tables
import terminaltables
import lldcli
import math
import ipaddress
import nplapicli
import copy
import itertools
from bit_utils import get_bits
from collections import namedtuple
import test_racli
import csv


def print_npl_struct(obj, prefix=""):
    if '__swig_getmethods__' not in dir(obj):
        if not isinstance(obj, int):
            print("-E- Illegal object ", obj, " in ", prefix)
            return

        if obj != 0:
            print(prefix, obj)
        return

    for field in obj.__swig_getmethods__:
        field_obj = obj.__getattribute__(field)
        print_npl_struct(field_obj, prefix + "." + field)


def get_device_revision_info(la_device):
    ll_device = la_device.get_ll_device()

    if ll_device.is_pacific():
        device_tree = ll_device.get_pacific_tree()
        json_file = os.path.join(os.environ['BASE_OUTPUT_DIR'], 'res', 'pacific_tree.json')
        device_name_major = 'pacific'
    elif ll_device.is_gibraltar():
        device_tree = ll_device.get_gibraltar_tree()
        json_file = os.path.join(os.environ['BASE_OUTPUT_DIR'], 'res', 'gibraltar_tree.json')
        device_name_major = 'gibraltar'
    elif ll_device.is_asic3():
        device_tree = ll_device.get_asic3_tree()
        json_file = os.path.join(os.environ['BASE_OUTPUT_DIR'], 'res', 'asic3_tree.json')
        device_name_major = 'asic3'
    elif ll_device.is_asic4():
        device_tree = ll_device.get_asic4_tree()
        json_file = os.path.join(os.environ['BASE_OUTPUT_DIR'], 'res', 'asic4_tree.json')
        device_name_major = 'asic4'
    elif ll_device.is_asic5():
        device_tree = ll_device.get_asic5_tree()
        json_file = os.path.join(os.environ['BASE_OUTPUT_DIR'], 'res', 'asic5_tree.json')
        device_name_major = 'asic5'
    else:
        raise Exception('Unknown device revision')

    revision = ll_device.get_device_revision()

    return {'revision': revision,
            'device_tree': device_tree,
            'json_file': json_file,
            'device_name_major': device_name_major}


class debug_device():

    RED = "\033[1;31m"
    END = "\033[0;0m"

    def __init__(self, la_device):

        self.la_device = la_device
        self.ll_device = self.la_device.get_ll_device()

        device_info = get_device_revision_info(self.la_device)
        self.device_revision = device_info['revision']
        self.device_tree = device_info['device_tree']
        self.device_name_major = device_info['device_name_major']

        json_file = device_info['json_file']
        if os.path.isfile(json_file) == False:
            exception_message = 'LBR resource file %s does not exist.' % json_file
            raise Exception(exception_message)

        with open(json_file, 'r', errors='replace') as fd:
            json_str = fd.read()
            # in case the JSON parsing fails, add a custom message to the raised exception
            try:
                self.parsed_data = json.loads(json_str)
            except Exception as inst:
                new_msg = "Failed to parse '{0}' as a JSON file after translation".format(json_file)
                reraise(inst, new_msg)

    def print_traps(self):
        tables = self.la_device.get_device_tables()
        redirect_table = tables.redirect_table[0]

        for l, k, m, v in redirect_table.entries(0):
            prefix = "redirect_table[%d]\t redirect_code=0x%x\t key=trap" % (l, v.payloads.redirect_code.val)
            print_npl_struct(k, prefix=prefix)

    def _set_attr(self, struct, name, value):
        for field in self.parsed_data[struct.__class_name__]['fields']:
            if (name == field[0]):
                if (value >= (1 << field[2])):
                    raise TypeError('Value inserted is out of range')
                else:
                    return object.__setattr__(struct, name, value)

        raise TypeError('Cannot set name %r on object of type %s' % (
            name, self.__class__.__name__))

    def create_register(self, reg):
        class_name = self.get_name(reg)
        return self._create_struct(class_name)

    def _create_struct(self, name):
        attributes = {}
        attributes["__class_name__"] = name
        attributes["__repr__"] = lambda struct: self.print(struct)
        attributes["__setattr__"] = lambda struct, name, value: self._set_attr(struct, name, value)
        for field in self.parsed_data[name]['fields']:
            attributes[field[0]] = 0

        class_name = name + "_class"
        class_name = type(class_name, (), attributes)
        ret = class_name()
        return ret

    def get_name(self, reg):
        name = reg.get_desc().name.lower()

        keys = ['lld_register_', 'lld_memory_']
        for key in keys:
            if name.startswith(key):
                name = name.replace(key, '', 1)

        return name

    def _read_bits(self, lsb, length, value):
        ret = value >> lsb
        mask = (1 << length) - 1
        return ret & mask

    def _write_bits(self, offset, length, value):
        ret = value << offset
        mask = (1 << (offset + length)) - 1
        return ret & mask

    def pack(self, struct):
        bv = 0
        class_name = struct.__class_name__
        for field in self.parsed_data[class_name]['fields']:
            (name, lsb, length) = field
            field_data = getattr(struct, name)
            bv |= self._write_bits(lsb, length, field_data)

        return bv

    def print(self, struct):
        str = ""
        class_name = struct.__class_name__
        for field in self.parsed_data[class_name]['fields']:
            (name, lsb, length) = field
            field_data = getattr(struct, name)
            str += "%s [%d:%d] = {0:#0{1}x}\n".format(field_data, 3 + int(length / 4)) % (name, lsb + length - 1, lsb)

        return str

    def unpack(self, value, class_name):
        ret = self._create_struct(class_name)
        for field in self.parsed_data[class_name]['fields']:
            (name, lsb, length) = field
            setattr(ret, name, self._read_bits(lsb, length, value))

        return ret

    def read_register(self, reg):
        class_name = self.get_name(reg)
        return self.__wrap_lld_api(self.ll_device.read_register(reg), class_name)

    def write_register(self, reg, value):
        if (value.__class__ != int):
            value = self.pack(value)

        return self.ll_device.write_register(reg, value)

    def read_memory(self, mem, index):
        class_name = self.get_name(mem)
        return self.__wrap_lld_api(self.ll_device.read_memory(mem, index), class_name)

    def write_memory(self, mem, index, value):
        if (value.__class__ != int):
            value = self.pack(value)

        return self.ll_device.write_memory(mem, index, value)

    def dump_path(self, tree_path, dump_filename=None):
        if dump_filename is not None:
            dumpfd = open(dump_filename, 'a')
        else:
            dumpfd = sys.stdout

        self.__recurse_path(dumpfd, tree_path)

        if dump_filename is not None:
            dumpfd.close()

    def __recurse_path(self, dumpfd, tree_path):
        # All blocks have 'get_block_id'. Leaf blocks implement 'initialize' in
        # their derived hierarchy where 'intermediate' blocks has only its common
        # impl.
        is_leaf_block = ('get_block_id' in dir(tree_path)) and (tree_path.initialize.__qualname__ != 'lld_block.initialize')
        if is_leaf_block:
            self.__iterate_blocks(dumpfd, tree_path)
            return

        is_array = '__getitem__' in dir(tree_path)
        if is_array:
            for path_arr_member in tree_path:
                self.__explore_path_node(dumpfd, path_arr_member)
        else:
            self.__explore_path_node(dumpfd, tree_path)

    def __iterate_blocks(self, dumpfd, blocks):
        is_array = '__getitem__' in dir(blocks)
        if is_array:
            for block in blocks:
                self.__dump_block(dumpfd, block)
        else:
            self.__dump_block(dumpfd, blocks)

    def __dump_block(self, dumpfd, block):
        is_valid = block.is_valid()
        if not is_valid:
            return

        prefix = '%s_tree' % self.device_name_major

        for reg in block.get_registers():
            value = self.ll_device.read_register(reg)
            reg_name = reg.get_name()
            print('ll_device.write_register({0}.{1}, 0x{2:X})'.format(prefix, reg_name, value), file=dumpfd)

        for mem in block.get_memories():
            mem_desc = mem.get_desc()
            if not mem_desc.readable:
                continue

            if mem_desc.is_volatile():
                continue

            entries = mem.get_desc().entries
            mem_name = mem.get_name()

            for entry_num in range(entries):
                value = self.ll_device.read_memory(mem, entry_num)
                print("ll_device.write_memory({0}.{1}, {2:3}, 0x{3:X}) ".format(prefix, mem_name, entry_num, value), file=dumpfd)

    def __explore_path_node(self, dumpfd, path_node):
        node_leafs = [attr for attr in dir(path_node) if not callable(getattr(path_node, attr)) and
                      not attr.startswith("__") and not isinstance(getattr(path_node, attr), int)]

        for leaf_name in node_leafs:
            leaf = path_node.__getattribute__(leaf_name)
            self.__recurse_path(dumpfd, leaf)

    def read_dvoq_qsm(self):
        for addr in range(4096):
            rd_data = self.ll_device.read_memory(self.device_tree.dvoq.qsm, addr)[1]

            if (rd_data & 0x7FFFF) > 0:
                print('context {}: size {}, bytes {}'.format(addr, rd_data & 0x7FFFF, (rd_data >> 19) & 0x3FFFFFFF))

    def __wrap_lld_api(self, read_value, class_name):
        return_status = False
        if (lldcli.get_error_mode() == sdk.error_mode_e_CODE):
            return_status = True
            if (read_value[0] != 0):
                raise Exception('read_register/memory failed with status %d' % (read_value[0]))
            read_value = read_value[1]

        ret = self.unpack(read_value, class_name)
        if return_status:
            ret = [0, ret]

        return ret

    # TODO debug_device doesn't look like the correct place for this method
    def cem_age_table_dump(self, execute=False, raw=False):
        if self.device_revision == sdk.la_device_revision_e_GIBRALTAR_A1 and execute is False:
            print(
                debug_device.RED +
                "CAUTION: THIS CLI IS KNOWN TO CORRUPT CEM AGE TABLE IN GB A1, PLEASE MAKE SURE NO TRAFFIC IS FLOWING" +
                debug_device.END)
            return

        len_dist = {}
        cnt = [0] * 16
        # Age table layout:
        # 8k x 112 age entries (4b per entry)
        # Total entry size: (28 * 2048) * 16 + 512 = 918016
        # Entry index formula:
        #   line index = core index * entry index * 28 / 112
        age_table = self.device_tree.cdb.top.cem_age_table
        for i in range(age_table.get_desc().entries):
            line = self.read_memory(age_table, i)
            width_bits = age_table.get_desc().width_bits
            assert(width_bits % 8 == 0)
            width_bytes = width_bits // 8
            line_bytes = line.age.to_bytes(width_bytes, byteorder='big')
            if raw is True:
                print('[%04d] %s' % (i, line))
            # each byte has 2 4-bit fields
            for j in range(len(line_bytes)):
                tmp_byte = line_bytes[j]
                # process 8-bit field
                upper = (tmp_byte & 0xF0) >> 4
                lower = (tmp_byte & 0x0F)
                cnt[upper] += 1
                cnt[lower] += 1

        for i in range(16):
            print("age value: 0x%x, %6d entries" % (i, cnt[i]))


def debug_on(device_id):
    sdk.la_set_logging_level(288, sdk.la_logger_level_e_DEBUG)  # no device
    sdk.la_set_logging_level(device_id, sdk.la_logger_level_e_DEBUG)
    sdk.la_set_logging_file('./sdk_debug_log.txt')


def debug_off(device_id):
    sdk.la_set_logging_level(288, sdk.la_logger_level_e_INFO)  # no device
    sdk.la_set_logging_level(device_id, sdk.la_logger_level_e_INFO)
    sdk.la_set_logging_file(None)

# @brief Class to retrieve CDB ARC usage counters.
#
# * Debug counters
# * Switch limit counters
# * AC port limit counters
# * CDB core utilization
# * EM group utilization


class arc_counters:

    GROUP_NUM = 256
    CORE_NUM = 16
    LIMIT_COUNTER_NUM = 1 << 12

    COUNTER_WIDTH = 1 << 20
    LIMIT_COUNTER_INIT_VAL = 0x7ffff

    CPU_ARC_CMD_REG = 36

    ARC_DBG_SIGNATURE = 0x4442475f
    ARC_DBG_BLOCK_READ_SIZE = 128

    # NOTE:
    # Make sure it's synced to arc_debug_counters in arc_cpu_common.h
    DEBUG_COUNTERS = [
        "main_loop",
        "cpu_command",
        "response_to_cpu",
        "learn_new_events",
        "learn_update_events",
        "learn_refresh_events",
        "learn_new",
        "simple_insert",
        "cpu_simple_insert",
        "double_insert",
        "cpu_double_insert",
        "relocate",
        "relocate_for_double",
        "relocate_double_entries",
        "cam_insert",
        "cpu_erase",
        "cpu_erase_not_found",
        "new_insert_fail",
        "update_lookup_fail",
        "update_conflicts",
        "poll_timeout",
        "read_request",
        "static_MAC",
        "dynamic_MAC",
        "age_sweep",
        "age_configs",
        "age_interval",
        "aged_entries",
        "age_ecc_error",
        "age_read_retry",
        "age_read_mismatches",
        "age_write_mismatches",
        "age_static_mismatches",
        "age_dynamic_mismatches",
        "age_value_mismatches",
        "age_check_invalid_entries",
        "age_check_failures",
        "update_limit_exceeds",
        "limit_counter_underflow",
        "occupancy_ctr_underflow",
        "cpu_lookups",
        "cpu_lookups_location",
        "cpu_lookup_not_found",
        "cpu_entry_overwrite",
        "cpu_read_not_found",
        "double_relocation_EM_FFE",
        "double_relocation_EM_READ",
        "double_relocation_EM_READ_fails",
        "double_relocation_EM_STORE",
        "double_relocation_EM_STORE_fails",
        "double_insert_EM_FFE",
        "double_insert_EM_READ",
        "double_insert_EM_READ_fails",
        "double_insert_single_relocation_fails",
        "double_relocation_parent-node_backwalks",
        "double_relocation_BST_loops_detected",
        "total_evacuation_tries",
        "set_feature_fails",
        "em_lookup_fail",
        "em_write_fail",
        "em_ffe_fail",
        "em_read_fail",
        "em_pop_fail",
        "em_delete_fail",
        "em_age_write_fail",
        "em_age_read_fail",
        "em_quick_insert_fail",
    ]

    def __init__(self, device):
        self.device = device
        self.ll_device = device.get_ll_device()

        device_info = get_device_revision_info(self.device)
        self.tree = device_info['device_tree']
        self.device_name_major = device_info['device_name_major']

        self.counters_mem = self.tree.cdb.top.counters
        self.cem = hw_tables.cem(self.ll_device)
        for counter in arc_counters.DEBUG_COUNTERS:
            setattr(self, 'dbg_' + counter, 0)
        # populate debug counters
        self.get_debug_counters()

    def find_debug_counters_start(self):
        # identify start of debug counters
        # read in a block of DCCM and process the data within
        _block = self.read_dccm(0, self.ARC_DBG_BLOCK_READ_SIZE)
        _loc = 0
        for elem in _block:
            if elem == self.ARC_DBG_SIGNATURE:
                break
            _loc += 1
        if _loc == len(_block):
            print("[ERROR] failed to locate start of ARC debug counters")
            return (-1, [])
        return (_loc, _block)

    def get_debug_counters(self):
        # identify start of debug counters
        # read in a block of DCCM and process the data within
        (_loc, _block) = self.find_debug_counters_start()
        if _loc == -1:
            return

        # populate counters with the adjusted offsets
        for idx in range(len(arc_counters.DEBUG_COUNTERS)):
            val = _block[_loc + idx + 1]
            setattr(self, 'dbg_' + arc_counters.DEBUG_COUNTERS[idx], val)

    def report_debug_counters(self):
        self.get_debug_counters()
        debug_counters = {}
        for idx in range(len(arc_counters.DEBUG_COUNTERS)):
            key = 'dbg_' + arc_counters.DEBUG_COUNTERS[idx]
            val = getattr(self, key)
            debug_counters[key] = val

        return debug_counters

    def dump_debug_counters(self):
        self.get_debug_counters()
        for idx in range(len(arc_counters.DEBUG_COUNTERS)):
            key = 'dbg_' + arc_counters.DEBUG_COUNTERS[idx]
            val = getattr(self, key)
            print("%-44s= %d" % (arc_counters.DEBUG_COUNTERS[idx], val))

    def reset_debug_counters(self):
        (_loc, _block) = self.find_debug_counters_start()
        if _loc == -1:
            return

        # halt ARC before accessing DCCM
        self.device.acquire_device_lock(True)
        self.ll_device.write_register(self.tree.cdb.top.arc_control_registers, 0x2)
        for idx in range(len(arc_counters.DEBUG_COUNTERS)):
            self._write_dccm((_loc + idx + 1), 0x0)

        # restart it back
        self.ll_device.write_register(self.tree.cdb.top.arc_control_registers, 0x1)
        self.device.release_device_lock()

    def report_group_counters(self):
        offset = arc_counters.LIMIT_COUNTER_NUM * 2
        return self._report_occupancy_counters(offset, arc_counters.GROUP_NUM)

    def report_core_counters(self):
        offset = arc_counters.LIMIT_COUNTER_NUM * 2 + arc_counters.GROUP_NUM
        return self._report_occupancy_counters(offset, arc_counters.CORE_NUM)

    def report_mac_relay_counters(self):
        return self._report_limit_counters(0)

    def report_ac_port_counters(self):
        return self._report_limit_counters(arc_counters.LIMIT_COUNTER_NUM)

    def read_dccm(self, start_line, count):
        res = []

        # halt ARC before accessing DCCM
        self.device.acquire_device_lock(True)
        self.ll_device.write_register(self.tree.cdb.top.arc_control_registers, 0x2)
        for idx in range(start_line, start_line + count):
            res.append(self._read_dccm(idx))

        # restart it back
        self.ll_device.write_register(self.tree.cdb.top.arc_control_registers, 0x1)
        self.device.release_device_lock()

        return res

    def write_dccm(self, line, val):
        # halt ARC before accessing DCCM
        self.device.acquire_device_lock(True)
        self.ll_device.write_register(self.tree.cdb.top.arc_control_registers, 0x2)
        self._write_dccm(line, val)
        # restart it back
        self.ll_device.write_register(self.tree.cdb.top.arc_control_registers, 0x1)
        self.device.release_device_lock()

    def _read_dccm(self, line):
        # bit[0] - read=0 or write=1
        # bit[1] - dccm=0 or dccm=1
        addr = line << 2
        self.ll_device.write_register(self.tree.cdb.top.arc_mem_regs, addr)
        self.ll_device.write_register(self.tree.cdb.top.arc_mem_start, 1)
        go = 1
        while go == 1:
            go = self.ll_device.read_register(self.tree.cdb.top.arc_mem_start)

        v = self.ll_device.read_register(self.tree.cdb.top.arc_mem_ccm_data)
        return v

    def _write_dccm(self, line, val):
        # bit[0] - read=0 or write=1
        # bit[1] - dccm=0 or dccm=1
        addr = (line << 2) + 1
        self.ll_device.write_register(self.tree.cdb.top.arc_mem_ccm_data, val)
        self.ll_device.write_register(self.tree.cdb.top.arc_mem_regs, addr)
        self.ll_device.write_register(self.tree.cdb.top.arc_mem_start, 1)
        go = 1
        while go == 1:
            go = self.ll_device.read_register(self.tree.cdb.top.arc_mem_start)

    def _report_occupancy_counters(self, offset, num):
        occupancy_counters = {}
        total = 0
        for idx in range(offset, offset + num):
            val = self.ll_device.read_memory(self.counters_mem, idx)
            val %= arc_counters.COUNTER_WIDTH
            total += val
            if val != 0:
                occupancy_counters[idx - offset] = val

        occupancy_counters['total'] = total
        return occupancy_counters

    def _report_limit_counters(self, offset):
        limit_counters = {}
        total = 0
        for idx in range(offset, offset + arc_counters.LIMIT_COUNTER_NUM):
            val = self.ll_device.read_memory(self.counters_mem, idx)
            val %= arc_counters.COUNTER_WIDTH
            if val != arc_counters.LIMIT_COUNTER_INIT_VAL:
                total += (arc_counters.LIMIT_COUNTER_INIT_VAL - val)
                limit_counters[idx - offset] = arc_counters.LIMIT_COUNTER_INIT_VAL - val

        limit_counters['total'] = total
        return limit_counters

# @brief Helper class to retrieve to store, analyze and manipulate CEM row.


class debuggable_report_row:
    KEY_FIELD = ' key'

    def __init__(self, row, key_type, prefix_length, key_length):
        self._row = row
        self._type = key_type
        self._prefix_length = prefix_length
        self._key_length = key_length

    def get_type(self):
        return self._type

    def get_debug_key(self):
        if self._type == 'EMPTY':
            return ''
        int_val = int(self._row[debuggable_report_row.KEY_FIELD], 0)
        report_bin_str = bin(int_val)
        if self._prefix_length > 0:
            # turns the report key that has the form <SUF><ORIG><PREF> to the string to <ORIG>
            orig_key_bin_str = report_bin_str[-self._key_length:-self._prefix_length]
        else:
            orig_key_bin_str = report_bin_str
        if orig_key_bin_str == '0b':
            orig_key_bin_str = '0b0'
        elif orig_key_bin_str == '':
            print(self._type, str(self._row))
            raise RuntimeError
        hex_str = hex(int(orig_key_bin_str, 2))
        return hex_str

    @staticmethod
    def create(row):
        if row[debuggable_report_row.KEY_FIELD] == '' or int(row[debuggable_report_row.KEY_FIELD], 16) == 0:
            return debuggable_report_row(row, 'EMPTY', 0, 0)
        elif debuggable_report_row.ends_with(row[debuggable_report_row.KEY_FIELD], '00'):
            return debuggable_report_row(row, 'IPV4_VRF_DIP', 2, 32)
        elif debuggable_report_row.ends_with(row[debuggable_report_row.KEY_FIELD], '011'):
            return debuggable_report_row(row, 'IPV6_VRF_DIP', 3, 128)
        elif debuggable_report_row.ends_with(row[debuggable_report_row.KEY_FIELD], '01101'):
            return debuggable_report_row(row, 'IPV4_VRF_S_G', 5, 32)
        elif debuggable_report_row.ends_with(row[debuggable_report_row.KEY_FIELD], '111101'):
            return debuggable_report_row(row, 'IPV6_VRF_S_G', 6, 128)
        elif debuggable_report_row.ends_with(row[debuggable_report_row.KEY_FIELD], '00'):
            return debuggable_report_row(row, 'IPV4_VRF_SIP', 2, 32)
        elif debuggable_report_row.ends_with(row[debuggable_report_row.KEY_FIELD], '011'):
            return debuggable_report_row(row, 'IPV6_VRF_SIP', 3, 128)
        elif debuggable_report_row.ends_with(row[debuggable_report_row.KEY_FIELD], '0001'):
            return debuggable_report_row(row, 'MAC', 4, 48)
        else:
            return debuggable_report_row(row, 'UNKNOWN', 0, 0)

    @staticmethod
    def ends_with(key, suffix):
        return bin(int(key, 16)).endswith(suffix)


# @brief Class to retrieve CEM data from device.
class cem_db:

    KEY_WIDTHS = [142, 78, 46]
    DATA_WIDTH = 110

    CAM_IDX = 255
    CAM_KEY_MSB = 205
    CAM_PAYLOAD_MSB = 63
    RED = "\033[1;31m"
    END = "\033[0;0m"

    def __init__(self, device):
        self.device = device
        self.ll_device = device.get_ll_device()

        device_info = get_device_revision_info(self.device)
        self.tree = device_info['device_tree']
        self.device_name_major = device_info['device_name_major']
        self.key_type_dict = {
            bin(nplapicli.NPL_CENTRAL_EM_LDB_BFD_LKUP.real)[2:]: "BFD",
            bin(nplapicli.NPL_CENTRAL_EM_LDB_COMPLEX_RPF.real)[2:]: "RPF",
            bin(nplapicli.NPL_CENTRAL_EM_LDB_IPV4_VRF_DIP.real)[2:]: "IPV4 DIP / SIP",
            bin(nplapicli.NPL_CENTRAL_EM_LDB_IPV4_VRF_S_G.real)[2:]: "IPV4 S,G",
            bin(nplapicli.NPL_CENTRAL_EM_LDB_IPV6_VRF_DIP.real)[2:]: "IPV6 DIP / SIP",
            bin(nplapicli.NPL_CENTRAL_EM_LDB_IPV6_VRF_SIP.real)[2:]: "IPV6 DIP / SIP",
            bin(nplapicli.NPL_CENTRAL_EM_LDB_IPV6_VRF_S_G.real)[2:]: "IPV6 S,G",
            bin(nplapicli.NPL_CENTRAL_EM_LDB_IP_PREFIX_ID.real)[2:]: "IP prefix id",
            bin(nplapicli.NPL_CENTRAL_EM_LDB_LPTS_2ND_LOOKUP.real)[2:]: "LPTS 2nd lookup",
            bin(nplapicli.NPL_CENTRAL_EM_LDB_LP_OVER_LAG.real)[2:]: "LP Over LAG",
            bin(nplapicli.NPL_CENTRAL_EM_LDB_MAC_RELAY_DA.real)[2:]: "L2 Mac",
            bin(nplapicli.NPL_CENTRAL_EM_LDB_MPLS_FWD.real)[2:]: "MPLS Lables",
            bin(nplapicli.NPL_CENTRAL_EM_LDB_PFC_LKUP.real)[2:]: "PFC"
        }
        self.sorted_key_list = sorted(list(self.key_type_dict.keys()), key=lambda x: len(x), reverse=True)

        if self.device_name_major == 'pacific':
            self.NUM_CDB_CORES = 4
            self.NUM_BANKS = 16
            self.init_memories_pacific()
        elif self.device_name_major == 'gibraltar':
            self.NUM_CDB_CORES = 8
            self.NUM_BANKS = 28
            self.init_memories_gibraltar()
        else:
            raise Exception('Unknown device revision')

    def init_memories_pacific(self):
        print('Initializing Pacific memories...')
        # list of 16 CEM cores
        self.core = []
        # list of 16 CAMs (one per core)
        self.cam = []
        # two-dimentional list of 16 cores / NUM_BANKS em_banks each
        self.banks = []

        for idx in range(self.NUM_CDB_CORES):
            for core in [self.tree.cdb.core_reduced[idx], self.tree.cdb.core[idx]]:
                self.banks.append(self._create_banks(core.hash_key_em0, core.srams_group0))
                self.banks.append(self._create_banks(core.hash_key_em1, core.srams_group1))
                self.core.append(core.srams_group0)
                self.core.append(core.srams_group1)
                self.cam.append(core.em_cam[0])
                self.cam.append(core.em_cam[1])

    def init_memories_gibraltar(self):
        # list of 16 CEM cores
        self.core = []
        # list of 16 CAMs (one per core)
        self.cam = []
        # two-dimentional list of 16 cores / NUM_BANKS em_banks each
        self.banks = []

        for idx in range(self.NUM_CDB_CORES):
            for core in [self.tree.cdb.core[idx]]:
                self.banks.append(self._create_banks(core.hash_key_em0, core.srams_group0))
                self.banks.append(self._create_banks(core.hash_key_em1, core.srams_group1))
                self.core.append(core.srams_group0)
                self.core.append(core.srams_group1)
                self.cam.append(core.em_cam[0])
                self.cam.append(core.em_cam[1])

    def _create_banks(self, hash_regs, bank_mems):
        banks = []
        for idx in range(self.NUM_BANKS):
            bank = hw_tables.em_bank(self.ll_device, idx, bank_mems[idx], hash_regs[idx], 0, cem_db.KEY_WIDTHS, cem_db.DATA_WIDTH)
            banks.append(bank)
        return banks

    def _get_entry(self, core_idx, bank_idx, idx):
        e = self.banks[core_idx][bank_idx].get_entry(idx)
        if not e.valid:
            return ("0", "0", "0", 0)

        if e.key_width != cem_db.KEY_WIDTHS[0]:
            # not double entry
            return (hex(e.key.get_value()), hex(e.payload.get_value()), hex(e.encrypted_key.get_value()), e.key_width)

        # double entry
        if bank_idx % 2 == 1:
            return ("0", "0", hex(e.encrypted_key.get_value()), e.key_width)

        # double entry is stored in two banks
        # bank 0 - msb = [141:64] ^ ([63:0] << 14)
        # bank 1 - lsb = [141:75]
        e_lsb = self.banks[core_idx][bank_idx + 1].get_entry(idx)
        key_63_0 = (e.key.get_value() ^ (e_lsb.key.get_value() << 11)) >> 14
        key_141_64 = e.key.get_value() ^ (key_63_0 << 14)
        key = (key_141_64 << 64) + key_63_0

        payload = (e.payload.get_value() << 32) + e_lsb.payload.get_value()

        return (hex(key), hex(payload), hex(e.encrypted_key.get_value()), e.key_width)

    def report(self, core_idxs, cam=True, filename="./cem_db.csv"):
        print(
            cem_db.RED +
            "CAUTION: THIS CLI IS RESOURCE INTENSIVE AND CAN CAUSE ROUTE UPDATES TO GET BLOCKED TEMPORARILY, DO NOT RUN IT PERIODICALLY. THIS IS A DEBUG CLI AND SHOULD BE RUN ONLY WHEN NECESSARY." +
            cem_db.END)
        print("Writing report to %s" % filename)
        fd = open(filename, "w")
        print("core_idx, bank, entry, key, payload, key_width, encrypted_key", file=fd)
        for core_idx in core_idxs:
            print("Writing content of core %02d" % core_idx)
            # each core in CEM is configured to have pre defined number of SRAM banks
            # SRAM banks are shared between CEM and LPM
            for bank_idx in range(self.NUM_BANKS - self._get_num_of_banks(core_idx=core_idx), self.NUM_BANKS):
                bank = self.banks[core_idx][bank_idx]
                size = bank.get_size()

                for idx in range(size):
                    key, pld, encr_key, key_width = self._get_entry(core_idx, bank_idx, idx)
                    print(
                        "%d, %d, %d, %s, %s, %d, %s" %
                        (core_idx,
                         bank_idx,
                         idx,
                         key,
                         pld,
                         key_width,
                         encr_key),
                        file=fd)

            if cam:
                size = self.cam[core_idx].get_desc().entries
                block_id = self.cam[core_idx].get_block_id()
                addr = self.cam[core_idx].get_desc().addr
                width_bits = self.cam[core_idx].get_desc().width_total_bits

                for idx in range(size):
                    v = self.ll_device.read_memory_raw(block_id, addr + idx, width_bits)
                    bv = lldcli.bit_vector(hex(v))
                    valid = bv.bit(width_bits - 1)
                    key = "0" if not valid else ("0x%s" % bv.bits(cem_db.CAM_KEY_MSB, cem_db.CAM_PAYLOAD_MSB + 1).to_string())
                    payload = "0" if not valid else ("0x%s" % bv.bits(cem_db.CAM_PAYLOAD_MSB, 0).to_string())
                    print("%d, %d, %d, %s, %s," % (core_idx, cem_db.CAM_IDX, idx, key, payload), file=fd)
        fd.close()

    @staticmethod
    def convert_report_2_debug(filename ="./cem_db.csv", debug_filename="./cem_db_debug.csv"):
        print("transforming {} to a debuggable file named {}".format(filename, debug_filename))
        with open(filename, newline='') as inf:
            with open(debug_filename, mode="+w", newline='') as outf:
                reader = csv.DictReader(inf)
                fieldnames = reader.fieldnames + ['type', 'debug_key']
                writer = csv.DictWriter(outf, fieldnames=fieldnames)
                for row in reader:
                    new_row = row
                    e_row = debuggable_report_row.create(row)
                    new_row['type'] = e_row.get_type()
                    new_row['debug_key'] = e_row.get_debug_key()
                    writer.writerow(new_row)

    def read_age(self, core_idx, bank_idx, entry_idx):
        # Age data is stored as following:
        # - Each core banks occupy 512 lines
        # - Each Bank occupy 32 lines (64 entries per line)
        # - CAM reside starting line (16 * 512), each CAM occupy half line; 32 entries
        # - Each entry is 4 bits wide (MSB is age owner bit)
        if bank_idx != cem_db.CAM_IDX:
            line = core_idx * 512 + bank_idx * 32 + int(entry_idx / 64)
            entry_offset = (entry_idx % 64) * 4
        else:
            line = 16 * 512 + int(core_idx / 2)
            entry_offset = (32 * (core_idx % 2) + entry_idx) * 4

        v = self.ll_device.read_memory(self.tree.cdb.top.cem_age_table, line)
        return ((v >> entry_offset) % 16)

    def _get_num_of_banks(self, core_idx):
        debug_d = debug_device(self.device)
        active_banks = debug_d.read_register(debug_d.device_tree.cdb.top.active_banks[core_idx]).active_banks
        banks_bit_map = bin(active_banks)[2:]
        return banks_bit_map.count("1")

    def _get_valid_entry(self, core_idx, bank_idx, idx):
        entry = self.banks[core_idx][bank_idx].get_entry(idx)
        if not entry.valid:
            return None
        else:
            return entry

    def _get_entry_type(self, key):
        key = bin(int(key, 16))[2:]
        # longest to match first
        for key_type in self.sorted_key_list:
            pattern = r"\d+{key}$".format(key=key_type)
            if re.match(pattern, key):
                return self.key_type_dict[key_type]
        return None

    def _is_double_entry(self, key_width):
        if key_width == 142:
            return True
        else:
            return False

    def report_summary(self, filename=None):
        print(
            cem_db.RED +
            "CAUTION: THIS CLI IS RESOURCE INTENSIVE AND CAN CAUSE ROUTE UPDATES TO GET BLOCKED TEMPORARILY, DO NOT RUN IT PERIODICALLY. THIS IS A DEBUG CLI AND SHOULD BE RUN ONLY WHEN NECESSARY." +
            cem_db.END)
        fd = sys.stdout
        if filename:
            fd = open(filename, "w")
        headers = ["Metric / Core"]
        core_single_entries = ["SRAM Single Entries"]
        core_double_entries = ["SRAM Double Entries"]
        sram_utilization = ["SRAM utilization %"]
        core_cam_entries = ["CAM Entries"]
        cam_utilization = ["CAM utilization %"]
        core_bfd = ["BFD"]
        core_pfc = ["PFC"]
        core_labels = ["MPLS Lables"]
        core_lpts = ["LPTS 2nd lookup"]
        core_rpf = ["RPF"]
        core_lp_over_lag = ["LP Over LAG"]
        core_ip_prefix_id = ["IP prefix id"]
        core_ipv6_s_g = ["IPV6 S,G"]
        core_ipv4_s_g = ["IPV4 S,G"]
        core_ipv6_dip = ["IPV6 DIP / SIP (/128)"]
        core_ipv4_dip = ["IPV4 DIP / SIP (/32)"]
        core_l2 = ["L2 Mac"]
        core_keys_dict = {}
        for core_idx in range(16):
            headers.append("Core %d" % core_idx)
            single_entries = 0
            double_entries = 0
            free_rows = 0
            cam_entries = 0
            core_size = 0
            accounting_dict = {
                "BFD": 0,
                "PFC": 0,
                "MPLS Lables": 0,
                "LPTS 2nd lookup": 0,
                "RPF": 0,
                "LP Over LAG": 0,
                "IP prefix id": 0,
                "IPV6 S,G": 0,
                "IPV4 S,G": 0,
                "IPV6 DIP / SIP": 0,
                "IPV4 DIP / SIP": 0,
                "L2 Mac": 0
            }
            core_keys_dict[core_idx] = []
            # each core in CEM is configured to have pre defined number of SRAM banks
            # 16 SRAM banks are shared between CEM and LPM out of which 0 - x is used by LPM and x+1 - 15 are used by CEM
            for bank_idx in range(self.NUM_BANKS - self._get_num_of_banks(core_idx=core_idx), self.NUM_BANKS):
                bank = self.banks[core_idx][bank_idx]
                size = bank.get_size()
                core_size += size
                for idx in range(size):
                    self.device.acquire_device_lock(True)
                    entry = self._get_valid_entry(core_idx, bank_idx, idx)
                    self.device.release_device_lock()
                    if not entry:
                        free_rows += 1
                        continue
                    if self._is_double_entry(entry.key_width):
                        double_entries += 1
                        if bank_idx % 2 == 1:
                            continue
                        # double entry is stored in two banks
                        # bank 0 - msb = [141:64] ^ ([63:0] << 14)
                        # bank 1 - lsb = [141:75]
                        self.device.acquire_device_lock(True)
                        e_lsb = self.banks[core_idx][bank_idx + 1].get_entry(idx)
                        self.device.release_device_lock()
                        key_63_0 = (entry.key.get_value() ^ (e_lsb.key.get_value() << 11)) >> 14
                        key_141_64 = entry.key.get_value() ^ (key_63_0 << 14)
                        key = hex((key_141_64 << 64) + key_63_0)
                        core_keys_dict[core_idx].append(key)
                    else:
                        single_entries += 1
                        key = hex(entry.key.get_value())
                        core_keys_dict[core_idx].append(key)
            size = self.cam[core_idx].get_desc().entries
            block_id = self.cam[core_idx].get_block_id()
            addr = self.cam[core_idx].get_desc().addr
            width_bits = self.cam[core_idx].get_desc().width_total_bits
            for idx in range(size):
                self.device.acquire_device_lock(True)
                v = self.ll_device.read_memory_raw(block_id, addr + idx, width_bits)
                self.device.release_device_lock()
                bv = lldcli.bit_vector(hex(v))
                valid = bv.bit(width_bits - 1)
                if valid:
                    cam_entries += 1
                    key = "0x%s" % bv.bits(cem_db.CAM_KEY_MSB, cem_db.CAM_PAYLOAD_MSB + 1).to_string()
                    core_keys_dict[core_idx].append(key)
            for key in core_keys_dict[core_idx]:
                entry_type = self._get_entry_type(key)
                if not entry_type:
                    continue
                accounting_dict[entry_type] = accounting_dict.get(entry_type, 0) + 1
            core_single_entries.append(single_entries)
            core_double_entries.append(int(double_entries / 2))
            sram_utilization.append((single_entries + double_entries) / core_size)
            core_cam_entries.append(cam_entries)
            cam_utilization.append(cam_entries / 32)
            core_bfd.append(accounting_dict["BFD"])
            core_pfc.append(accounting_dict["PFC"])
            core_labels.append(accounting_dict["MPLS Lables"])
            core_lpts.append(accounting_dict["LPTS 2nd lookup"])
            core_rpf.append(accounting_dict["RPF"])
            core_l2.append(accounting_dict["L2 Mac"])
            core_lp_over_lag.append(accounting_dict["LP Over LAG"])
            core_ip_prefix_id.append(accounting_dict["IP prefix id"])
            core_ipv6_s_g.append(accounting_dict["IPV6 S,G"])
            core_ipv4_s_g.append(accounting_dict["IPV4 S,G"])
            core_ipv6_dip.append(accounting_dict["IPV6 DIP / SIP"])
            core_ipv4_dip.append(accounting_dict["IPV4 DIP / SIP"])
        headers.append("Tot/Avg")
        data_rows = [
            core_ipv4_dip,
            core_ipv6_dip,
            core_ipv4_s_g,
            core_ipv6_s_g,
            core_labels,
            core_l2,
            core_lpts,
            core_bfd,
            core_pfc,
            core_rpf,
            core_lp_over_lag,
            core_ip_prefix_id,
            core_single_entries,
            core_double_entries,
            core_cam_entries
        ]
        stat_rows = [
            sram_utilization,
            cam_utilization]
        for row in data_rows:
            row.append(sum(row[1:]))
        for row in stat_rows:
            num_elems = len(row)
            row.append(sum(row[1:]) / (num_elems - 1))
            for i in range(1, num_elems + 1):
                row[i] = "%.1f" % (row[i] * 100) + '%'
        table = terminaltables.AsciiTable([headers] + data_rows + stat_rows)
        print(table.table, file=fd)
        if filename:
            fd.close()


# @brief Class to retrieve debug data from LPM


class lpm_db:
    VRF_LEN = 11
    IPV4_IP_LEN = 32
    IPV6_IP_LEN = 128
    IPV4_LPM_FULL_PREFIX_LEN = VRF_LEN + IPV4_IP_LEN + 1
    IPV6_LPM_FULL_PREFIX_LEN = VRF_LEN + IPV6_IP_LEN + 1

    LPM_TCAM_BANK_SIZE = 512
    RED = "\033[1;31m"
    END = "\033[0;0m"

    def __init__(self, device):
        self.device = device
        self.ll_device = self.device.get_ll_device()

        device_info = get_device_revision_info(self.device)

        self.device_tree = device_info['device_tree']
        self.device_name_major = device_info['device_name_major']

        rm = sdk_debug.la_device_get_resource_manager(device)
        self.lpm = rm.get_lpm_unmanaged()
        self.bucketing_tree = self.lpm.get_tree_unmanaged()
        self.lpm_cores = []
        for idx in range(self.lpm.get_num_cores()):
            self.lpm_cores.append(self.lpm.get_core_unmanaged(idx))

    # @brief Reports the placement of an entry in LP cores
    #
    # param[in] ipv4_key    NPL key
    # param[in] length      Key length as it was provided to LPM NPL table
    def find_ipv4_entry(self, ipv4_key, length, to_print=True):
        key = ipv4_key.pack()

        # Input data formatting
        lpm_length = length + lpm_db.VRF_LEN + 1
        bits_to_clear = lpm_db.IPV4_LPM_FULL_PREFIX_LEN - lpm_length
        key = key >> bits_to_clear

        (status, distr_node, tcam_node, l1_node, l2_node) = self._find_entry(key, lpm_length, verbose=to_print)

        # Print out
        if status and to_print:
            all_prefix = key << bits_to_clear
            print("Input: prefix=0x%012x, width=%d, orig_key=0x%012x" % (all_prefix, lpm_length, ipv4_key.pack()))
            self._pretty_print(distr_node, tcam_node, l1_node, l2_node, is_ipv6=False)

        return (status, distr_node, tcam_node, l1_node, l2_node)

    # @brief Reports the placement of an entry in LP cores
    #
    # param[in] ipv4_key    NPL key
    # param[in] length      Key length as it was provided to LPM NPL table
    def find_ipv6_entry(self, ipv6_key, length, to_print=True):
        key = ipv6_key.pack()
        # setting key type
        key += (1 << (lpm_db.IPV6_LPM_FULL_PREFIX_LEN - 1))

        # Input data formatting
        lpm_length = length + lpm_db.VRF_LEN + 1
        bits_to_clear = lpm_db.IPV6_LPM_FULL_PREFIX_LEN - lpm_length
        key = key >> bits_to_clear

        (status, distr_node, tcam_node, l1_node, l2_node) = self._find_entry(key, lpm_length, verbose=to_print)

        # Print out
        if status and to_print:
            all_prefix = key << bits_to_clear
            print("Input: prefix=0x%012x, width=%d, orig_key=0x%012x" % (all_prefix, lpm_length, ipv6_key.pack()))
            self._pretty_print(distr_node, tcam_node, l1_node, l2_node, is_ipv6=True)

        return (status, distr_node, tcam_node, l1_node, l2_node)

    def get_occupancy_stats(self):
        stats = []

        self.device.acquire_device_lock(True)

        total_l1_stats = self.bucketing_tree.get_occupancy(hw_tables.lpm_level_e_L1)
        total_l2_stats = self.bucketing_tree.get_occupancy(hw_tables.lpm_level_e_L2)
        for core in self.lpm_cores:
            my_stats = {}

            tcam = core.get_tcam()
            tcam_stats = tcam.get_occupancy()
            core_id = core.get_id()
            l1_stats = total_l1_stats[core_id]
            l2_stats = total_l2_stats[core_id]

            my_stats['ipv4_tcam_entries'] = tcam_stats.num_single_entries
            my_stats['ipv6_double_tcam_entries'] = tcam_stats.num_double_entries
            my_stats['ipv6_quad_tcam_entries'] = tcam_stats.num_quad_entries
            my_stats['l1_entries'] = l1_stats.sram_single_entries
            my_stats['l2_sram_single_entries'] = l2_stats.sram_single_entries
            my_stats['l2_sram_double_entries'] = l2_stats.sram_double_entries
            my_stats['l2_hbm_entries'] = l2_stats.hbm_entries
            my_stats['core_entries'] = l2_stats.sram_single_entries + l2_stats.sram_double_entries + l2_stats.hbm_entries
            my_stats['ipv4_entries'] = l2_stats.sram_ipv4_entries + l2_stats.hbm_ipv4_entries
            my_stats['ipv6_entries'] = l2_stats.sram_ipv6_entries + l2_stats.hbm_ipv6_entries
            my_stats['ipv4_entries_sram_entries'] = l2_stats.sram_ipv4_entries
            my_stats['ipv4_entries_hbm_entries'] = l2_stats.hbm_ipv4_entries
            my_stats['ipv6_entries_sram_entries'] = l2_stats.sram_ipv6_entries
            my_stats['ipv6_entries_hbm_entries'] = l2_stats.hbm_ipv6_entries
            my_stats['tcam_occupied_rows'] = tcam_stats.occupied_cells
            my_stats['tcam_free_rows'] = tcam_stats.empty_cells
            my_stats['l1_rows'] = l1_stats.sram_rows
            my_stats['l2_sram_rows'] = l2_stats.sram_rows
            my_stats['l2_hbm_rows'] = l2_stats.hbm_buckets

            stats.append(my_stats)

        self.device.release_device_lock()

        for core_idx, core in enumerate(self.lpm_cores):
            my_stats = stats[core_idx]

            tcam = core.get_tcam()

            l1_params = self.bucketing_tree.get_parameters(hw_tables.lpm_level_e_L1)
            l1_double_bucket_size = l1_params.bucket_num_fixed_entries * 2 + l1_params.bucket_num_shared_entries
            l2_params = self.bucketing_tree.get_parameters(hw_tables.lpm_level_e_L2)
            l2_double_bucket_size = l2_params.bucket_num_fixed_entries + l2_params.bucket_num_shared_entries
            l2_max_bucket_size = l2_params.bucket_num_fixed_entries * 2 + l2_params.bucket_num_shared_entries

            tcam_total_rows = tcam.get_num_cells()
            my_stats['tcam_occupancy'] = my_stats['tcam_occupied_rows'] / tcam_total_rows

            max_l1_rows = l1_params.num_of_sram_buckets / 2
            my_stats['l1_occupancy'] = my_stats['l1_rows'] / max_l1_rows

            max_l2_sram_rows = l2_params.num_of_sram_buckets / 2
            my_stats['l2_sram_occupancy'] = my_stats['l2_sram_rows'] / max_l2_sram_rows

            l2_hbm_occupancy = 0 if (l2_params.num_of_hbm_buckets == 0) else my_stats['l2_hbm_rows'] / l2_params.num_of_hbm_buckets
            my_stats['l2_hbm_occupancy'] = l2_hbm_occupancy

            l1_rows = my_stats['l1_rows']
            l1_utilization = 0 if (l1_rows == 0) else my_stats['l1_entries'] / (l1_double_bucket_size * l1_rows)
            my_stats['l1_utilization'] = l1_utilization

            l2_sram_rows = my_stats['l2_sram_rows']
            l2_sram_utilization = 0 if (l2_sram_rows == 0) else (
                my_stats['l2_sram_single_entries'] + 2 * my_stats['l2_sram_double_entries']) / (l2_double_bucket_size * l2_sram_rows)
            my_stats['l2_sram_utilization'] = l2_sram_utilization

            l2_hbm_rows = my_stats['l2_hbm_rows']
            l2_hbm_utilization = 0 if (l2_hbm_rows == 0) else my_stats['l2_hbm_entries'] / (l2_max_bucket_size * l2_hbm_rows)
            my_stats['l2_hbm_utilization'] = l2_hbm_utilization

        return stats

    # @brief Summary report
    #
    # Per core utilization and occupancy report
    # Break down per TCAM, L1 and L2 levels
    def report(self, filename=None):
        print(
            lpm_db.RED +
            "CAUTION: THIS CLI IS RESOURCE INTENSIVE AND CAN CAUSE ROUTE UPDATES TO GET BLOCKED TEMPORARILY, DO NOT RUN IT PERIODICALLY. THIS IS A DEBUG CLI AND SHOULD BE RUN ONLY WHEN NECESSARY." +
            lpm_db.END)

        column_headers = ["Metric / Core"]
        core_entries = ["Entries"]
        ipv4_entries = ["IPv4 Entries"]
        ipv4_entries_sram_entries = ["IPv4 SRAM Entries"]
        ipv4_entries_hbm_entries = ["IPv4 HBM Entries"]
        ipv6_entries = ["IPv6 Entries"]
        ipv6_entries_sram_entries = ["IPv6 SRAM Entries"]
        ipv6_entries_hbm_entries = ["IPv6 HBM Entries"]
        tcam_occupied_rows = ["TCAM Occupied Rows"]
        tcam_free_rows = ["TCAM Free Rows"]
        ipv4_tcam_entries = ["IPv4 TCAM Entries"]
        ipv6_double_tcam_entries = ["IPv6 double TCAM Entries"]
        ipv6_quad_tcam_entries = ["IPv6 quad TCAM Entries"]
        l1_rows = ["L1 Rows"]
        l1_entries = ["L1 Entries"]
        l2_sram_rows = ["L2 SRAM Rows"]
        l2_hbm_rows = ["L2 HBM Rows"]
        l2_sram_single_entries = ["L2 SRAM Single Entries"]
        l2_sram_double_entries = ["L2 SRAM Double Entries"]
        l2_hbm_entries = ["L2 HBM Entries"]
        tcam_occupancy = ["TCAM Occupancy"]
        l1_occupancy = ["L1 Occupancy (% Rows used)"]
        l2_sram_occupancy = ["L2 SRAM Occupancy (% Rows used)"]
        l2_hbm_occupancy = ["L2 HBM Occupancy (% Rows used)"]
        l1_utilization = ["L1 Utilization (of occupied buckets)"]
        l2_sram_utilization = ["L2 SRAM Utilization (of occupied buckets)"]
        l2_hbm_utilization = ["L2 HBM Utilization (of occupied buckets)"]

        stats = self.get_occupancy_stats()

        column_headers += ["Core %d" % core_id for core_id in range(len(stats))]

        ipv4_tcam_entries += [core_stats['ipv4_tcam_entries'] for core_stats in stats]
        ipv6_double_tcam_entries += [core_stats['ipv6_double_tcam_entries'] for core_stats in stats]
        ipv6_quad_tcam_entries += [core_stats['ipv6_quad_tcam_entries'] for core_stats in stats]
        l1_entries += [core_stats['l1_entries'] for core_stats in stats]
        l2_sram_single_entries += [core_stats['l2_sram_single_entries'] for core_stats in stats]
        l2_sram_double_entries += [core_stats['l2_sram_double_entries'] for core_stats in stats]
        l2_hbm_entries += [core_stats['l2_hbm_entries'] for core_stats in stats]
        core_entries += [core_stats['core_entries'] for core_stats in stats]
        ipv4_entries += [core_stats['ipv4_entries'] for core_stats in stats]
        ipv6_entries += [core_stats['ipv6_entries'] for core_stats in stats]
        ipv4_entries_sram_entries += [core_stats['ipv4_entries_sram_entries'] for core_stats in stats]
        ipv4_entries_hbm_entries += [core_stats['ipv4_entries_hbm_entries'] for core_stats in stats]
        ipv6_entries_sram_entries += [core_stats['ipv6_entries_sram_entries'] for core_stats in stats]
        ipv6_entries_hbm_entries += [core_stats['ipv6_entries_hbm_entries'] for core_stats in stats]
        tcam_occupied_rows += [core_stats['tcam_occupied_rows'] for core_stats in stats]
        tcam_free_rows += [core_stats['tcam_free_rows'] for core_stats in stats]
        l1_rows += [core_stats['l1_rows'] for core_stats in stats]
        l2_sram_rows += [core_stats['l2_sram_rows'] for core_stats in stats]
        l2_hbm_rows += [core_stats['l2_hbm_rows'] for core_stats in stats]
        tcam_occupancy += [core_stats['tcam_occupancy'] for core_stats in stats]
        l1_occupancy += [core_stats['l1_occupancy'] for core_stats in stats]
        l2_sram_occupancy += [core_stats['l2_sram_occupancy'] for core_stats in stats]
        l2_hbm_occupancy += [core_stats['l2_hbm_occupancy'] for core_stats in stats]
        l1_utilization += [core_stats['l1_utilization'] for core_stats in stats]
        l2_sram_utilization += [core_stats['l2_sram_utilization'] for core_stats in stats]
        l2_hbm_utilization += [core_stats['l2_hbm_utilization'] for core_stats in stats]

        rows_to_sum = [
            core_entries,
            ipv4_entries,
            ipv6_entries,
            ipv4_entries_sram_entries,
            ipv4_entries_hbm_entries,
            ipv6_entries_sram_entries,
            ipv6_entries_hbm_entries,
            tcam_occupied_rows,
            tcam_free_rows,
            ipv4_tcam_entries,
            ipv6_double_tcam_entries,
            ipv6_quad_tcam_entries,
            l1_rows,
            l1_entries,
            l2_sram_rows,
            l2_hbm_rows,
            l2_sram_single_entries,
            l2_sram_double_entries,
            l2_hbm_entries]

        rows_to_average = [
            tcam_occupancy,
            l1_occupancy,
            l2_sram_occupancy,
            l2_hbm_occupancy,
            l1_utilization,
            l2_sram_utilization,
            l2_hbm_utilization]

        column_headers.append("Tot/Avg")

        for row in rows_to_sum:
            data_items = row[1:]
            row.append(sum(data_items))

        for row in rows_to_average:
            data_items = row[1:]
            num_elems = len(data_items)
            row.append(sum(data_items) / num_elems)

            # convert to percentages
            for i in range(1, len(row)):
                row[i] = "%.1f" % (row[i] * 100) + '%'

        table = terminaltables.AsciiTable([column_headers] + rows_to_sum + rows_to_average)

        fd = sys.stdout
        if filename:
            fd = open(filename, "w")

        print(table.table, file=fd)

        if filename:
            fd.close()

    # @ brief Detailed report of distributor entries
    #
    # Prefix mapping to group
    # Group mapping to core
    def report_distributer_in_hw(self, filename=None):

        distr_tcam = self.device_tree.cdb.top.clpm_group_map_tcam[0]

        type_str = ["ipv4", "ipv6", "none"]
        report_rows = [["Line", "Type", "Width", "Prefix", "Group", "Core", "Key", "Mask", "Group (hw)", "Core (hw)"]]
        for e in self.lpm.get_distributer().get_entries():
            width = e.key.get_width()
            type_idx = 2 if width == 0 else (e.key.get_value() >> (width - 1))
            tcam_row = e.location.cell

            k, m, valid = self.ll_device.read_tcam(distr_tcam, tcam_row)

            if self.device_name_major == 'pacific':
                group = self.ll_device.read_memory(self.device_tree.cdb.top.clpm_group_map_regs, tcam_row)
                core = self.ll_device.read_register(self.device_tree.cdb.top.lpm_group_map_table[group])
            elif self.device_name_major == 'gibraltar':
                group = self.ll_device.read_memory(self.device_tree.cdb.top.clpm_tcam_index_to_lpm_group_map_regs[0], tcam_row)
                core = self.ll_device.read_memory(self.device_tree.cdb.top.clpm_group_to_lpm_core_map_regs[0], group)
            else:
                raise Exception('Unknown device')

            row = [
                tcam_row,
                type_str[type_idx],
                width,
                hex(e.key.get_value()),
                e.payload,
                self.lpm.get_core_index_by_group(
                    e.payload),
                "0x%020x" %
                k,
                "0x%020x" %
                m,
                group,
                core]
            report_rows.append(row)

        table = terminaltables.AsciiTable(report_rows)

        fd = sys.stdout
        if filename:
            fd = open(filename, "w")

        print(table.table, file=fd)

        if filename:
            fd.close()

    def encode_lpm_prefix(self, prefix, width):
        is_ipv6 = (prefix >> (width - 1)) == 1
        if is_ipv6:
            return (prefix, width)

        broken_bit = 20
        decoded_key_len = lpm_db.VRF_LEN + 32 + 1
        encoded_key_len = decoded_key_len + 1
        bits_above_broken_bit = encoded_key_len - (broken_bit + 1)
        if width <= bits_above_broken_bit:
            return (prefix, width)

        prefix_padded = prefix << (decoded_key_len - width)
        prefix_msb = get_bits(prefix_padded, width - 1, broken_bit)
        prefix_lsb = get_bits(prefix_padded, broken_bit - 1, 0)
        encoded_prefix_padded = (prefix_msb << (broken_bit + 1)) | prefix_lsb
        encoded_prefix = encoded_prefix_padded >> (decoded_key_len - width)

        return (encoded_prefix, width + 1)

    def decode_lpm_prefix(self, prefix, width):
        is_ipv6 = (prefix >> (width - 1)) == 1
        if is_ipv6:
            return (prefix, width)

        broken_bit = 20
        decoded_key_len = lpm_db.VRF_LEN + 32 + 1
        encoded_key_len = decoded_key_len + 1
        bits_above_broken_bit = encoded_key_len - (broken_bit + 1)
        if width <= bits_above_broken_bit:
            return (prefix, width)

        assert(encoded_key_len >= width)

        prefix_padded = prefix << (encoded_key_len - width)
        decoded_padded = (
            get_bits(
                prefix_padded,
                encoded_key_len -
                1,
                broken_bit +
                1) << broken_bit) | get_bits(
            prefix_padded,
            broken_bit -
            1,
            0)
        decoded_prefix = decoded_padded >> (encoded_key_len - width)

        return (decoded_prefix, width - 1)

    # @brief Report LPM database, reconstructed from device memory
    #
    # @param[in]    core_idx    LPM core index (0..15)
    def report_memory_content(self, core_idx, filename="./lpm_dump.csv"):
        fd = open(filename, "w")
        core_hw_writer = self.lpm_cores[core_idx].get_core_hw_writer()
        core_tcam = self.lpm_cores[core_idx].get_tcam()

        if self.device_name_major == 'gibraltar':
            print('Gibraltar does not support reading LPM memory content yet (needs support in lpm_core_hw_writer_gb)')
            fd.close()
            return

        print(
            "idx",
            "is_ipv6",
            "key_width (encoded)",
            "key (encoded)",
            "key_width (decoded)",
            "key (decoded)",
            "network",
            "payload",
            "tcam.line",
            "tcam.prefix_width",
            "tcam.prefix",
            "l1.bucket",
            "l1.prefix_width",
            "l1.prefix",
            "l1.payload (default)",
            "l1.is_default",
            "l2.bucket",
            "l2.prefix_width",
            "l2.prefix",
            "l2.is_wide_entry",
            "l2.is_leaf",
            "l2.is_default",
            sep=',',
            file=fd)
        count = 0

        for i in range(core_tcam.get_num_cells()):
            tcam_location = core_hw_writer.tcam_row_to_location(i)
            tcam = core_hw_writer.read_tcam(tcam_location)
            if not tcam.valid:
                continue

            if tcam.is_ipv6 and ((i // lpm_db.LPM_TCAM_BANK_SIZE) % 2 != 0):
                continue

            tcam_key = tcam.prefix.get_value()
            tcam_key_width = tcam.prefix_width

            l1_bucket, l1_bucket_default_payload = core_hw_writer.read_l1_bucket(tcam.payload)

            for l1 in l1_bucket:
                if not l1.valid:
                    continue

                l1_key = (tcam_key << l1.prefix_width) + l1.prefix.get_value()
                l1_key_width = tcam_key_width + l1.prefix_width

                l2_bucket, l2_bucket_default_payload = core_hw_writer.read_l2_bucket(l1.payload)

                for l2 in l2_bucket:
                    if not l2.valid:
                        continue

                    l2_key = (l1_key << l2.prefix_width) | l2.prefix.get_value()
                    l2_key_width = l1_key_width + l2.prefix_width
                    (l2_key_decoded, l2_key_width_decoded) = self.decode_lpm_prefix(l2_key, l2_key_width)

                    print(
                        count,
                        tcam.is_ipv6,
                        l2_key_width,
                        hex(l2_key),
                        l2_key_width_decoded,
                        hex(l2_key_decoded),
                        self.lpm_key_to_string(l2_key_decoded, l2_key_width_decoded),
                        hex(l2.payload),
                        i,
                        tcam.prefix_width,
                        hex(tcam.prefix.get_value()),
                        tcam.payload,
                        l1.prefix_width,
                        hex(l1.prefix.get_value()),
                        '',  # l1.payload in case of default L1 entry
                        False,  # l1.is_default
                        l1.payload,
                        l2.prefix_width,
                        hex(l2.prefix.get_value()),
                        l2.is_wide_entry,
                        l2.is_l2_leaf,
                        False,  # l2.is_default"
                        sep=',',
                        file=fd)
                    count += 1

                (l1_key_decoded, l1_key_width_decoded) = self.decode_lpm_prefix(l1_key, l1_key_width)
                # L2 default entry
                print(
                    count,
                    tcam.is_ipv6,
                    l1_key_width,
                    hex(l1_key),
                    l1_key_width_decoded,
                    hex(l1_key_decoded),
                    self.lpm_key_to_string(l1_key_decoded, l1_key_width_decoded),
                    hex(l2_bucket_default_payload),
                    i,
                    tcam.prefix_width,
                    hex(tcam.prefix.get_value()),
                    tcam.payload,
                    l1.prefix_width,
                    hex(l1.prefix.get_value()),
                    '',  # l1.payload in case of default L1 entry
                    False,  # l1.is_default
                    l1.payload,
                    0,  # l2.prefix_width
                    0,  # l2.prefix
                    False,  # l2.is_wide_entry
                    False,  # l2.is_l2_leaf
                    True,  # l2.is_default
                    sep=',',
                    file=fd)
                count += 1

            (tcam_key_decoded, tcam_key_width_decoded) = self.decode_lpm_prefix(tcam_key, tcam_key_width)
            # L1 default entry
            print(
                count,
                tcam.is_ipv6,
                tcam_key_width,
                hex(tcam_key),
                tcam_key_width_decoded,
                hex(tcam_key_decoded),
                self.lpm_key_to_string(tcam_key_decoded, tcam_key_width_decoded),
                hex(l1_bucket_default_payload),
                i,
                tcam.prefix_width,
                hex(tcam.prefix.get_value()),
                tcam.payload,
                0,  # l1 prefix width
                0,  # l1 prefix
                hex(l1_bucket_default_payload),  # l1.payload in case of default L1 entry
                True,  # l1.is_default
                'N/A',  # l2 bucket
                'N/A',  # l2.prefix_width
                'N/A',  # l2.prefix
                'N/A',  # l2.is_wide_entry
                'N/A',  # l2.is_l2_leaf
                'N/A',  # l2.is_default
                sep=',',
                file=fd)
            count += 1
        fd.close()

    # @brief Check list of table entries (key, length, value) vs the content of LPM database
    #
    # @param[in]    entries     List of NPL table entries (either ipv4_lpm_table or ipv6_lpm_table
    # @param[in]    is_ipv6     Whether entries ipv4 or ipv6
    def check_entries_in_lpm(self, entries, is_ipv6=False, verbose=False):
        count = 0
        ret_val = True
        entry_type = "ipv6" if is_ipv6 else "ipv4"
        find_func = self.find_ipv6_entry if is_ipv6 else self.find_ipv4_entry

        for k, length, v in entries:
            success, d, t, l1, l2 = find_func(k, length, to_print=verbose)
            if not success:
                print("-E- No %s entry found in LPM for key=0x%012x, len=%d" % (entry_type, k.pack(), length))
                ret_val = False
            else:
                count += 1

        print("Found %d entries" % count)
        return ret_val

    # @brief Check list of table entries (key, length, value) vs memory content
    #
    # @param[in]    entries     List of NPL table entries (either ipv4_lpm_table or ipv6_lpm_table
    # @param[in]    is_ipv6     Whether entries ipv4 or ipv6
    def check_entries_in_hw(self, entries, is_ipv6=False, verbose=False):
        count = 0
        ret_val = True
        entry_type = "ipv6" if is_ipv6 else "ipv4"
        find_func = self.find_ipv6_entry if is_ipv6 else self.find_ipv4_entry

        for k, length, v in entries:
            success, d, t, l1, l2 = find_func(k, length, to_print=verbose)
            if not success:
                print("-E- No %s entry found in LPM for key=0x%012x, len=%d" % (entry_type, k.pack(), length))
                ret_val = False
                continue

            lpm_length = length
            key = k.pack()
            if is_ipv6:
                # setting key type
                key += (1 << (lpm_db.IPV6_LPM_FULL_PREFIX_LEN - 1))

                lpm_length += lpm_db.VRF_LEN + 1
                key >>= (lpm_db.IPV6_LPM_FULL_PREFIX_LEN - lpm_length)
            else:
                lpm_length += lpm_db.VRF_LEN + 1
                key >>= (lpm_db.IPV4_LPM_FULL_PREFIX_LEN - lpm_length)

            status = self._find_entry_in_hw(key, lpm_length, d, t, l1, l2, verbose)
            if status:
                count += 1

            ret_val &= status

        print("Found %d entries" % count)
        return ret_val

    def _find_entry_in_hw(self, key, lpm_length, distr_node, tcam_node, l1_node, l2_node, verbose=True, encode=True):
        if self.device_name_major == 'gibraltar':
            print('-E- Gibraltar does not support reading LPM memory content yet (needs support in lpm_core_hw_writer_gb)')
            return False

        if encode:
            key, lpm_length = self.encode_lpm_prefix(key, lpm_length)

        # Group/Core
        group = distr_node.payload
        core_idx = self.lpm.get_core_index_by_group(group)

        core = self.lpm_cores[core_idx]
        writer = core.get_core_hw_writer()

        remaining_width = lpm_length

        # TCAM
        tcam_entry = writer.read_tcam(tcam_node.location)
        if not tcam_entry.valid:
            if verbose:
                print("-E- No entry found in HW TCAM for key=0x%012x, len=%d" % (key, lpm_length))
            return False

        found_key = tcam_entry.prefix.get_value()
        remaining_width -= tcam_entry.prefix_width

        # L1
        l1_entry = None
        l1_entries, l1_default_payload = writer.read_l1_bucket(tcam_entry.payload)
        for entry in l1_entries:
            if not entry.valid:
                continue

            hw_key_upto_l1 = (tcam_entry.prefix.get_value() << entry.prefix_width) | entry.prefix.get_value()
            hw_width_upto_l1 = tcam_entry.prefix_width + entry.prefix_width + 1  # +1 for v4/v6 bit
            if (l1_node.key.get_value() == hw_key_upto_l1):
                if entry.payload != l1_node.payload:
                    if verbose:
                        print(
                            "-E- Found in HW L1 for key=0x%012x, len=%d but payload doesn't match. (sw %d  hw %d)" %
                            (key, lpm_length, l1_node.payload, entry.payload))
                    return False
                l1_entry = entry
                break

        if not l1_entry:
            if verbose:
                print("Hitting L1 Default Entry for key=0x%012x, len=%d" % (key, lpm_length))

            # TODO handle GB (L1 default is an L2 bucket, it comes with a negative width)
            if l1_default_payload != l2_node.payload:
                if verbose:
                    print(
                        "-E- Found entry in HW but payloads don't match for key=0x%012x, len=%d  (sw 0x%x  hw 0x%x  is_default? True (L1))" %
                        (key, lpm_length, l2_node.payload, l1_default_payload))
                return False
            else:
                return True

        zero_length_index = 5 if (tcam_entry.payload % 2) == 0 else 7
        if l1_entry.prefix_width == 0 and l1_entry.index != zero_length_index:
            if verbose:
                print("-E- L1 entry is not placed at index 5 for key=0x%012x, len=%d" % (key, lpm_length))
            return False

        found_key = (found_key << l1_entry.prefix_width) + l1_entry.prefix.get_value()
        remaining_width -= l1_entry.prefix_width

        # L2
        l2_entry_payload = None
        bucket_entries, default_payload = writer.read_l2_bucket(l1_entry.payload)
        for entry in bucket_entries:
            if not entry.valid:
                continue

            result_key = (found_key << entry.prefix_width) + entry.prefix.get_value()
            if (result_key == key) and (entry.prefix_width <= remaining_width):
                l2_entry_payload = entry.payload
                break

        is_default = False
        if l2_entry_payload is None:
            if verbose:
                print(
                    "-D- No entry found in HW L2 for key=0x%012x, len=%d. Using default payload 0x%x" %
                    (key, lpm_length, default_payload))
            is_default = True
            l2_entry_payload = default_payload

        if l2_entry_payload != l2_node.payload:
            if verbose:
                print(
                    "-E- Found entry in HW but payloads don't match for key=0x%012x, len=%d  (sw 0x%x  hw 0x%x  is_default? %s)" %
                    (key, lpm_length, l2_node.payload, l2_entry_payload, is_default))
            return False

        return True

    def _find_entry(self, key, lpm_length, verbose=True, encode=True):
        if encode:
            key, lpm_length = self.encode_lpm_prefix(key, lpm_length)

        distr_node = self.lpm.get_distributer().find_entry_as_hw(hex(key), lpm_length)
        if not distr_node.valid:
            if verbose:
                print("-E- Couldn't find distributor entry for key=0x%012x, len=%d" % (key, lpm_length))
            return (False, None, None, None, None)

        distr_prefix_width = distr_node.key.get_width()

        group = distr_node.payload
        core_idx = self.lpm.get_core_index_by_group(group)
        core = self.lpm_cores[core_idx]

        # TCAM
        tcam = core.get_tcam()
        tcam_node = tcam.find_entry_as_hw(hex(key), lpm_length)
        if not tcam_node.valid:
            if verbose:
                print("-E- No entry at TCAM found for key=0x%012x, len=%d" % (key, lpm_length))
            return (False, distr_node, None, None, None)

        # Tree
        tree = self.bucketing_tree

        # L1
        l1_entry = tree.find_entry_as_hw(hex(key), lpm_length, core_idx, hw_tables.lpm_level_e_L1, tcam_node.payload)
        if (not l1_entry.is_valid):
            if verbose:
                print("-E- No entry at L1 found for key=0x%012x, len=%d" % (key, lpm_length))
            return (False, distr_node, tcam_node, None, None)

        if (l1_entry.is_default_entry):
            if verbose:
                print("-I- L1 hit default value key=0x%012x, len=%d" % (key, lpm_length))
            return (True, distr_node, tcam_node, l1_entry, None)

        # L2
        l2_entry = tree.find_entry_as_hw(hex(key), lpm_length, core_idx, hw_tables.lpm_level_e_L2, l1_entry.payload)
        if (not l2_entry.is_valid):
            if verbose:
                print("-E- No entry at L1 found for key=0x%012x, len=%d" % (key, lpm_length))
            return (False, distr_node, tcam_node, l1_entry, None)

        return (True, distr_node, tcam_node, l1_entry, l2_entry)

    def enable_force_l2_node_is_leaf(self, prefix, is_leaf):
        core_idx = self.l2_prefix_to_core(prefix)
        core = self.lpm_cores[core_idx]
        self.device.acquire_device_lock(True)
        core.enable_force_l2_node_is_leaf(prefix, is_leaf)
        self.device.release_device_lock()

    def disable_force_l2_node_is_leaf(self, l2_entry):
        core_idx = self.l2_prefix_to_core(l2_entry)
        core = self.lpm_cores[core_idx]
        self.device.acquire_device_lock(True)
        core.disable_force_l2_node_is_leaf(l2_entry.key)
        self.device.release_device_lock()

    def prefix_to_core(self, prefix, lpm_length):
        prefix_value = prefix.get_value()
        distr_node = self.lpm.get_distributer().find_entry_as_hw(hex(prefix_value), lpm_length)
        group = distr_node.payload
        core_idx = self.lpm.get_core_index_by_group(group)
        return core_idx

    def l2_prefix_to_core(self, prefix):
        return self.prefix_to_core(prefix, prefix.get_width())

    def is_prefix_ipv6(self, prefix):
        return (prefix >> (prefix.get_width() - 1)) == 1

    def _pretty_print(self, distr_node, tcam_node, l1_node, l2_node, is_ipv6=False):
        entry_len = lpm_db.IPV6_LPM_FULL_PREFIX_LEN if is_ipv6 else (lpm_db.IPV4_LPM_FULL_PREFIX_LEN + 1)  # +1 due to issue #693

        if distr_node:
            distr_prefix_width = distr_node.key.get_width()
            bits_to_shift = entry_len - distr_prefix_width
            group = distr_node.payload
            core_idx = self.lpm.get_core_index_by_group(group)
            row_id = distr_node.location.cell
            print("Distr: prefix=0x%012x, width=%03d, group=%d, core_idx=%d, row=%d" %
                  (distr_node.key.get_value(), distr_prefix_width, group, core_idx, row_id))

        if tcam_node:
            tcam_prefix = tcam_node.key.get_value()
            tcam_prefix_width = tcam_node.key.get_width()
            bits_to_shift = entry_len - tcam_node.key.get_width()
            tcam_prefix <<= bits_to_shift
            print(
                "TCAM:  prefix=0x%012x, width=%03d, payload=%d, bankset=%d, bank=%d, cell=%d" %
                (tcam_prefix,
                 tcam_prefix_width,
                 tcam_node.payload,
                 tcam_node.location.bankset,
                 tcam_node.location.bank,
                 tcam_node.location.cell))

        if l1_node:
            print("L1:    prefix=0x%012x, payload=%d" % (l1_node.key.get_value(), l1_node.payload))

        if l2_node:
            print("L2:    prefix=0x%012x, payload=%d" % (l2_node.key.get_value(), l2_node.payload))

    # @brief Move L2 bucket from src_row to dst_row
    def move_l2_bucket(self, core_idx, src_row, destination_memory):
        core = self.lpm_cores[core_idx]
        hbm_address_offset = core.get_hbm_cache_manager().get_hbm_address_offset()
        is_src_in_hbm = hw_tables.is_location_in_hbm(hw_tables.lpm_level_e_L2, src_row, hbm_address_offset)
        is_dst_in_hbm = (destination_memory == hw_tables.l2_bucket_location_e_HBM)
        if (is_src_in_hbm == is_dst_in_hbm):
            print('src and dst are in the same memory location')
            return None

        tree = self.bucketing_tree
        bucket = tree.get_bucket_by_hw_index(core_idx, hw_tables.lpm_level_e_L2, src_row)

        if bucket is None:
            print('No bucket at row %d' % src_row)
            return None

        core.move_l2_bucket(src_row, destination_memory)

        dst_row = bucket.get_hw_index()
        return dst_row

    def move_l2_bucket_from_sram_to_hbm(self, core_idx, src_row):
        return self.move_l2_bucket(core_idx, src_row, hw_tables.l2_bucket_location_e_HBM)

    def move_l2_bucket_from_hbm_to_sram(self, core_idx, src_row):
        return self.move_l2_bucket(core_idx, src_row, hw_tables.l2_bucket_location_e_SRAM)

    def get_lpm_hbm_channel_bank_utilization_stats(self):
        self.device.acquire_device_lock(True)
        l2_buckets = self.bucketing_tree.get_buckets(hw_tables.lpm_level_e_L2)

        NUMBER_REPLICATIONS = 4
        NUMBER_CHANNELS = 16
        NUMBER_BANKS = 16
        HBM_START_OFFSET = 4096

        channel_utilization_data = [[{'entries': 0, 'buckets': 0} for _ in range(NUMBER_BANKS)] for _ in range(NUMBER_CHANNELS)]

        for bucket in l2_buckets:
            hw_index = bucket.get_hw_index()
            if (hw_index < HBM_START_OFFSET):
                continue

            coreid = bucket.get_core()
            core_hw_writer = self.lpm_cores[coreid].get_core_hw_writer()

            for repl in range(NUMBER_REPLICATIONS):
                hbm_location = core_hw_writer.calculate_bucket_location_in_hbm(hw_index, repl)
                bank = hbm_location.bank
                cpu_channel = get_bits(hbm_location.channel, 0, 0)
                channel_idx = get_bits(hbm_location.channel, 3, 1)
                channel = (cpu_channel << 3) | channel_idx
                channel_utilization_data[channel][bank]['buckets'] += 1
                channel_utilization_data[channel][bank]['entries'] += bucket.size()

        self.device.release_device_lock()

        return channel_utilization_data

    def report_lpm_hbm_channel_bank_utilization(self, count_entries=False, filename=None):

        channel_utilization_data = self.get_lpm_hbm_channel_bank_utilization_stats()
        num_channels = len(channel_utilization_data)
        num_banks = len(channel_utilization_data[0])
        count_key = 'entries' if count_entries else 'buckets'

        headers = ['Channel / Bank'] + ['Bank %d' % b for b in range(num_banks)] + ['Total %s' % count_key.capitalize()]

        channel_table_rows = []
        for channel in range(num_channels):
            row_header = 'Channel %d' % channel
            bank_data_for_this_channel = [channel_utilization_data[channel][bank][count_key] for bank in range(num_banks)]
            channel_table_rows.append([row_header] + bank_data_for_this_channel + [sum(bank_data_for_this_channel)])

        bank_sums = []
        for bank in range(num_banks):
            bank_sum = sum(channel_utilization_data[channel][bank][count_key] for channel in range(num_channels))
            bank_sums.append(bank_sum)

        bank_sum_table_row = ['Total %s' % count_key.capitalize()] + bank_sums + [sum(bank_sums)]

        table = terminaltables.AsciiTable([headers] + channel_table_rows + [bank_sum_table_row])

        fd = sys.stdout
        if filename:
            fd = open(filename, 'w')

        print(table.table, file=fd)

        if filename:
            fd.close()

    def network_prefix_to_lpm_key(self, vrf, network_prefix, encode=False):
        network = ipaddress.ip_network(network_prefix)
        is_ipv6 = (network.version == 6)
        full_prefix_length = 1 + lpm_db.VRF_LEN + network.prefixlen

        full_prefix_padded = (
            is_ipv6 << (
                lpm_db.VRF_LEN +
                network.max_prefixlen)) | (
            vrf << network.max_prefixlen) | int(
                network.network_address)
        full_prefix = full_prefix_padded >> (network.max_prefixlen - network.prefixlen)

        if (encode):
            (full_prefix, full_prefix_length) = self.encode_lpm_prefix(full_prefix, full_prefix_length)

        return (full_prefix, full_prefix_length)

    def lpm_key_to_network_prefix(self, prefix, prefix_length, decode=False):
        if decode:
            (prefix, prefix_length) = self.decode_lpm_prefix(prefix, prefix_length)

        if (prefix_length == 0):
            return None

        is_ipv6 = get_bits(prefix, prefix_length - 1, prefix_length - 1)

        if (prefix_length < lpm_db.VRF_LEN + 1):
            if (prefix_length == 1):
                return (is_ipv6, 0, 0, None)
            vrf_part = get_bits(prefix, prefix_length - 2, 0)
            return (is_ipv6, vrf_part, prefix_length - 1, None)

        vrf = get_bits(prefix, prefix_length - 2, prefix_length - lpm_db.VRF_LEN - 1)
        ip = get_bits(prefix, prefix_length - 2 - lpm_db.VRF_LEN, 0)

        full_ip_length = lpm_db.IPV6_IP_LEN if is_ipv6 else lpm_db.IPV4_IP_LEN
        prefix_ip_length = prefix_length - 1 - lpm_db.VRF_LEN

        ip = ip << (full_ip_length - prefix_ip_length)

        if is_ipv6:
            network = ipaddress.IPv6Network(ip)
        else:
            network = ipaddress.IPv4Network(ip)

        network = network.supernet(new_prefix=prefix_ip_length)

        return (is_ipv6, vrf, lpm_db.VRF_LEN, network)

    def lpm_key_to_string(self, prefix, prefix_length, decode=False):
        res = self.lpm_key_to_network_prefix(prefix, prefix_length, decode)

        if res is None:
            return '*'

        (is_ipv6, vrf, vrf_len, network) = res

        if network is None:
            return 'VRF=%d/%d Network=* (IPv%d)' % (vrf, vrf_len, 6 if is_ipv6 else 4)

        return 'VRF=%d  Network=%s' % (vrf, network.with_prefixlen)

    def get_lpm_key_info(self, key, length):
        (status, distr_node, tcam_node, l1_node, l2_node) = self._find_entry(key, length, verbose=False)
        if not status:
            return None

        group = distr_node.payload
        core_idx = self.lpm.get_core_index_by_group(group)

        l1_bucket = tcam_node.payload
        l2_bucket = l1_node.payload

        l2_location = 'SRAM' if (l2_bucket < 4096) else 'HBM'

        caching_manager = self.bucketing_tree.get_hbm_cache_manager(core_idx)
        bucket_hotness = caching_manager.get_hotness_of_bucket(l2_bucket)

        return {
            'core': core_idx,
            'l1_bucket': l1_bucket,
            'l2_bucket': l2_bucket,
            'l2_location': l2_location,
            'bucket_hotness': bucket_hotness}

    def get_hbm_caching_params(self, core_id=0):
        caching_manager = self.bucketing_tree.get_hbm_cache_manager(core_id)
        params = caching_manager.get_caching_params()
        return params

    def set_hbm_caching_params(self, params, core_ids=range(16)):
        for core_id in core_ids:
            caching_manager = self.bucketing_tree.get_hbm_cache_manager(core_id)
            caching_manager.set_caching_params(params)

    def print_hbm_caching_params(self, params):
        print("hotness_increase_on_hit_hbm = %d" % params.hotness_increase_on_hit_hbm)
        print("hotness_threshold_to_evict = %d" % params.hotness_threshold_to_evict)
        print("hotness_increase_on_hit_sram  = %d" % params.hotness_increase_on_hit_sram)
        print("initial_bucket_hotness = %d" % params.initial_bucket_hotness)
        print("usecs_until_hotness_decrease = %d" % params.usecs_until_hotness_decrease)
        print("hotness_threshold_to_cache = %d" % params.hotness_threshold_to_cache)
        print("max_buckets_to_cache = %d" % params.max_buckets_to_cache)
        print("max_hotness_level = %d" % params.max_hotness_level)

    def report_hbm_caching_statistics(self, clear_counters=False, filename=None):
        core_ids = range(16)
        caching_managers = [self.bucketing_tree.get_hbm_cache_manager(core_id) for core_id in core_ids]

        self.device.acquire_device_lock(True)
        stats_list = [cm.get_statistics(clear_counters) for cm in caching_managers]
        self.device.release_device_lock()

        table_headers = ["Stats / Core"]
        table_cachings = ["Cachings"]
        table_evictions = ["Evictions"]
        table_num_sram_buckets = ["SRAM Total Buckets"]
        table_num_hbm_buckets = ["HBM Total Buckets"]
        table_num_sram_cold_buckets = ["SRAM Cold Buckets"]
        table_num_sram_moderate_buckets = ["SRAM Moderate Buckets"]
        table_num_sram_hot_buckets = ["SRAM Hot Buckets"]
        table_num_hbm_cold_buckets = ["HBM Cold Buckets"]
        table_num_hbm_moderate_buckets = ["HBM Moderate Buckets"]
        table_num_hbm_hot_buckets = ["HBM Hot Buckets"]

        for core_idx, core in enumerate(self.lpm_cores):
            stats = stats_list[core_idx]
            table_headers.append("Core %d" % core_idx)
            table_cachings.append(stats.cachings)
            table_evictions.append(stats.evictions)
            table_num_sram_buckets.append(stats.sram_num_buckets)
            table_num_hbm_buckets.append(stats.hbm_num_buckets)
            table_num_sram_cold_buckets.append(stats.sram_num_cold_buckets)
            table_num_sram_moderate_buckets.append(stats.sram_num_moderate_buckets)
            table_num_sram_hot_buckets.append(stats.sram_num_hot_buckets)
            table_num_hbm_cold_buckets.append(stats.hbm_num_cold_buckets)
            table_num_hbm_moderate_buckets.append(stats.hbm_num_moderate_buckets)
            table_num_hbm_hot_buckets.append(stats.hbm_num_hot_buckets)

        data_rows = [
            table_cachings,
            table_evictions,
            table_num_sram_buckets,
            table_num_hbm_buckets,
            table_num_sram_cold_buckets,
            table_num_sram_moderate_buckets,
            table_num_sram_hot_buckets,
            table_num_hbm_cold_buckets,
            table_num_hbm_moderate_buckets,
            table_num_hbm_hot_buckets
        ]

        table_headers.append("Total")
        for row in data_rows:
            row.append(sum(row[1:]))

        table = terminaltables.AsciiTable([table_headers] + data_rows)

        fd = sys.stdout
        if filename:
            fd = open(filename, 'w')

        print(table.table, file=fd)

        if filename:
            fd.close()

    def hotness_level_to_char(self, caching_params, level):
        hotness_char = 'M'
        if level >= caching_params.hotness_threshold_to_cache:
            hotness_char = 'H'
        elif level < caching_params.hotness_threshold_to_evict:
            hotness_char = 'C'
        return hotness_char

    def print_hbm_caching_histograms(self, core_idxs=range(16), use_colors=False, filename=None):
        if type(core_idxs) == int:
            core_idxs = [core_idxs]
        elif core_idxs is None:
            core_idxs = []

        all_core_idxs = range(16)
        sram_total_buckets = 0
        hbm_total_buckets = 0

        num_hotness_levels = hw_tables.lpm_hbm_cache_manager.NUM_CACHING_HOTNESS_LEVELS
        caching_managers = [self.bucketing_tree.get_hbm_cache_manager(core_id) for core_id in all_core_idxs]

        self.device.acquire_device_lock(True)
        stats_list = [caching_manager.get_statistics(False) for caching_manager in caching_managers]
        self.device.release_device_lock()

        params = self.get_hbm_caching_params()

        if use_colors:
            CRED = '\033[91m'
            CYELLOW = '\033[93m'
            CBLUE = '\033[94m'
            CEND = '\033[0m'
        else:
            CRED = ''
            CYELLOW = ''
            CBLUE = ''
            CEND = ''

        colors = {'C': CBLUE, 'M': CYELLOW, 'H': CRED}

        sram_overall_hist = [0 for _ in range(num_hotness_levels)]
        hbm_overall_hist = [0 for _ in range(num_hotness_levels)]

        fd = sys.stdout
        if filename:
            fd = open(filename, 'w')

        for core_id in all_core_idxs:
            stats = stats_list[core_id]

            sram_buckets = stats.sram_num_buckets
            hbm_buckets = stats.hbm_num_buckets
            sram_total_buckets += sram_buckets
            hbm_total_buckets += hbm_buckets

            for level in range(num_hotness_levels):
                sram_overall_hist[level] += stats.sram_hotness_histogram[level]
                hbm_overall_hist[level] += stats.hbm_hotness_histogram[level]

            if core_id not in core_idxs:
                continue

            if (sram_buckets == 0) and (hbm_buckets == 0):
                continue

            print('Core %d' % core_id, file=fd)

            print('SRAM:', file=fd)

            if sram_buckets == 0:
                print('Empty', file=fd)
            else:
                for level in range(num_hotness_levels):
                    cnt = stats.sram_hotness_histogram[level]
                    if cnt > 0:
                        percentage = cnt / sram_buckets * 100
                        hotness_char = self.hotness_level_to_char(params, level)
                        print(
                            '%-4d (%s)  %-8d    %6.2f%%    %s%s%s' %
                            (level,
                             hotness_char,
                             cnt,
                             percentage,
                             colors[hotness_char],
                             '*' *
                             math.ceil(percentage),
                             CEND), file=fd)

            print('HBM:', file=fd)

            if hbm_buckets == 0:
                print('Empty', file=fd)
            else:
                for level in range(num_hotness_levels):
                    cnt = stats.hbm_hotness_histogram[level]
                    if cnt > 0:
                        percentage = cnt / hbm_buckets * 100
                        hotness_char = self.hotness_level_to_char(params, level)
                        print(
                            '%-4d (%s)  %-8d    %6.2f%%    %s%s%s' %
                            (level,
                             hotness_char,
                             cnt,
                             percentage,
                             colors[hotness_char],
                             '*' *
                             math.ceil(percentage),
                             CEND), file=fd)
                print('', file=fd)

        print('', file=fd)
        print('All cores:', file=fd)
        print('SRAM:', file=fd)

        if sram_total_buckets == 0:
            print('Emtpy', file=fd)
        else:
            for level in range(num_hotness_levels):
                cnt = sram_overall_hist[level]
                if cnt > 0:
                    percentage = cnt / sram_total_buckets * 100
                    hotness_char = self.hotness_level_to_char(params, level)
                    print(
                        '%-4d (%s)  %-8d    %6.2f%%    %s%s%s' %
                        (level,
                         hotness_char,
                         cnt,
                         percentage,
                         colors[hotness_char],
                         '|' *
                         math.ceil(percentage),
                         CEND), file=fd)

        print('HBM:', file=fd)
        if hbm_total_buckets == 0:
            print('Emtpy', file=fd)
        else:
            for level in range(num_hotness_levels):
                cnt = hbm_overall_hist[level]
                if cnt > 0:
                    percentage = cnt / hbm_total_buckets * 100
                    hotness_char = self.hotness_level_to_char(params, level)
                    print(
                        '%-4d (%s)  %-8d    %6.2f%%    %s%s%s' %
                        (level,
                         hotness_char,
                         cnt,
                         percentage,
                         colors[hotness_char],
                         '=' *
                         math.ceil(percentage),
                         CEND),
                        file=fd)

        if filename:
            fd.close()

# @brief Private data structure


class _cdb_mems:
    pass


# @brief Helper to retrieve the content of CDB databases
#
# * CEM database
#       Exact Match banks content
# * LPM database
#       TCAM + trie memory
#       L1 memory
#       L2 banks
class cdb_helper:
    LPM_TCAM_BANK_SIZE = 512

    def __init__(self, device):
        self.device = device
        self.ll_device = self.device.get_ll_device()
        self.cores = []

        device_info = get_device_revision_info(self.device)

        self.tree = device_info['device_tree']
        self.device_name_major = device_info['device_name_major']

        if self.device_name_major == 'pacific':
            self.init_core_mems_pacific()
        elif self.device_name_major == 'gibraltar':
            self.init_core_mems_gibraltar()
        else:
            raise Exception('Unknown device revision')

    def init_core_mems_pacific(self):
        NUM_CDB_CORES = 4

        for cdb_idx in range(NUM_CDB_CORES):
            for core in [self.tree.cdb.core_reduced[cdb_idx], self.tree.cdb.core[cdb_idx]]:
                for idx in [0, 1]:
                    core_mems = _cdb_mems()
                    num_tcams = len(core.lpm_tcam)
                    core_mems.lpm_tcam = []
                    core_mems.lpm_tcam.append(core.lpm_tcam[idx * (num_tcams >> 1)])
                    core_mems.lpm_tcam.append(core.lpm_tcam[idx * (num_tcams >> 1) + 1])
                    core_mems.lpm_tcam.append(core.lpm_tcam[idx * (num_tcams >> 1) + 2])
                    core_mems.lpm_tcam.append(core.lpm_tcam[idx * (num_tcams >> 1) + 3])

                    # tcam mem
                    core_mems.lpm_tcam_mem = []
                    core_mems.lpm_tcam_mem.append(core.trie_mem[idx])
                    core_mems.lpm_tcam_mem.append(core.extnd_trie_mem[idx])

                    # L1
                    core_mems.l1_mem = []
                    core_mems.l1_mem.append(core.subtrie_mem[idx])
                    core_mems.l1_mem.append(core.extnd_subtrie_mem[idx])

                    # L2/CEM banks
                    banks = [core.srams_group0, core.srams_group1]
                    core_mems.banks = banks[idx]

                    self.cores.append(core_mems)

    def init_core_mems_gibraltar(self):
        NUM_CDB_CORES = 8

        for cdb_idx in range(NUM_CDB_CORES):
            core = self.tree.cdb.core[cdb_idx]
            for idx in [0, 1]:
                core_mems = _cdb_mems()
                core_mems.lpm_tcam = core.lpm0_tcam if (idx == 0) else core.lpm1_tcam

                # tcam mem
                core_mems.lpm_tcam_mem = []
                core_mems.lpm_tcam_mem.append(core.trie_mem[idx])
                core_mems.lpm_tcam_mem.append(core.extnd_trie_mem[idx])

                # L1
                core_mems.l1_mem = []
                core_mems.l1_mem.append(core.subtrie_mem[idx])
                core_mems.l1_mem.append(core.extnd_subtrie_mem[idx])

                # L2/CEM banks
                banks = [core.srams_group0, core.srams_group1]
                core_mems.banks = banks[idx]

                self.cores.append(core_mems)

    # @Read raw content of Central Exact Match banks
    #
    # @param[in]    core_idxs       CEM cores (0..15)
    # @param[in]    bank_idxs       Exact Match banks (0..15) not allocated for LPM
    def read_cem_mem(self, core_idxs, bank_idxs, filename="./cem_data.csv"):
        print("cdb_helper::read_cem_mem writing to %s" % filename)
        fd = open(filename, "w")
        print("type, core_idx, memory, line, value", file=fd)
        for core_idx in core_idxs:
            for bank_idx in bank_idxs:
                bank = self.cores[core_idx].banks[bank_idx]
                for i in range(bank.get_desc().entries):
                    v = self.ll_device.read_memory(bank, i)
                    print('%s, %d, %s, %d, 0x%x' % ("memory", core_idx, bank.get_name(), i, v), file=fd)

        fd.close()

    # @Read raw content of LPM cores
    #
    # distributer data
    # TCAM data (lpm_tcam + trie_mem)
    # L1 data (subtrie_mem)
    # L2 data (CEM banks)
    #
    # @param[in]    core_idxs       LPM cores (0..15)
    # @param[in]    bank_idxs       Exact Match banks (0..15) allocated for LPM (starts from 0)
    def read_lpm_mem(self, core_idxs, bank_idxs, filename="./lpm_data.csv"):
        print("cdb_helper::read_cem_mem writing to %s" % filename)
        fd = open(filename, "w")
        print("type, core_idx, memory, line, value, key, mask, valid", file=fd)
        # distributer

        if self.device_name_major == 'pacific':
            mems = [self.tree.cdb.top.clpm_group_map_regs]
        elif self.device_name_major == 'gibraltar':
            mems = self.tree.cdb.top.clpm_tcam_index_to_lpm_group_map_regs
        else:
            raise Exception('Unknown device')

        for mem in mems:
            distr_entries = mem.get_desc().entries
            for i in range(distr_entries):
                v = self.ll_device.read_memory(mem, i)
                print('%s, , %s, %d, 0x%x' % ("memory", mem.get_name(), i, v), file=fd)

        for distr_tcam in self.tree.cdb.top.clpm_group_map_tcam:
            for i in range(distr_entries):
                k, m, valid = self.ll_device.read_tcam(distr_tcam, i)
                print('%s, , %s, %d, ,0x%x, 0x%x, %d' % ("tcam", distr_tcam.get_name(), i, k, m, valid), file=fd)

        # group to core mapping
        if self.device_name_major == 'pacific':
            for reg in self.tree.cdb.top.lpm_group_map_table:
                v = self.ll_device.read_register(reg)
                print('%s, , %s, , 0x%x' % ("register", reg.get_name(), v), file=fd)
        elif self.device_name_major == 'gibraltar':
            mems = self.tree.cdb.top.clpm_group_to_lpm_core_map_regs
            for mem in mems:
                entries = mem.get_desc().entries
                for i in range(entries):
                    v = self.ll_device.read_memory(mem, i)
                    print('%s, , %s, %d, 0x%x' % ("memory", mem.get_name(), i, v), file=fd)
        else:
            raise Exception('Unknown device')

        # data
        for core_idx in core_idxs:
            # TCAMs
            for idx in range(len(self.cores[core_idx].lpm_tcam)):
                tcam = self.cores[core_idx].lpm_tcam[idx]
                for i in range(1024):  # TODO understand why tcam.get_desc().entries returns 2K instead of 1K
                    k, m, valid = self.ll_device.read_tcam(tcam, i)
                    print('%s, %d, %s, %d, ,0x%x, 0x%x, %d' % ("tcam", core_idx, tcam.get_name(), i, k, m, valid), file=fd)

            # TCAM Memories
            for idx in range(len(self.cores[core_idx].lpm_tcam_mem)):
                tcam_mem = self.cores[core_idx].lpm_tcam_mem[idx]
                for i in range(tcam_mem.get_desc().entries):
                    v = self.ll_device.read_memory(tcam_mem, i)
                    print('%s, %d, %s, %d, 0x%x' % ("memory", core_idx, tcam_mem.get_name(), i, v), file=fd)

            # L1
            for idx in range(len(self.cores[core_idx].l1_mem)):
                mem = self.cores[core_idx].l1_mem[idx]
                for i in range(mem.get_desc().entries):
                    v = self.ll_device.read_memory(mem, i)
                    print('%s, %d, %s, %d, 0x%x' % ("memory", core_idx, mem.get_name(), i, v), file=fd)

            # L2
            for bank_idx in bank_idxs:
                bank = self.cores[core_idx].banks[bank_idx]
                for i in range(bank.get_desc().entries):
                    v = self.ll_device.read_memory(bank, i)
                    print('%s, %d, %s, %d, 0x%x' % ("memory", core_idx, bank.get_name(), i, v), file=fd)
        fd.close()


# @brief Wrapper class on top of swig object to allow dynamic function addition.
#
# Swig objects disable dynamic binding of object methods. Wrapper allows this.


class swig_obj_debug:

    def __init__(self, obj):
        self.obj = obj

    def __getattr__(self, item):
        return self.obj.__getattribute__(item)

# @brief Bind method to an object.
#
# @param[in]    obj     Object
# @param[in]    name    Name of the method to be bound
# @param[in]    method  Pointer to a method (function that accepts self as a first parameter)


def bind_func(obj, name, method):
    obj.__setattr__(name, types.MethodType(method, obj))


# @brief Replay ra_simulator command file.
#
# Useful to observe the exact failing write command.
def execute_cmd_file(ll_device, filename):

    print("Reading cmd file %s" % filename)
    fd = open(filename, 'r')
    lines = fd.readlines()
    fd.close()

    logfilename = './sdk_regdump.log'
    logfd = open(logfilename, 'w')

    local_addr_len = 1 << 32

    comment_regex = r'^#'
    write_mem_regex = r'^write_mem (\S+) (\S+) (\S+)$'
    write_reg_regex = r'^write_reg (\S+) (\S+) (\S+)$'
    poll_reg_regex = r'^poll_no_response (\S+) (\S+) (\S+) (\S+) (\S+)$'

    line_idx = 0
    for line in lines:
        line = line.rstrip()
        line_idx += 1

        if (line_idx % 1000) == 0:
            print("Parsing line %d" % line_idx)

        #print("%d %s" % (line_idx, line))
        match = re.search(comment_regex, line)
        if match:
            continue

        match = re.search(write_mem_regex, line)
        if match:
            addr = int(match.group(1), 16)
            local_addr = addr % local_addr_len
            block_id = int(addr / local_addr_len)
            len = int(match.group(2), 10)
            val = int(match.group(3), 16)
            print(line, file=logfd)
            ll_device.write_memory_raw(block_id, local_addr, len * 8, val)

        match = re.search(write_reg_regex, line)
        if match:
            addr = int(match.group(1), 16)
            local_addr = addr % local_addr_len
            block_id = int(addr / local_addr_len)
            len = int(match.group(2), 10)
            val = int(match.group(3), 16)
            print(line, file=logfd)
            ll_device.write_register_raw(block_id, local_addr, len * 8, val)

        match = re.search(poll_reg_regex, line)
        if match:
            addr = int(match.group(1), 16)
            local_addr = addr % local_addr_len
            block_id = int(addr / local_addr_len)
            len = int(match.group(2), 10)
            exp_val = int(match.group(3), 16)
            mask = int(match.group(4), 16)
            iterations = int(match.group(5), 10)
            print(line, file=logfd)
            for i in range(iterations):
                val = ll_device.read_register_raw(block_id, local_addr, len * 8)
                if ((val ^ exp_val) & mask) == 0:
                    continue

    logfd.close()

# @brief Class to retrieve CTM data from device.


class ctm_db:

    interface_idx_to_string = [
        "TERM",
        "FW0",
        "FW1",
        "TX0",
        "TX1"]

    YELLOW = "\033[1;33m"
    RED = "\033[1;31m"
    END = "\033[0;0m"

    def __init__(self, device):
        self.device = device
        self.ll_device = self.device.get_ll_device()
        if self.ll_device.is_pacific():
            self.device_name_major = 'pacific'
            self.tree = self.ll_device.get_pacific_tree()
        elif self.ll_device.is_gibraltar():
            self.device_name_major = 'gibraltar'
            self.tree = self.ll_device.get_gibraltar_tree()
        else:
            self.device_name_major = 'unknown'
            raise Exception('Unknown device revision')
        self.ctm_debug = None

        # table is uniquely identified by the slice_id, logical_table_type_e, and key_width.
        self.eligable_tcams_for_table_map = {}
        self.rm = sdk_debug.la_device_get_resource_manager(device)
        self.ctm_mgr = self.rm.get_ctm_mgr()
        self.ctm_config = test_racli.ctm_config_to_ctm_config_tcam(self.ctm_mgr.get_ctm_config())
        self.ring_range = range(sdk_debug.ra.NUM_RINGS)
        self.tcam_range = range(sdk_debug.ra.NUM_MEMS_PER_SUBRING * self.ctm_config.get_number_of_subrings())
        self.line_range = range(sdk_debug.ra.BANK_SIZE)
        # This dictionary should not be used outside of _get_db_meta class method
        self.db_ids_320b = {}
        self._initialize_db_ids_320b()
        self.table_names = []
        self.wide_table_names = []
        self.init_ctm_debug()
        self.interface_db_id_to_table = {ifs: {} for ifs in self.interface_idx_to_string}
        self.parse_tables_data_from_json()

    def init_ctm_debug(self):
        ctm_reader = ctm_device_reader(self.device)
        ctm_config_dict = ctm_reader.get_device_data_dict()
        self.ctm_debug = ctm_debug(ctm_config_dict)

    def parse_tables_data_from_json(self):
        DEFAULT_MICROCODE_METADATA_FILE = "res/microcode_metadata_file.json"
        DEFAULT_BASE_OUTPUT_DIR = "out/noopt-debug"

        MICROCODE_METADATA_FILE_ENVVAR = "MICROCODE_METADATA_FILE"
        BASE_OUTPUT_DIR_ENVVAR = "BASE_OUTPUT_DIR"

        MAX_DB_ID_WIDTH = 6  # Bits indices larged then this numebr will be ignored.

        meta_data_file = os.getenv(MICROCODE_METADATA_FILE_ENVVAR, DEFAULT_MICROCODE_METADATA_FILE)
        base_output_dir = os.getenv(BASE_OUTPUT_DIR_ENVVAR, DEFAULT_BASE_OUTPUT_DIR)

        tables_json_path = os.path.join(base_output_dir, meta_data_file)

        if not os.path.exists(tables_json_path):
            raise Exception(
                "Can't find tables meta data json at %s, %s can't be initiated." %
                (tables_json_path, type(self).__name__))

        with open(tables_json_path, "r") as f:
            tables_json = json.load(f)

        table_names = set()
        wide_table_names = set()
        tables_data = tables_json["tables"]
        for table_name in tables_data:
            table_desc = tables_data[table_name]

            if "network" not in table_desc.get("accessed_from_contexts", {}):
                continue

            if "external_central_tcam" not in table_desc.get("database", {}):
                continue

            assert len(table_desc["key_consts_per_opt"]) == 1, "Unexepected JSON format."

            assert len(table_desc["via_interfaces"]) == 1, "Multiple interface for tables isn't handled."

            k, m = self.parse_db_id(table_desc["key_consts_per_opt"][0], MAX_DB_ID_WIDTH)
            json_interface_name = table_desc["via_interfaces"][0]["outgoing"]["name"]
            interface = self.parse_interface(json_interface_name)
            wide = table_desc["via_interfaces"][0]["outgoing"]["parts"] == 2
            formatted_table_name = self.format_table_name(table_name)
            self.interface_db_id_to_table[interface][(k, m, wide)] = formatted_table_name
            table_names.add(formatted_table_name)
            if wide:
                wide_table_names.add(formatted_table_name)

        self.table_names = sorted(list(table_names))
        self.wide_table_names = sorted(list(wide_table_names))

    def parse_db_id(self, db_id_consts, max_width):
        k = 0
        m = 0
        for const_desc in reversed(db_id_consts):
            lsb = const_desc["lsb"]
            val = int(const_desc["value_in_hex"], 16)
            width = const_desc["width"]
            assert width > 0
            if (lsb + width) > max_width:
                continue
            k |= (val << lsb)
            m |= (2 ** width - 1) << lsb

        return k, m

    def parse_interface(self, json_interface_name):
        json_name_to_interface_name = {
            "outgoing_central_tcam_f0": "FW0",
            "outgoing_central_tcam_f1": "FW1",
            "outgoing_central_tcam_tx0": "TX0",
            "outgoing_central_tcam_tx1": "TX1",
            "outgoing_central_tcam_t": "TERM"
        }
        interface_name = json_name_to_interface_name.get(json_interface_name, None)
        if interface_name is None:
            raise Exception("Unrecognized interface in JSON.")
        return interface_name

    def format_table_name(self, table_name):
        return table_name.replace("_table", "")

    def report(self):
        print(
            ctm_db.RED +
            "CAUTION: THIS CLI IS RESOURCE INTENSIVE AND CAN CAUSE ROUTE UPDATES TO GET BLOCKED TEMPORARILY, DO NOT RUN IT PERIODICALLY. THIS IS A DEBUG CLI AND SHOULD BE RUN ONLY WHEN NECESSARY." +
            ctm_db.END)
        ring_tcam_to_table_count = self.get_entries_count_per_table()
        # Create report terminal table
        for ring_idx in self.ring_range:
            data_rows = []
            for table_name in self.table_names:
                feature_data_row = []
                feature_name = table_name
                feature_data_row.append(table_name)
                for bank_idx in self.tcam_range:
                    bank_val = ring_tcam_to_table_count[ring_idx][bank_idx].get(feature_name, "-")
                    feature_data_row.append(bank_val)
                total = sum([i for i in feature_data_row if isinstance(i, int)])
                if feature_data_row[0] in self.wide_table_names:
                    total = int(total / 2)
                feature_data_row.append(total if total > 0 else "-")
                data_rows.append(feature_data_row)
            data_rows.sort()
            data_rows = list(k for k, _ in itertools.groupby(data_rows))
            total_row = ["Total"]
            for idx in self.tcam_range:
                bank_total = 0
                for feature_data_row in data_rows:
                    val = feature_data_row[idx + 1]
                    if isinstance(val, int):
                        bank_total += val
                total_row.append("{} / 512".format(bank_total))
            total_row.append("-")
            banks_to_interface = [
                "" if self.ctm_debug.get_interface_by_tcam(
                    ring_idx,
                    bank_idx // 12,
                    bank_idx % 12)[0] == "INVL" else
                self.ctm_debug.get_interface_by_tcam(
                    ring_idx,
                    bank_idx // 12,
                    bank_idx % 12) for bank_idx in self.tcam_range]
            legend = "{:<8}/ {}\n{:<8}/ {}".format("Feature", "Bank", "", "(Slice,Interface)")
            headers = [legend] + ["Bank #{}\n{}".format(bank_idx, banks_to_interface[bank_idx])
                                  for bank_idx in self.tcam_range] + ["Total"]
            table = terminaltables.AsciiTable([headers] + data_rows + [total_row])
            print("Ring #{}".format(ring_idx))
            print(table.table)

    # Function's behavior is dependent on call order: For each TCAM pair lsb TCAM shoud be visited first.
    def _get_db_meta(self, key, ring_num, tcam_num, line_num):
        DB_META = namedtuple("DB_META", ["key", "mask", "is_wide", "out_interface", "table_name"])
        # TODO we should use subrings all over debug_utils.
        subring_idx = tcam_num // 12
        if self.ll_device.is_gibraltar():
            tcam_num = tcam_num % 12
        is_wide = False
        # if entry is 320b
        if key & 1 == 1:
            is_wide = True
            # if in msb tcam, get db id, which was previously saved from lsb tcam entry
            if self.ctm_config.is_msb_tcam(tcam_num):
                lsb_tcam_num = self.ctm_config.get_lsb_tcam(tcam_num)
                db_id = self.db_ids_320b[ring_num][lsb_tcam_num][line_num]
                return db_id

        # db_ids compared using output interface which is MSB in case of wide TCAM,
        tcam_num_for_ifs_calc = self.ctm_config.get_msb_tcam(tcam_num) if is_wide else tcam_num
        slice_idx, interface = self.ctm_debug.get_interface_by_tcam(ring_num, subring_idx, tcam_num_for_ifs_calc)

        for key_mask_wide_tuple in self.interface_db_id_to_table[interface]:
            db_k, db_m, is_db_wide = key_mask_wide_tuple
            if is_db_wide == is_wide and db_k == db_m & key:
                table_name = self.interface_db_id_to_table[interface][key_mask_wide_tuple]
                ret_db_id = DB_META(db_k, db_m, is_db_wide, interface, table_name)
                if is_wide:
                    self.db_ids_320b[ring_num][tcam_num][line_num] = ret_db_id
                return ret_db_id

        raise Exception("Couldn't find entry's db_id")

    def _get_non_lpm_tcam_content(self, ring_num, tcam_num, tcam):
        ret_list = []

        for line in self.line_range:
            key, mask, valid = self.ll_device.read_tcam(tcam, line)
            if valid:
                db_meta = self._get_db_meta(key, ring_num, tcam_num, line)
                ret_list.append({"db_meta": db_meta, "key": key, "mask": mask, "ring": ring_num, "tcam": tcam_num, "line": line})

        return ret_list

    def _get_lpm_tcam_content(self, ring_num, tcam_num, tcam1, tcam2):
        ret_list = []

        for line in self.line_range:
            key1, mask1, valid1 = self.ll_device.read_tcam(tcam1, line)
            key2, mask2, valid2 = self.ll_device.read_tcam(tcam1, line + 512)
            key3, mask3, valid3 = self.ll_device.read_tcam(tcam2, line)
            key4, mask4, valid4 = self.ll_device.read_tcam(tcam2, line + 512)
            key = key1 + (key2 << 40) + (key3 << 80) + (key4 << 120)
            mask = mask1 + (mask2 << 40) + (mask3 << 80) + (mask4 << 120)
            if valid1 and valid2 and valid3 and valid4:
                db_meta = self._get_db_meta(key, ring_num, tcam_num, line)
                ret_list.append({"db_meta": db_meta, "key": key, "mask": mask, "ring": ring_num, "tcam": tcam_num, "line": line})

        return ret_list

    def _initialize_db_ids_320b(self):
        for core_idx in self.ring_range:
            self.db_ids_320b[core_idx] = {}
            for bank_idx in self.tcam_range:
                self.db_ids_320b[core_idx][bank_idx] = {}

    def _read_tcam_content(self):
        if self.device_name_major == 'pacific':
            return self._read_tcam_content_pacific()
        elif self.device_name_major == 'gibraltar':
            return self._read_tcam_content_gibraltar()
        else:
            raise Exception('Unknown device revision')

    def _read_tcam_content_pacific(self):
        tcams_list = []
        lpm_tcam_num_banksets = self.device.get_int_property(sdk.la_device_property_e_LPM_TCAM_NUM_BANKSETS)
        for ring_num in self.ring_range:
            ring_calc = int(ring_num / 2)
            for tcam_num in self.tcam_range:
                if (ring_num % 2 == 0 and tcam_num in range(0, 4)) or (ring_num % 2 != 0 and tcam_num in range(0, 6)):
                    # can be lpm TCAM
                    is_lpm_enabled = True
                else:
                    # non LPM TCAM
                    is_lpm_enabled = False

                if is_lpm_enabled:
                    if ring_num % 2 == 0:  # full core
                        # TCAM 0 & 2 always used by lpm
                        # when in increased lpm scale mode (num banksets == 2) also TCAM 1 & 3  used by lpm
                        if tcam_num in [0, 2] or (lpm_tcam_num_banksets == 2 and tcam_num in [1, 3]):
                            continue   # ignore TCAMs used by LPM
                        tcam1 = self.tree.cdb.core_reduced[ring_calc].lpm_tcam[tcam_num * 2]
                        tcam2 = self.tree.cdb.core_reduced[ring_calc].lpm_tcam[tcam_num * 2 + 1]
                    else:  # reduced core
                        # TCAM tcam 0 & 3 always used by lpm
                        # when in increased lpm scale mode (num banksets == 2) also TCAM 1 & 4  used by lpm
                        if tcam_num in [0, 3] or (lpm_tcam_num_banksets == 2 and tcam_num in [1, 4]):
                            continue
                        tcam1 = self.tree.cdb.core[ring_calc].lpm_tcam[tcam_num * 2]
                        tcam2 = self.tree.cdb.core[ring_calc].lpm_tcam[tcam_num * 2 + 1]

                    one_tcam_list = self._get_lpm_tcam_content(ring_num, tcam_num, tcam1, tcam2)
                else:
                    if ring_num % 2 == 0:
                        tcam = self.tree.cdb.core_reduced[ring_calc].acl_tcam[tcam_num - 4]
                    else:
                        tcam = self.tree.cdb.core[ring_calc].acl_tcam[tcam_num - 6]
                    one_tcam_list = self._get_non_lpm_tcam_content(ring_num, tcam_num, tcam)
                tcams_list += one_tcam_list

        return tcams_list

    def get_eligable_tcams_for_tables(self):
        return self.eligable_tcams_for_table_map

    def get_table_key_size(self, table_id):
        return self.ctm_config.get_ctm_table_key_size(table_id)

    def print_eligable_tcams_for_tables(self):
        for slice_id in self.eligable_tcams_for_table_map:
            print("-----------------------------------------------------------------------------------------------")
            print("slice: " + str(slice_id))
            for table in self.eligable_tcams_for_table_map[slice_id]:
                key_width = self.ctm_config.get_ctm_table_key_size(table)
                table_key_width_string = "320b"
                if key_width == sdk_debug.ra.KEY_SIZE_160b:
                    table_key_width_string = "160b"
                if table in ctm_db.table_type_str_dict:
                    print(" table: " + ctm_db.table_type_str_dict[table] + " " + table_key_width_string)
                else:
                    print(" ctm table_id: " + str(table) + " " + table_key_width_string)
                for tcam in self.eligable_tcams_for_table_map[slice_id][table]:
                    print("    tcam: {ring: " + str(tcam.ring_id) + ", tcam: " + str(tcam.tcam_id) + "}")

    def _read_tcam_content_gibraltar(self):
        tcams_list = []
        lpm_tcam_num_banksets = self.device.get_int_property(sdk.la_device_property_e_LPM_TCAM_NUM_BANKSETS)
        for ring_idx in self.ring_range:
            for tcam_idx in self.tcam_range:
                if tcam_idx < sdk_debug.ra.NUM_MEMS_PER_SUBRING:
                    tcam_subring_idx = tcam_idx
                    is_subring0 = True
                else:
                    # TCAMs in subring1 are remapped with index between 12 and 23
                    tcam_subring_idx = tcam_idx - sdk_debug.ra.NUM_MEMS_PER_SUBRING
                    is_subring0 = False

                is_lpm_enabled = tcam_subring_idx in range(0, 4)
                if is_lpm_enabled:
                    if tcam_subring_idx == 0 or (lpm_tcam_num_banksets == 2 and tcam_subring_idx == 1):  # ignore TCAMs used by LPM
                        continue
                    if is_subring0:
                        tcam1 = self.tree.cdb.core[ring_idx].lpm0_tcam[tcam_subring_idx * 2]
                        tcam2 = self.tree.cdb.core[ring_idx].lpm0_tcam[tcam_subring_idx * 2 + 1]
                    else:
                        tcam1 = self.tree.cdb.core[ring_idx].lpm1_tcam[tcam_subring_idx * 2]
                        tcam2 = self.tree.cdb.core[ring_idx].lpm1_tcam[tcam_subring_idx * 2 + 1]
                    one_tcam_list = self._get_lpm_tcam_content(ring_idx, tcam_idx, tcam1, tcam2)
                else:
                    if is_subring0:
                        tcam = self.tree.cdb.core[ring_idx].ring0_acl_tcam[tcam_subring_idx - 4]
                    else:
                        tcam = self.tree.cdb.core[ring_idx].ring1_acl_tcam[tcam_subring_idx - 4]
                    one_tcam_list = self._get_non_lpm_tcam_content(ring_idx, tcam_idx, tcam)
                tcams_list += one_tcam_list

        return tcams_list

    def _print_tcam_content(self, tcam_list, filename=None):
        print("Writing Central TCAM content to %s" % filename)
        fd = open(filename, "w")
        for ent in tcam_list:
            ring_num = ent["ring"]
            tcam_num = ent["tcam"]
            line_num = ent["line"]
            db_id = ent["db_meta"].key
            key = ent["key"]
            mask = ent["mask"]
            print("ring:{0} tcam:{1} line:{2} db id:{3} - {4}/{5}".format(ring_num,
                                                                          tcam_num, line_num, db_id, hex(key), hex(mask)), file=fd)
        fd.close()

    def read_and_dump(self, filename="./ctm_db.txt"):
        print(
            ctm_db.RED +
            "CAUTION: THIS CLI IS RESOURCE INTENSIVE AND CAN CAUSE ROUTE UPDATES TO GET BLOCKED TEMPORARILY, DO NOT RUN IT PERIODICALLY. THIS IS A DEBUG CLI AND SHOULD BE RUN ONLY WHEN NECESSARY." +
            ctm_db.END)
        tcam_entry_list = self._read_tcam_content()
        self._print_tcam_content(tcam_entry_list, filename)

    def report_hw_usage(self):
        print(
            ctm_db.RED +
            "CAUTION: THIS CLI IS RESOURCE INTENSIVE AND CAN CAUSE ROUTE UPDATES TO GET BLOCKED TEMPORARILY, DO NOT RUN IT PERIODICALLY. THIS IS A DEBUG CLI AND SHOULD BE RUN ONLY WHEN NECESSARY." +
            ctm_db.END)
        tcam_entry_list = self._read_tcam_content()
        rings_tcam_dict = {}
        for ring in self.ring_range:
            # TODO subrings
            for bank in self.tcam_range:
                ring_dict = rings_tcam_dict.get(ring, {})
                ring_dict[bank] = 0
                rings_tcam_dict[ring] = ring_dict
        for ent in tcam_entry_list:
            ring = ent["ring"]
            bank = ent["tcam"]
            rings_tcam_dict[ring][bank] = rings_tcam_dict[ring][bank] + 1
        headers = ["Ring #"] + ["Bank #{}".format(i) for i in self.tcam_range]
        rows = [headers]
        for ring in range(8):
            ring_list = ["ring #{}".format(ring)]
            for bank in self.tcam_range:
                used = (3 - len(str(rings_tcam_dict[ring][bank]))) * "0" + str(rings_tcam_dict[ring][bank])
                ring_list.append(used + " / 512")
            rows.append(ring_list)
        table = terminaltables.AsciiTable(rows)
        print(table.table)

    def get_entries_count_per_table(self):
        tcam_entries = self._read_tcam_content()
        entry_to_feature_per_ring = {ring_idx: {tcam_idx: {} for tcam_idx in self.tcam_range} for ring_idx in self.ring_range}

        for entry in tcam_entries:
            ring_idx = entry["ring"]
            tcam_idx = entry["tcam"]
            db_meta = entry["db_meta"]
            out_interface = db_meta.out_interface
            table_name = db_meta.table_name
            entry_to_feature_per_ring[ring_idx][tcam_idx][table_name] = entry_to_feature_per_ring[ring_idx][tcam_idx].get(
                table_name, 0) + 1
        return entry_to_feature_per_ring


# @brief Wrapper class for the device's CTM configuration registers.
class ctm_registers_arrays:
    def __init__(self):
        # key_channel_interface[ring_idx] is the register that saves the
        # interfaces of the ring_idx key channels (in ascending order)
        self.key_channel_interface = []
        # tcams[ring_idx][subring_idx][i] is the register that saves the key and
        # the hit channel of the i'th tcam in subring_idx in ring_idx
        self.tcams = []
        # srams[ring_idx][subring_idx][i] is the register that saved the tcams and
        # the hit channel of the i'th sram in subring_idx in ring_idx
        self.srams = []
        # res_channels_sram[ring_idx][subring_idx][i] is the register that saves
        # the srams of the i'th res channel in subring_idx in ring_idx
        self.res_channels_srams = []
        # slice_res_channels[slice_idx] is the register that saves the res channels that connected to the slice_idx slice interfaces
        self.slice_res_channels = []
        # m_dbm_rings[merger_idx] is the register that saves the mapping of the merger_idx merger ring
        self.m_dbm_rings = []
        # lpm_tcams[ring_idx][subring_idx][i] is the register that saves if the tcam i/2 is for lpm.
        self.lpm_tcams = []


class subring:
    def __init__(self):
        self.key_channel_to_interface = []
        self.lpm_tcams = []
        self.tcam_to_key_channel = []
        self.tcam_to_hit_channel = []
        self.tcam_content = []
        self.sram_to_tcam = []
        self.sram_to_hit_channel = []
        self.sram_to_res_channel = []
        self.sram_is_msb = []
        self.res_channel_to_interface = []
        self.tcam_pairs = []


class ctm_debug:
    INVALID_CHANNEL = 7

    def __init__(self, ctm_data_dict):
        self.ctm_data = ctm_data_dict

    def get_interface_by_tcam(self, ring_idx, subring_idx, tcam_idx):
        key_channel = self.ctm_data["rings"][ring_idx][subring_idx].tcam_to_key_channel[tcam_idx]
        if key_channel == self.INVALID_CHANNEL:
            return ("INVL", 0)
        interface_stage = self.ctm_data["rings"][ring_idx][subring_idx].key_channel_to_interface[key_channel]["stage"]
        interface_slice = self.ctm_data["rings"][ring_idx][subring_idx].key_channel_to_interface[key_channel]["slice"]
        return (interface_slice, interface_stage)


# @brief retriving the device TCAM configuration
class ctm_device_reader:

    NUM_OF_RINGS = 8
    NUM_OF_SLICES = 6
    NUM_OF_MERGERS = 4
    NUM_OF_INTERFACES = 5
    NUM_OF_KEY_CHANNELS = 5
    NUM_TCAMS_PER_SUBRING = 12
    INTERFACE_NUM_TO_NAME = {0: "TERM", 1: "FW0", 2: "FW1", 3: "TX0", 4: "TX1"}

    def __init__(self, device):

        self.ll_device = device.get_ll_device()

        self.registers_arrays = ctm_registers_arrays()

        self.rings_res_channels_to_interface = [{} for ring in range(self.NUM_OF_RINGS)]
        self.dbm_res_channels_to_interface = {0: [], 1: [], 2: [], 3: []}

        if self.ll_device.is_pacific():
            self.tree = self.ll_device.get_pacific_tree()
            self.num_of_subrings = 1
            self.init_registers_arrays_pacific()
        elif self.ll_device.is_gibraltar():
            self.tree = self.ll_device.get_gibraltar_tree()
            self.num_of_subrings = 2
            self.init_registers_arrays_gibraltar()
        else:
            raise Exception('Unknown device revision')

        self.init_rings_res_channels_to_interface()
        rings_array = self.create_rings_array()
        merger_to_rings_map = self.get_merger_to_rings_mapping()
        self.hw_data_dict = self.create_hw_dict(rings_array, merger_to_rings_map, self.dbm_res_channels_to_interface)

    # @brief fiiling self.registers_arrays fields for a pacific device
    def init_registers_arrays_pacific(self):

        # fiiling self.registers_array.m_dbm_rings
        self.registers_arrays.m_dbm_rings = self.tree.cdb.top.dbm_join_rings

        # filling self.registers_arrays.key_channel_interface
        self.registers_arrays.key_channel_interface = self.tree.cdb.top.ring_channel_select

        # filling self.registers_arrays.tcams, self.registers_arrays.srams,
        # registers_arrays.res_channels_srams , registers_arrays.lpm_tcams
        all_rings_tcams = []
        all_rings_srams = []
        all_rings_res_channels = []
        all_rings_lpm_tcams = []
        for ring_idx in range(self.NUM_OF_RINGS // 2):
            for ring in [self.tree.cdb.core_reduced[ring_idx], self.tree.cdb.core[ring_idx]]:
                ring_tcams = []
                subring_tcams = ring.ctm_ring_tcams_cfg
                ring_tcams.append(subring_tcams)
                all_rings_tcams.append(ring_tcams)
                ring_srams = []
                subring_srams = ring.ctm_ring_srams_cfg
                ring_srams.append(subring_srams)
                all_rings_srams.append(ring_srams)
                ring_res_channels = []
                subring_res_channels = ring.ctm_ring_result_channel_sram_sel
                ring_res_channels.append(subring_res_channels)
                all_rings_res_channels.append(ring_res_channels)
                ring_lpm_tcams = []
                subring_lpm_tcams = ring.lpm_tcam_for_ctm
                ring_lpm_tcams.append(subring_lpm_tcams)
                all_rings_lpm_tcams.append(ring_lpm_tcams)
        self.registers_arrays.tcams = all_rings_tcams
        self.registers_arrays.srams = all_rings_srams
        self.registers_arrays.res_channels_srams = all_rings_res_channels
        self.registers_arrays.lpm_tcams = all_rings_lpm_tcams

        # filling self.registers_arrays.slice_res_channels
        self.registers_arrays.slice_res_channels = self.tree.cdb.top.slice_result_index_select

    # @brief fiiling self.registers_arrays fields for a pacific device
    def init_registers_arrays_gibraltar(self):

        # fiiling self.registers_array.m_dbm_rings
        self.registers_arrays.m_dbm_rings = self.tree.cdb.top.dbm_join_rings

        # filling self.registers_arrays.key_channel_interface
        self.registers_arrays.key_channel_interface = self.tree.cdb.top.ring_channel_select

        # self.registers_arrays.tcams, self.registers_arrays.srams, self.registers_arrays.res_channels_srams , registers_arrays.lpm_tcams
        all_rings_tcams = []
        all_rings_srams = []
        all_rings_res_channels = []
        all_rings_lpm_tcams = []
        for ring_idx in range(self.NUM_OF_RINGS):
            ring = self.tree.cdb.core[ring_idx]
            ring_tcams = []
            subring0_tcams = ring.ctm_ring0_tcams_cfg
            ring_tcams.append(subring0_tcams)
            subring1_tcams = ring.ctm_ring1_tcams_cfg
            ring_tcams.append(subring1_tcams)
            all_rings_tcams.append(ring_tcams)
            ring_srams = []
            subring0_srams = ring.ctm_ring0_srams_cfg
            ring_srams.append(subring0_srams)
            subring1_srams = ring.ctm_ring1_srams_cfg
            ring_srams.append(subring1_srams)
            all_rings_srams.append(ring_srams)
            ring_res_channels = []
            subring0_res_channels = ring.ctm_ring0_result_channel_sram_sel
            ring_res_channels.append(subring0_res_channels)
            subring1_res_channels = ring.ctm_ring1_result_channel_sram_sel
            ring_res_channels.append(subring1_res_channels)
            all_rings_res_channels.append(ring_res_channels)
            ring_lpm_tcams = []
            subring0_lpm_tcams = ring.lpm0_tcam_for_ctm
            ring_lpm_tcams.append(subring0_lpm_tcams)
            subring1_lpm_tcams = ring.lpm1_tcam_for_ctm
            ring_lpm_tcams.append(subring1_lpm_tcams)
            all_rings_lpm_tcams.append(ring_lpm_tcams)
        self.registers_arrays.tcams = all_rings_tcams
        self.registers_arrays.srams = all_rings_srams
        self.registers_arrays.res_channels_srams = all_rings_res_channels
        self.registers_arrays.lpm_tcams = all_rings_lpm_tcams

        # filling self.registers_arrays.slice_res_channels
        self.registers_arrays.slice_res_channels = self.tree.cdb.top.slice_result_index_select

     # @brief fiiling rings_res_channels_to_interface
    def init_rings_res_channels_to_interface(self):
        RESULT_SELECT_WIDTH = 6
        for slice_idx in range(self.NUM_OF_SLICES):
            slice_reg = self.registers_arrays.slice_res_channels[slice_idx]
            reg_data = self.ll_device.read_register(slice_reg)
            for interface_idx in range(self.NUM_OF_INTERFACES):
                abs_res_channel = get_bits(reg_data,
                                           RESULT_SELECT_WIDTH * (interface_idx + 1) - 1,
                                           RESULT_SELECT_WIDTH * interface_idx)
                if abs_res_channel <= 39:
                    ring_number = abs_res_channel // self.NUM_OF_KEY_CHANNELS
                    res_channel_number = abs_res_channel % self.NUM_OF_INTERFACES
                    self.rings_res_channels_to_interface[ring_number][res_channel_number] = (
                        slice_idx, self.INTERFACE_NUM_TO_NAME[interface_idx])
                if (abs_res_channel >= 40) and (abs_res_channel <= 43):
                    self.dbm_res_channels_to_interface[abs_res_channel -
                                                       40] = (slice_idx, self.INTERFACE_NUM_TO_NAME[interface_idx])

    def find_1_indexes(self, number):
        indexes_list = [i for i in range(number.bit_length()) if number & (1 << i)]
        return indexes_list

    def get_wide_tcam_offset(self):
        if self.ll_device.is_pacific():
            return 6
        else:
            return 1

    def is_lsb_tcam(self, tcam):
        if self.ll_device.is_pacific():
            return (tcam < 6)
        else:
            return ((tcam % 2) == 0)

    def get_non_lpm_tcam_content(self, ring_num, tcam_num, tcam):
        ret_list = []
        for line in range(sdk_debug.ra.BANK_SIZE):
            key, mask, valid = self.ll_device.read_tcam(tcam, line)
            if valid:
                ret_list.append({"key": key, "mask": mask, "line": line})
        return ret_list

    def get_lpm_tcam_content(self, ring_num, tcam_num, tcam1, tcam2):
        ret_list = []
        for line in range(sdk_debug.ra.BANK_SIZE):
            key1, mask1, valid1 = self.ll_device.read_tcam(tcam1, line)
            key2, mask2, valid2 = self.ll_device.read_tcam(tcam1, line + 512)
            key3, mask3, valid3 = self.ll_device.read_tcam(tcam2, line)
            key4, mask4, valid4 = self.ll_device.read_tcam(tcam2, line + 512)
            key = key1 + (key2 << 40) + (key3 << 80) + (key4 << 120)
            mask = mask1 + (mask2 << 40) + (mask3 << 80) + (mask4 << 120)
            is_valid = valid1 and valid2 and valid3 and valid4
            if is_valid:
                ret_list.append({"key": key, "mask": mask, "line": line})

        return ret_list

    def get_tcam_content_pacific(self, subring, ring_idx, sunring_idx):
        tcams_content = {}
        ring_calc = int(ring_idx / 2)
        for tcam_num in range(self.NUM_TCAMS_PER_SUBRING):
            if (ring_idx % 2 == 0 and tcam_num in range(0, 4)) or (ring_idx %
                                                                   2 != 0 and tcam_num in range(0, 6)):  # can be lpm TCAM
                is_lpm_ctm_shared_tcam = True
            else:  # non LPM TCAM
                is_lpm_ctm_shared_tcam = False
            if is_lpm_ctm_shared_tcam:
                if tcam_num in subring.lpm_tcams:
                    continue  # ignore TCAMs used by LPM
                elif ring_idx % 2 == 0:  # full core
                    tcam1 = self.tree.cdb.core_reduced[ring_calc].lpm_tcam[tcam_num * 2]
                    tcam2 = self.tree.cdb.core_reduced[ring_calc].lpm_tcam[tcam_num * 2 + 1]
                else:  # reduced core
                    tcam1 = self.tree.cdb.core[ring_calc].lpm_tcam[tcam_num * 2]
                    tcam2 = self.tree.cdb.core[ring_calc].lpm_tcam[tcam_num * 2 + 1]
                one_tcam_list = self.get_lpm_tcam_content(ring_idx, tcam_num, tcam1, tcam2)
            else:
                if ring_idx % 2 == 0:
                    tcam = self.tree.cdb.core_reduced[ring_calc].acl_tcam[tcam_num - 4]
                else:
                    tcam = self.tree.cdb.core[ring_calc].acl_tcam[tcam_num - 6]
                one_tcam_list = self.get_non_lpm_tcam_content(ring_idx, tcam_num, tcam)
            tcams_content[tcam_num]  = one_tcam_list
        return tcams_content

    def get_tcam_content_gibraltar(self, subring, ring_idx, subring_idx):
        tcams_content = {}
        for tcam_num in range(self.NUM_TCAMS_PER_SUBRING):
            is_lpm_ctm_shared_tcam = tcam_num in range(0, 4)
            if is_lpm_ctm_shared_tcam:
                if tcam_num in subring.lpm_tcams:
                    continue  # ignore TCAMs used by LPM
                if subring_idx == 0:
                    tcam1 = self.tree.cdb.core[ring_idx].lpm0_tcam[tcam_num * 2]
                    tcam2 = self.tree.cdb.core[ring_idx].lpm0_tcam[tcam_num * 2 + 1]
                else:
                    tcam1 = self.tree.cdb.core[ring_idx].lpm1_tcam[tcam_num * 2]
                    tcam2 = self.tree.cdb.core[ring_idx].lpm1_tcam[tcam_num * 2 + 1]
                one_tcam_list = self.get_lpm_tcam_content(ring_idx, tcam_num, tcam1, tcam2)
            else:
                if subring_idx == 0:
                    tcam = self.tree.cdb.core[ring_idx].ring0_acl_tcam[tcam_num - 4]
                else:
                    tcam = self.tree.cdb.core[ring_idx].ring1_acl_tcam[tcam_num - 4]
                one_tcam_list = self.get_non_lpm_tcam_content(ring_idx, tcam_num, tcam)
            tcams_content[tcam_num] = one_tcam_list
        return tcams_content

    def create_key_channel_to_interface(self, ring_idx):
        key_channel_to_interface = {}
        KEY_CHANNEL_WIDTH = 5
        key_channel_to_interface_reg = self.registers_arrays.key_channel_interface[ring_idx]
        reg_data = self.ll_device.read_register(key_channel_to_interface_reg)
        for key_channel_num in range(self.NUM_OF_KEY_CHANNELS):
            abs_interface = get_bits(reg_data, KEY_CHANNEL_WIDTH * (key_channel_num + 1) - 1, KEY_CHANNEL_WIDTH * key_channel_num)
            if abs_interface > self.NUM_OF_SLICES * self.NUM_OF_INTERFACES:
                interface_slice = {"stage": "INVL", "slice": 0}
            else:
                slice_num = abs_interface // self.NUM_OF_KEY_CHANNELS
                interface_name = self.INTERFACE_NUM_TO_NAME[abs_interface % self.NUM_OF_INTERFACES]
                interface_slice = {"stage": interface_name, "slice": slice_num}
            key_channel_to_interface[key_channel_num] = interface_slice
        return key_channel_to_interface

    def get_lpm_tcams(self, ring_idx, subring_idx):
        lpm_tcams = []
        num_of_registers = len(self.registers_arrays.lpm_tcams[ring_idx][subring_idx])
        for i in range(num_of_registers):
            tcam_reg = self.registers_arrays.lpm_tcams[ring_idx][subring_idx][i]
            reg_data = self.ll_device.read_register(tcam_reg)
            is_lpm = get_bits(reg_data, 0, 0)
            if is_lpm == 0 and i // 2 not in lpm_tcams:
                lpm_tcams.append(i // 2)
        return lpm_tcams

    def get_tcam_hit_and_key_channels(self, ring_idx, subring_idx):
        tcam_to_key_channel = {}
        tcam_to_hit_channel = {}
        num_of_tcams = len(self.registers_arrays.tcams[ring_idx][subring_idx])
        for i in range(num_of_tcams):
            tcam_reg = self.registers_arrays.tcams[ring_idx][subring_idx][i]
            reg_data = self.ll_device.read_register(tcam_reg)
            key_channel_for_tcam = get_bits(reg_data, 2, 0)
            if self.ll_device.is_pacific():
                hit_channel_for_tcam = get_bits(reg_data, 5, 3)
            else:  # GB
                hit_channel_for_tcam = get_bits(reg_data, 7, 5)
            tcam_to_key_channel[i] = key_channel_for_tcam
            tcam_to_hit_channel[i] = hit_channel_for_tcam
        return (tcam_to_key_channel, tcam_to_hit_channel)

    def get_sram_tcam_tcam_and_hit_channel(self, ring_idx, subring_idx):
        sram_to_tcam = {}
        sram_to_hit_channel = {}
        num_of_srams = len(self.registers_arrays.srams[ring_idx][subring_idx])
        for i in range(num_of_srams):
            sram_reg = self.registers_arrays.srams[ring_idx][subring_idx][i]
            reg_data = self.ll_device.read_register(sram_reg)
            first_half_tcam = get_bits(reg_data, 3, 0)
            second_half_tcam = get_bits(reg_data, 7, 4)
            both_tcams = [first_half_tcam, second_half_tcam]
            first_half_hit_channel = get_bits(reg_data, 10, 8)
            second_half_hit_channel = get_bits(reg_data, 13, 11)
            both_hit_channel = [first_half_hit_channel, second_half_hit_channel]
            sram_to_tcam[i] = both_tcams
            sram_to_hit_channel[i] = both_hit_channel
        return (sram_to_tcam, sram_to_hit_channel)

    def get_sram_result_mapping(self, ring_idx, subring_idx):
        sram_to_res_channel = {}
        sram_is_msb = {}
        num_of_res_channels = len(self.registers_arrays.res_channels_srams[ring_idx][subring_idx])
        for i in range(num_of_res_channels):
            res_channel_reg = self.registers_arrays.res_channels_srams[ring_idx][subring_idx][i]
            reg_data = self.ll_device.read_register(res_channel_reg)
            lsb_sram_dec = get_bits(reg_data, 11, 0)
            lsb_srams = self.find_1_indexes(lsb_sram_dec)
            msb_sram_dec = get_bits(reg_data, 23, 12)
            msb_srams = self.find_1_indexes(msb_sram_dec)
            for lsb_sram in lsb_srams:
                sram_to_res_channel[lsb_sram] = i
                sram_is_msb[lsb_sram] = 0
            for msb_sram in msb_srams:
                sram_to_res_channel[msb_sram] = i
                sram_is_msb[msb_sram] = 1
        return (sram_to_res_channel, sram_is_msb)

    def get_res_channel_to_interface_mapping(self, ring_idx):
        res_channel_to_interface = {}
        ring_dict = self.rings_res_channels_to_interface[ring_idx]
        for i in ring_dict.keys():
            slice_num = (ring_dict[i])[0]
            interface_name = (ring_dict[i])[1]
            interface_slice = {"stage": interface_name, "slice": slice_num}
            res_channel_to_interface[i] = interface_slice
        return res_channel_to_interface

    def create_tcams_pairs(self, subring):
        INVALID_CHANNEL = 7
        tcams_pairs_subring = []
        offset = self.get_wide_tcam_offset()
        for tcam in range(self.NUM_TCAMS_PER_SUBRING):
            if self.is_lsb_tcam(tcam):
                if subring.tcam_to_key_channel[tcam] != INVALID_CHANNEL and subring.tcam_to_key_channel[tcam +
                                                                                                        offset] != INVALID_CHANNEL:
                    interface_low = subring.key_channel_to_interface[subring.tcam_to_key_channel[tcam]]
                    interface_high = subring.key_channel_to_interface[subring.tcam_to_key_channel[tcam + offset]]
                    if interface_low["slice"] == interface_high["slice"]:
                        if (interface_high["stage"] == "FW0" and interface_low["stage"] == "FW1") or (
                                interface_high["stage"] == "TX0" and interface_low["stage"] == "TX1"):
                            tcams_pairs_subring.append((tcam, tcam + offset))

        return tcams_pairs_subring

    # @brief creates ring object that is going to be  written to json file
    def create_subring(self, ring_idx, subring_idx):
        subring_to_return = subring()
        subring_to_return.key_channel_to_interface = self.create_key_channel_to_interface(ring_idx)
        subring_to_return.tcam_to_key_channel = self.get_tcam_hit_and_key_channels(ring_idx, subring_idx)[0]
        subring_to_return.tcam_to_hit_channel = self.get_tcam_hit_and_key_channels(ring_idx, subring_idx)[1]
        subring_to_return.sram_to_tcam = self.get_sram_tcam_tcam_and_hit_channel(ring_idx, subring_idx)[0]
        subring_to_return.sram_to_hit_channel = self.get_sram_tcam_tcam_and_hit_channel(ring_idx, subring_idx)[1]
        subring_to_return.sram_to_res_channel = self.get_sram_result_mapping(ring_idx, subring_idx)[0]
        subring_to_return.sram_is_msb = self.get_sram_result_mapping(ring_idx, subring_idx)[1]
        subring_to_return.res_channel_to_interface = self.get_res_channel_to_interface_mapping(ring_idx)
        subring_to_return.lpm_tcams = self.get_lpm_tcams(ring_idx, subring_idx)
        if self.ll_device.is_pacific():
            subring_to_return.tcam_content = self.get_tcam_content_pacific(subring_to_return, ring_idx, subring_idx)
        else:
            subring_to_return.tcam_content = self.get_tcam_content_gibraltar(subring_to_return, ring_idx, subring_idx)
        subring_to_return.tcam_pairs = self.create_tcams_pairs(subring_to_return)
        return subring_to_return

    def create_rings_array(self):
        rings_array = []
        NUM_OF_SUBRINGS = self.num_of_subrings
        for ring_idx in range(self.NUM_OF_RINGS):
            ring = {}
            for subring_idx in range(NUM_OF_SUBRINGS):
                subring = self.create_subring(ring_idx, subring_idx)
                ring[subring_idx] = subring
            rings_array.append(ring)
        return rings_array

    def get_merger_to_rings_mapping(self):
        all_mergers = []
        for merger_idx in range(self.NUM_OF_MERGERS):
            merger_rings = []
            merger_reg = self.registers_arrays.m_dbm_rings[merger_idx]
            reg_data = self.ll_device.read_register(merger_reg)
            dec_representation = get_bits(reg_data, 8, 0)
            merger_rings = self.find_1_indexes(dec_representation)
            all_mergers.append(merger_rings)
        return all_mergers

    def create_hw_dict(self, list_of_rings, list_of_mergers, dbm_res_channel):
        rings = {}
        db_merger = {}
        db_merger_interfaces = dbm_res_channel
        # changing rings and mergers lists into a dictionary
        for i in range(len(list_of_rings)):
            rings[i] = list_of_rings[i]
        for i in range(len(list_of_mergers)):
            db_merger[i] = list_of_mergers[i]
        hw_dict = {"rings": rings, "db_merger": db_merger, "db_merger_interfaces": db_merger_interfaces}
        return hw_dict

    def get_device_data_dict(self):
        data_dict = self.hw_data_dict
        return data_dict
