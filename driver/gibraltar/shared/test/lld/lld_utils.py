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
import test_lldcli
import sys
import os
import subprocess
import uuid


RAM_DISK_PATH = '/dev/shm/'


def __dump_block_recursively(dumpfd, ll_device, block):
    is_valid = block.is_valid()
    block_name = block.get_name()
    block_id = block.get_block_id() if is_valid else -1
    level = "+" * len(block_name.split("."))
    print("{0} block(name={1}, id={2})".format(level, block_name, block_id), file=dumpfd)

    for reg in block.get_registers():
        reg_desc = reg.get_desc()

        if reg_desc.is_volatile():
            continue

        value = ll_device.read_register(reg)
        reg_name = reg.get_name()
        level = "+" * len(reg_name.split("."))
        print("{0} register(name={1}, value=0x{2:X})".format(level, reg_name, value), file=dumpfd)

    for mem in block.get_memories():
        mem_desc = mem.get_desc()
        if not mem_desc.readable:
            continue

        if mem_desc.is_volatile():
            continue

        entries = mem.get_desc().entries
        mem_name = mem.get_name()

        for entry_num in range(entries):
            value = ll_device.read_memory(mem, entry_num)
            level = "+" * len(mem_name.split("."))
            print("{0} memory(name={1}, entry_num={2:3}, value=0x{3:X}) ".format(level, mem_name, entry_num, value), file=dumpfd)

    for child_block in block.get_blocks():
        __dump_block_recursively(dumpfd, ll_device, child_block)


def dump_device_tree(device_tree, ll_device, dump_filename=None):
    if dump_filename is not None:
        dumpfd = open(dump_filename, "w")
    else:
        dumpfd = sys.stdout

    for block in device_tree.get_blocks():
        __dump_block_recursively(dumpfd, ll_device, block)

    if dump_filename is not None:
        dumpfd.close()


def dump_interrupt_tree(interrupt_tree, dump_filename=None):
    interrupt_tree.dump_tree(True, True, dump_filename)


def bitmask_ones(ones):
    return ((1 << ones) - 1)


def is_warm_boot_supported():
    return not test_lldcli.is_clang_compilation() and test_lldcli.is_serialization_supported()


def get_warm_boot_file_name():
    # get name of WB serialization file;
    # if RAM disk is available, file will be created on RAM disk;
    # otherwise, file will be created in /tmp/
    if os.path.exists(RAM_DISK_PATH):
        filename = os.path.join(RAM_DISK_PATH, str(uuid.uuid4())) + '.warm_boot'
        while os.path.exists(filename):
            filename = os.path.join(RAM_DISK_PATH, str(uuid.uuid4())) + '.warm_boot'
    else:
        sys.stdout.write('WARNING: RAM disk {} not available, WB serialization file will be created in /tmp/\n'.format(RAM_DISK_PATH))
        sys.stdout.flush()
        filename = os.path.join('/tmp/', str(uuid.uuid4())) + '.warm_boot'
        while os.path.exists(filename):
            filename = os.path.join('/tmp/', str(uuid.uuid4())) + '.warm_boot'

    return filename
