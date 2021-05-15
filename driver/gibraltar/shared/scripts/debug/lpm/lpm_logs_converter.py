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
from lpm_hw_to_logic_converter_base import lpm_distributor_entry, lpm_tcam_entry, lpm_bucket, lpm_entry, lpm_default, lpm_prefix, lpm_hw_to_logic_converter_base
from bit_utils import get_bits
from lpm_hw_to_logic_converter_pacific import lpm_hw_to_logic_converter_pacific

NUMBER_OF_CORES = 16
DISTRIBUTOR_TCAM_NUMBER_OF_ROWS = 128
TCAM_MAX_CORE_ENTRIES = 2048
L1_NUMBER_OF_BUCKETS = 1024 * 4
L2_NUMBER_OF_BUCKETS = 4096 + 12 * 1024


class lpm_logs_converter(lpm_hw_to_logic_converter_base):

    def __init__(self, logs_file):
        self.distributor = {}
        self.cores = [lpm_core() for _ in range(NUMBER_OF_CORES)]

        # Set TCAM defaults since it's not printed to logs.
        for core in self.cores:
            core.tcam[511] = lpm_tcam_entry(lpm_prefix(1, 1), valid=True, payload=0, hit_width=1)
            core.tcam[2047] = lpm_tcam_entry(lpm_prefix(0, 1), valid=True, payload=0, hit_width=1)

        distributor_to_group = {}
        group_to_core = {}
        with open(logs_file, "r") as fd:

            for lno, line in enumerate(fd):

                m = None

                if m is None and 'set_distributor_line' in line:
                    m = re.match(
                        '.*set_distributor_line\(line after offset = (?P<line>([0-9]*)), key = (?P<key>([0-9a-f]*)), key width = (?P<width>([0-9]*)), payload = (0x)?(?P<payload>([0-9a-f]*)).*',
                        line)
                    if m is not None:
                        row = int(m['line'], 10)
                        key = int(m['key'], 16)
                        width = int(m['width'], 10)
                        payload = int(m['payload'], 16)
                        distributor_to_group[row] = {'key': key, 'width': width, 'payload': payload, 'valid': True}

                if m is None and 'assigning group' in line:
                    m = re.match('.*assigning group (?P<group>([0-9]*)) to core (?P<core>([0-9]*))', line)
                    if m is not None:
                        group = int(m['group'], 10)
                        core = int(m['core'], 10)
                        group_to_core[group] = core

                if m is None and 'remove_distributor_line' in line:
                    m = re.match('.*remove_distributor_line\(line after offset = (?P<line>([0-9]*)).*', line)
                    if m is not None:
                        row = int(m['line'], 10)
                        if row in distributor_to_group.keys():
                            distributor_to_group[row]['valid'] = False
                        else:
                            print('ERROR: Distributer removing an invalid row %d  [log file line %d]' % (row, lno))
                            return

                if m is None and 'TCAM Wr' in line:
                    m = re.match(
                        '.*LPM: TCAM Wr *core = (?P<core>([0-9]*)) *row = (?P<row>([0-9]*)) *key = 0x(?P<key>([0-9a-f]*)) *key width = (?P<width>([0-9]*)) *payload = (?P<payload>([0-9]*))',
                        line)
                    if m is not None:
                        core = int(m['core'], 10)
                        row = int(m['row'], 10)
                        key_value = int(m['key'], 16)
                        width = int(m['width'], 10)
                        payload = int(m['payload'], 10)
                        key = lpm_prefix(key_value, width)
                        self.cores[core].tcam[row] = lpm_tcam_entry(key=key, valid=True, payload=payload, hit_width=width)

                if m is None and 'TCAM Iv' in line:
                    m = re.match('.*LPM: TCAM Iv *core = (?P<core>([0-9]*)) *row = (?P<row>([0-9]*))', line)
                    if m is not None:
                        core = int(m['core'], 10)
                        row = int(m['row'], 10)
                        if row in self.cores[core].tcam and self.cores[core].tcam[row].valid is True:
                            self.cores[core].tcam[row].valid = False
                        else:
                            print('WARNING: TCAM Invalidation of already invalid row %d  [log file line %d]' % (row, lno))

                if m is None and 'Write L' in line:
                    m = re.match(
                        '.*LPM Core (?P<core>([0-9]*)) Write L(?P<tree>([1-2])) Bucket Line (?P<line>([0-9]*))  #Nodes (?P<nnodes>([0-9]*))  root width (?P<rwidth>([0-9]*)):',
                        line)
                    if m is not None:
                        current_core = int(m['core'], 10)
                        current_tree = int(m['tree'])
                        current_row = int(m['line'], 10)
                        root_width = int(m['rwidth'], 10)
                        nodes_seen = 0

                        buckets = self.cores[current_core].l1 if current_tree == 1 else self.cores[current_core].l2

                        buckets[current_row] = lpm_bucket()

                if m is None and 'Node: key' in line:
                    m = re.match(
                        '.*Node: key (?P<key>([0-9a-f]*)) width (?P<width>([0-9]*)) payload (?P<payload>([0-9a-f]*))', line)
                    if m is not None:
                        key = int(m['key'], 16)
                        width = int(m['width'], 10)
                        payload = int(m['payload'], 16)
                        clean_width = width - root_width
                        clean_key = get_bits(key, clean_width - 1, 0)
                        nodes_seen += 1

                        try:
                            buckets = self.cores[current_core].l1 if current_tree == 1 else self.cores[current_core].l2
                        except Exception:
                            print("Corrupted log file, trying to add entries to bucket before bucket declaration.")

                        entry_key = lpm_prefix(clean_key, clean_width)
                        buckets[current_row].entries.append(lpm_entry(key=entry_key, payload=payload, valid=True))

                if m is None and 'Default bucket payload' in line:
                    m = re.match('.*Default bucket payload (?P<payload>([0-9a-f]*))', line)
                    if m is not None:
                        buckets = self.cores[current_core].l1 if current_tree == 1 else self.cores[current_core].l2
                        payload = int(m['payload'], 16)
                        # Right now supports only pacific.
                        buckets[current_row].default = lpm_default(payload, is_pointer=False)

        for row in distributor_to_group:
            key_valuue = distributor_to_group[row]['key']
            width = distributor_to_group[row]['width']
            group = distributor_to_group[row]['payload']
            valid = distributor_to_group[row]['valid']
            key = lpm_prefix(key_valuue, width)
            core = group_to_core.get(group, 0)
            self.distributor[row] = lpm_distributor_entry(key, valid, group, core)

    # @brief Encode ip and vrf into a lpm key.
    #
    # param[in]  ip_str         IPv6 or IPv4 as string.
    # param[in]  vrf            VRF number.
    # param[out] ret_key        Key in LPM format.
    @staticmethod
    def encode_lpm_key(vrf, ip_str):
        return lpm_hw_to_logic_converter_pacific.encode_lpm_key(vrf, ip_str)

    # @brief Returns the number of distributor rows.
    def get_distributor_number_of_rows(self):
        return DISTRIBUTOR_TCAM_NUMBER_OF_ROWS

    # @brief Reads a single distributor row.
    #
    # param[in] row_idx                Row index to read.
    # param[out] distributor_entry     Distributor entry which contains key,mask,value,group,core
    def read_distributor_row(self, row_idx):
        default_value = lpm_distributor_entry(lpm_prefix(0, 0), False, 0, 0)
        return self.distributor.get(row_idx, default_value)

    # @brief Returns the number of tcam rows.
    def get_tcam_number_of_rows(self):
        return TCAM_MAX_CORE_ENTRIES

    # @brief Reads a tcam row.
    #
    # param[in]  core_idx       Core index to read.
    # param[int] row_idx        Row index to read.
    # param[out] tcam_entry     TCAM entry containing key,length,valid,payload,hit_width.
    def read_tcam_row(self, core_idx, row_idx):
        default_value = lpm_tcam_entry(lpm_prefix(0, 0), False, 0, 0)
        return self.cores[core_idx].tcam.get(row_idx, default_value)

    # @brief Returns the number of l1 buckets.
    def get_l1_number_of_buckets(self):
        return L1_NUMBER_OF_BUCKETS

    # @brief Reads a L1 bucket.
    #
    # param[in]  core_idx       Core index to read.
    # param[in]  bucket_idx     Bucket index to read.
    # param[out] bucket         Bucket written in core core_idx with HW index bucket_idx.
    def read_l1_bucket(self, core_idx, bucket_idx):
        default_value = lpm_bucket()
        default_value.default = lpm_default(0)
        return self.cores[core_idx].l1.get(bucket_idx, default_value)

    # @brief Returns the number of l2 buckets.
    def get_l2_number_of_buckets(self):
        return L2_NUMBER_OF_BUCKETS

    # @brief Reads a L2 bucket.
    #
    # param[in]  core_idx       Core index to read.
    # param[in]  bucket_idx     Bucket index to read.
    # param[out] bucket         Bucket written in core core_idx with HW index bucket_idx.
    def read_l2_bucket(self, core_idx, bucket_idx):
        default_value = lpm_bucket()
        default_value.default = lpm_default(0)
        return self.cores[core_idx].l2.get(bucket_idx, default_value)


class lpm_core:
    def __init__(self):
        self.tcam = {}
        self.l1 = {}
        self.l2 = {}
