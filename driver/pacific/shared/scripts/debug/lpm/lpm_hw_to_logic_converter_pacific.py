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

from lpm_hw_to_logic_converter_base import *
from bit_utils import get_bits
import ipaddress

ADDRESS_TYPE_LENGTH = 1
IPV6_LENGTH = 128
IPV4_LENGTH = 32
VRF_LENGTH = 11
IPV6_KEY_LENGTH = IPV6_LENGTH + VRF_LENGTH + ADDRESS_TYPE_LENGTH
IPV4_KEY_LENGTH = IPV4_LENGTH + VRF_LENGTH + ADDRESS_TYPE_LENGTH
IPV4_ENCODED_KEY_LENGTH = IPV4_LENGTH + VRF_LENGTH + ADDRESS_TYPE_LENGTH + 1  # Broken bit
BROKEN_BIT_INDEX_IN_PREFIX = 20  # HW bug broken bit index.

# Distributor
DISTRIBUTOR_TCAM_WIDTH = 80
DISTRIBUTOR_TCAM_NUMBER_OF_ROWS = 128
IPV4_LENGTH_IN_DISTRIBUTOR = 46  # Actual bits of IPv4 distributor encoded key
DISTRIBUTOR_IPV4_ENC_VALUE = 0xfff
DISTRIBUTOR_IPV4_ENC_WIDTH = 12
NUMBER_OF_REPLICAS = 12

# L1:
L1_NUMBER_OF_BUCKETS = 1024 * 4  # Including extended L1 memory.
L1_ENTRY_LENGTH = 34
L1_PAYLOAD_LENGTH = 15
L1_PREFIX_LENGTH = 17
L1_ENTRY_FULLNESS_WIDTH = 2

# L2 :
L2_NUMBER_OF_BUCKETS = 4096
L2_SRAM_BANK_WIDTH = 109
L2_NUMBER_OF_SHARED_ENTRIES = 14
L2_ECC = 22
L2_ENTRY_LENGTH = 38
L2_DOUBLE_BUCKET_SIZE = 44
L2_ENCODING_WIDTH = 4
L2_DEFAULT_WIDTH = 20
L2_PAYLOAD_WIDTH = 20
L2_PREFIX_LENGTH = 16 + 1
L2_DOUBLE_BUCKET_ENCODING = 0xfffff
L2_NUMBER_OF_BANKS = 9

# HBM:
HBM_NUMBER_OF_BUCKETS = 12 * 1024
HBM_SECTION_WIDTH = 256
HBM_NUM_SECTIONS = 4
HBM_NUM_ENTRIES_IN_SECTION = 6
HBM_NUM_REPLICATIONS = 4


class lpm_hw_to_logic_converter_pacific(lpm_hw_to_logic_converter_base):

    def get_distributor_number_of_rows(self):
        return DISTRIBUTOR_TCAM_NUMBER_OF_ROWS

    def get_distributor_row_width(self):
        return DISTRIBUTOR_TCAM_WIDTH

    def read_distributor_row(self, row_idx):
        distributor_entry = k, m, v = self.hw_src.read_group_map_tcam(row_idx, replica=0)
        replicas_entries_list = [self.hw_src.read_group_map_tcam(
            row_idx, replica=replica_idx) for replica_idx in range(NUMBER_OF_REPLICAS)]
        for replica_entry in replicas_entries_list:
            if distributor_entry != replica_entry:
                print("ERROR: distributor lines with index %d in different replicas are not equal." % row_idx)
                for idx, (k, m, v) in enumerate(replicas_entries_list):
                    print("Replica: %d, Key: 0x%x, Mask: 0x%x is valid? %d" % (idx, k, m, v))
                return lpm_distributor_entry(lpm_prefix(0, 0), False, 0, 0)
        group_number = self.hw_src.read_tcam_line_to_group_table(row_idx)
        core = self.hw_src.read_group_to_core_table(group_number)
        ret_key = self.decode_distributor_key(k, m, row_idx)
        return lpm_distributor_entry(ret_key, v, group_number, core)

    # return value is lpm_prefix
    def decode_distributor_key(self, key, mask, row_idx):
        if mask == 0:
            return lpm_prefix(0, 0)
        key_width = bin(mask).count('1')

        is_ipv6 = not (
            get_bits(
                key & mask,
                DISTRIBUTOR_TCAM_WIDTH -
                1,
                DISTRIBUTOR_TCAM_WIDTH -
                DISTRIBUTOR_IPV4_ENC_WIDTH) == DISTRIBUTOR_IPV4_ENC_VALUE)

        key_value = (key & mask)
        ret_key = lpm_prefix(int(is_ipv6), ADDRESS_TYPE_LENGTH)
        assert 0 < key_width <= DISTRIBUTOR_TCAM_WIDTH
        if is_ipv6:
            encoded_ip_value = get_bits(key_value, DISTRIBUTOR_TCAM_WIDTH - 1, DISTRIBUTOR_TCAM_WIDTH - key_width)
            ret_key <<= key_width
            ret_key.value |= encoded_ip_value

        else:
            key_width -= DISTRIBUTOR_IPV4_ENC_WIDTH
            prefix_start_idx = IPV4_LENGTH_IN_DISTRIBUTOR - key_width
            prefix_end_idx = IPV4_LENGTH_IN_DISTRIBUTOR - 1
            prefix_width = prefix_end_idx - prefix_start_idx + 1
            ret_key <<= prefix_width
            ret_key.value |= get_bits(key_value, prefix_end_idx, prefix_start_idx) if prefix_width > 0 else 0

        return ret_key

    def get_l1_number_of_buckets(self):
        return L1_NUMBER_OF_BUCKETS

    def read_l1_bucket(self, core_idx, bucket_idx):
        bucket_number_in_row = bucket_idx % 2
        l1_row_index = bucket_idx // 2
        row_data = self.hw_src.read_core_subtrie_mem(core_idx, l1_row_index)
        l1__row_buckets = self.get_buckets_from_l1_row(row_data)
        return l1__row_buckets[bucket_number_in_row]

    @staticmethod
    def get_buckets_from_l1_row(row_data):
        ENCODING_WIDTH = 3
        NUMBER_OF_SHARED_ENTRIES = 4
        NUMBER_OF_FIXED_ENTRIES = 2
        DEFAULT_PAYLOAD_WIDTH = 20
        NON_ENTRY_DATA_WIDTH = ENCODING_WIDTH + 2 * DEFAULT_PAYLOAD_WIDTH
        offset = 0
        number_of_bucket1_shared_entries = get_bits(row_data, offset + ENCODING_WIDTH - 1, offset)
        offset += ENCODING_WIDTH
        l1_row_buckets = [lpm_bucket() for _ in range(2)]
        assert number_of_bucket1_shared_entries <= NUMBER_OF_SHARED_ENTRIES
        default0 = get_bits(row_data, offset + DEFAULT_PAYLOAD_WIDTH - 1, offset)
        offset += DEFAULT_PAYLOAD_WIDTH
        default1 = get_bits(row_data, offset + DEFAULT_PAYLOAD_WIDTH - 1, offset)
        offset += DEFAULT_PAYLOAD_WIDTH
        l1_row_buckets[0].default = lpm_default(default0)
        l1_row_buckets[1].default = lpm_default(default1)

        # Bucket 1 shared entries:
        for _ in range(0, number_of_bucket1_shared_entries):
            entry = get_bits(row_data, offset + L1_ENTRY_LENGTH - 1, offset)
            index = (offset - NON_ENTRY_DATA_WIDTH) // L1_ENTRY_LENGTH
            entry_instance = lpm_hw_to_logic_converter_pacific.l1_entry_to_lpm_entry(entry, is_shared=True, entry_index=index)
            offset += L1_ENTRY_LENGTH
            if not entry_instance.valid:
                continue

            l1_row_buckets[1].entries.append(entry_instance)

        # Bucket 0 shared entries:
        for _ in range(0, NUMBER_OF_SHARED_ENTRIES - number_of_bucket1_shared_entries):
            entry = get_bits(row_data, offset + L1_ENTRY_LENGTH - 1, offset)
            index = (offset - NON_ENTRY_DATA_WIDTH) // L1_ENTRY_LENGTH
            entry_instance = lpm_hw_to_logic_converter_pacific.l1_entry_to_lpm_entry(entry, is_shared=True, entry_index=index)
            offset += L1_ENTRY_LENGTH
            if not entry_instance.valid:
                continue

            l1_row_buckets[0].entries.append(entry_instance)

        # Bucket 0 fixed entries:
        for _ in range(0, NUMBER_OF_FIXED_ENTRIES):
            entry = get_bits(row_data, offset + L1_ENTRY_LENGTH - 1, offset)
            index = (offset - NON_ENTRY_DATA_WIDTH) // L1_ENTRY_LENGTH
            entry_instance = lpm_hw_to_logic_converter_pacific.l1_entry_to_lpm_entry(entry, is_shared=False, entry_index=index)
            offset += L1_ENTRY_LENGTH
            if not entry_instance.valid:
                continue

            l1_row_buckets[0].entries.append(entry_instance)

        # Bucket 1 fixed entries:
        for _ in range(0, NUMBER_OF_FIXED_ENTRIES):
            entry = get_bits(row_data, offset + L1_ENTRY_LENGTH - 1, offset)
            index = (offset - NON_ENTRY_DATA_WIDTH) // L1_ENTRY_LENGTH
            entry_instance = lpm_hw_to_logic_converter_pacific.l1_entry_to_lpm_entry(entry, is_shared=False, entry_index=index)
            offset += L1_ENTRY_LENGTH
            if not entry_instance.valid:
                continue

            l1_row_buckets[1].entries.append(entry_instance)

        return l1_row_buckets

    @staticmethod
    def l1_entry_to_lpm_entry(entry, is_shared, entry_index):
        offset = 0
        l1_fullness = get_bits(entry, offset + L1_ENTRY_FULLNESS_WIDTH - 1, offset)
        offset += L1_ENTRY_FULLNESS_WIDTH
        payload = get_bits(entry, offset + L1_PAYLOAD_LENGTH - 1, offset)
        offset += L1_PAYLOAD_LENGTH
        prefix = get_bits(entry, offset + L1_PREFIX_LENGTH - 1, offset)
        if prefix == 0:
            return lpm_entry(lpm_prefix(0, 0), 0, valid=False, is_shared=is_shared, index=entry_index)

        prefix = lpm_hw_to_logic_converter_pacific.decode_bucket_prefix(prefix)
        return lpm_entry(prefix, payload=payload, valid=True, is_shared=is_shared, index=entry_index)

    @staticmethod
    def decode_bucket_prefix(prefix):
        assert prefix != 0
        width_diff = 0
        while prefix % 2 == 0:
            prefix >>= 1
            width_diff += 1

        prefix >>= 1
        return lpm_prefix(prefix, L1_PREFIX_LENGTH - width_diff - 1)

    @staticmethod
    def l2_entry_to_lpm_entry(l2_entry, is_shared, entry_index):
        offset = 0
        payload = get_bits(l2_entry, offset + L2_PAYLOAD_WIDTH - 1, offset)
        offset += L2_PAYLOAD_WIDTH
        prefix = get_bits(l2_entry, offset + L2_PREFIX_LENGTH - 1, offset)
        offset += L2_PREFIX_LENGTH
        if prefix == 0:
            return lpm_entry(lpm_prefix(0, 0), payload=None, valid=False, is_shared=is_shared, index=entry_index)

        is_leaf = not bool(get_bits(l2_entry, offset, offset))
        prefix = lpm_hw_to_logic_converter_pacific.decode_bucket_prefix(prefix)
        assert prefix.width <= L2_PREFIX_LENGTH - 1
        return lpm_entry(prefix, payload=payload, valid=True, is_shared=is_shared, is_leaf=is_leaf, index=entry_index)

    @staticmethod
    def get_buckets_from_l2_row(row, row_width):
        NON_ENTRY_DATA_WIDTH = L2_ECC + L2_ENCODING_WIDTH + 2 * L2_DEFAULT_WIDTH
        ret_buckets = [lpm_bucket() for _ in range(2)]
        offset = 0
        ecc = get_bits(row, offset + L2_ECC - 1, offset)
        offset += L2_ECC
        shared_to_1 = get_bits(row, offset + L2_ENCODING_WIDTH - 1, offset)
        offset += L2_ENCODING_WIDTH
        # defaults:
        default0 = get_bits(row, offset + L2_DEFAULT_WIDTH - 1, offset)
        ret_buckets[0].default = lpm_default(default0)
        offset += L2_DEFAULT_WIDTH
        default1 = get_bits(row, offset + L2_DEFAULT_WIDTH - 1, offset)
        ret_buckets[1].default = lpm_default(default1)
        offset += L2_DEFAULT_WIDTH

        # Bucket 1 Shared:
        for _ in range(shared_to_1):
            entry = get_bits(row, offset + L2_ENTRY_LENGTH - 1, offset)
            index = (offset - NON_ENTRY_DATA_WIDTH) // L2_ENTRY_LENGTH
            entry_instance = lpm_hw_to_logic_converter_pacific.l2_entry_to_lpm_entry(entry, is_shared=True, entry_index=index)
            offset += L2_ENTRY_LENGTH
            if not entry_instance.valid:
                continue
            ret_buckets[1].entries.append(entry_instance)

        # Bucket 0 Shared:
        for _ in range(L2_NUMBER_OF_SHARED_ENTRIES - shared_to_1):
            entry = get_bits(row, offset + L2_ENTRY_LENGTH - 1, offset)
            index = (offset - NON_ENTRY_DATA_WIDTH) // L2_ENTRY_LENGTH
            entry_instance = lpm_hw_to_logic_converter_pacific.l2_entry_to_lpm_entry(entry, is_shared=True, entry_index=index)
            offset += L2_ENTRY_LENGTH
            if not entry_instance.valid:
                continue

            ret_buckets[0].entries.append(entry_instance)

        end_of_shared_offset = offset
        # In L2, fixed entries are interleaved (b0e0, b1e0, b0e1, b1e1...)
        while offset < row_width:
            entry = get_bits(row, offset + L2_ENTRY_LENGTH - 1, offset)
            index = (offset - NON_ENTRY_DATA_WIDTH) // L2_ENTRY_LENGTH
            entry_instance = lpm_hw_to_logic_converter_pacific.l2_entry_to_lpm_entry(entry, is_shared=False, entry_index=index)
            offset += L2_ENTRY_LENGTH * 2

            if not entry_instance.valid:
                continue

            ret_buckets[0].entries.append(entry_instance)

        offset = L2_ENTRY_LENGTH + end_of_shared_offset
        while offset < row_width:
            entry = get_bits(row, offset + L2_ENTRY_LENGTH - 1, offset)
            index = (offset - NON_ENTRY_DATA_WIDTH) // L2_ENTRY_LENGTH
            entry_instance = lpm_hw_to_logic_converter_pacific.l2_entry_to_lpm_entry(entry, is_shared=False, entry_index=index)
            offset += L2_ENTRY_LENGTH * 2

            if not entry_instance.valid:
                continue

            ret_buckets[1].entries.append(entry_instance)

        return ret_buckets

    def get_l2_number_of_buckets(self):
        return L2_NUMBER_OF_BUCKETS + int(self.is_hbm_enabled) * HBM_NUMBER_OF_BUCKETS

    def read_l2_bucket(self, core_idx, bucket_idx):
        if bucket_idx < L2_NUMBER_OF_BUCKETS:
            return self.read_l2_sram_bucket(core_idx, bucket_idx)
        else:
            return self.read_l2_hbm_bucket(core_idx, bucket_idx)

    def read_l2_hbm_bucket(self, core_idx, bucket_idx):
        ret_bucket = lpm_bucket()
        line_value = self.hw_src.read_hbm_line(core_idx, bucket_idx)

        default_value = get_bits(line_value, L2_DEFAULT_WIDTH - 1, 0)

        ret_bucket.default = lpm_default(default_value)
        for section_idx in range(HBM_NUM_SECTIONS):
            for entry_id in range(HBM_NUM_ENTRIES_IN_SECTION):
                lsb = section_idx * HBM_SECTION_WIDTH + L2_DEFAULT_WIDTH + entry_id * L2_ENTRY_LENGTH
                entry_value = get_bits(line_value, lsb + L2_ENTRY_LENGTH - 1, lsb)
                entry = self.parse_hbm_entry(entry_value, entry_index=(section_idx * HBM_NUM_ENTRIES_IN_SECTION + entry_id))
                if entry.valid:
                    ret_bucket.entries.append(entry)

        return ret_bucket

    @staticmethod
    def parse_hbm_entry(entry: int, entry_index):
        offset = 0
        prefix = get_bits(entry, offset + L2_PREFIX_LENGTH - 1, offset)
        offset += L2_PREFIX_LENGTH
        payload = get_bits(entry, offset + L2_PAYLOAD_WIDTH - 1, offset)
        offset += L2_PAYLOAD_WIDTH
        if prefix == 0:
            return lpm_entry(lpm_prefix(0, 0), payload=0, valid=False, is_shared=False, index=entry_index)
        prefix = lpm_hw_to_logic_converter_pacific.decode_bucket_prefix(prefix)
        is_leaf = not bool(get_bits(entry, offset, offset))
        assert prefix.width <= L2_PREFIX_LENGTH - 1
        return lpm_entry(prefix, payload=payload, valid=True, is_shared=False, is_leaf=is_leaf, index=entry_index)

    def read_l2_sram_bucket(self, core_idx, bucket_idx):
        hw_row = bucket_idx // 2
        bucket_number_in_row = bucket_idx % 2
        row_width = bits_to_read = L2_NUMBER_OF_BANKS * L2_SRAM_BANK_WIDTH
        l2_row = 0
        bank_idx = 0
        total_width = 0
        while bits_to_read > 0:
            bank = self.hw_src.read_core_sram_group(core_idx, bank_idx, hw_row)
            bank <<= total_width
            l2_row += bank
            total_width += L2_SRAM_BANK_WIDTH
            bank_idx += 1
            bits_to_read -= L2_SRAM_BANK_WIDTH
        l2_buckets = self.get_buckets_from_l2_row(l2_row, row_width)
        merged_double_list = []
        is_double = False
        last_entry = None
        for entry in l2_buckets[bucket_number_in_row].entries:
            if not entry.valid:
                continue

            if is_double:
                last_entry.payload = entry.payload
                last_entry.key <<= entry.key.width
                last_entry.key.value |= entry.key.value
                entry = last_entry
                is_double = False

            if entry.payload == L2_DOUBLE_BUCKET_ENCODING:
                is_double = True
                last_entry = entry

            else:
                merged_double_list.append(entry)

        retval = lpm_bucket()
        retval.entries = merged_double_list
        retval.default = l2_buckets[bucket_number_in_row].default
        return retval

    @staticmethod
    def encode_lpm_key(vrf, ip_str):
        addr = ipaddress.ip_address(ip_str)
        is_ipv6 = (addr.version == 6)
        ip = int(addr)
        ip_len = IPV6_LENGTH if is_ipv6 else IPV4_LENGTH
        full_key = (is_ipv6 << (VRF_LENGTH + ip_len)) | (vrf << ip_len) | ip
        full_len = VRF_LENGTH + ip_len + 1
        ret_key = lpm_hw_to_logic_converter_pacific.encode_prefix(full_key, full_len)
        return ret_key

    @staticmethod
    def encode_prefix(prefix, width):

        is_ipv6 = (prefix >> (width - 1)) == 1
        if is_ipv6:
            return lpm_prefix(prefix, width)

        bits_above_broken_bit = IPV4_ENCODED_KEY_LENGTH - (BROKEN_BIT_INDEX_IN_PREFIX + 1)
        if width <= bits_above_broken_bit:
            return lpm_prefix(prefix, width)

        prefix_padded = prefix << (IPV4_KEY_LENGTH - width)
        prefix_msb = get_bits(prefix_padded, width - 1, BROKEN_BIT_INDEX_IN_PREFIX)
        prefix_lsb = get_bits(prefix_padded, BROKEN_BIT_INDEX_IN_PREFIX - 1, 0)
        encoded_prefix_padded = (prefix_msb << (BROKEN_BIT_INDEX_IN_PREFIX + 1)) | prefix_lsb
        encoded_prefix = encoded_prefix_padded >> (IPV4_KEY_LENGTH - width)
        return lpm_prefix(encoded_prefix, width + 1)
