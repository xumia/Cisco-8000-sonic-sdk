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
NUMBER_OF_REPLICAS = 12
# TCAM
TCAM_MAX_CORE_ENTRIES = 2048
TCAM_WIDTH = 40
TCAM_PAYLOAD_START = 0
TCAM_HIT_WIDTH_START = 13  # TCAM payload is 0:12 - L1 bucket index, 13:19 - Hit width.
TCAM_PAYLOAD_WIDTH = 20
TCAM_LONG_LINES = 240
TCAM_NUMBER_OF_ROWS = 512
TCAM_BROKEN_BIT_INDEX = 16
TCAM_IPV6_HW_TCAMS_ORDER = [1, 0, 3, 2]  # Search IPv6 in TCAM order.

# L1:
L1_NUMBER_OF_BUCKETS = 1024 * 4  # Including extended L1 memory.
L1_ENTRY_LENGTH = 33  # in pacific it was 34
L1_PAYLOAD_LENGTH = L1_DEFAULT_POINTER_LENGTH = 15
L1_PREFIX_LENGTH = 17
L1_DEFAULT_LENGTH_WIDTH = 8

# L2 :
L2_NUMBER_OF_BUCKETS = 4096
L2_SRAM_BANK_WIDTH = 110
L2_NUMBER_OF_SHARED_ENTRIES = 14
L2_ECC = 24
L2_ENCODING_WIDTH = 4
L2_PAYLOAD_WIDTH = 28
L2_DEFAULT_WIDTH = L2_PAYLOAD_WIDTH
L2_PREFIX_LENGTH = 16 + 1
L2_DOUBLE_BUCKET_ENCODING = 0xfffff
L2_NUMBER_OF_BANKS = 9
L2_IS_NARROW_WIDTH = 1
L2_COUNTER_WIDTH = 4
L2_ENTRY_TYPE_WIDTH = 1
L2_NUMBER_OF_SHARED_GROUPS = 12
L2_ENTRY_WIDTH = L2_PAYLOAD_WIDTH + L2_PREFIX_LENGTH + L2_ENTRY_TYPE_WIDTH
L2_GROUP_WIDTH = 2 * L2_ENTRY_WIDTH + L2_IS_NARROW_WIDTH

# HBM
HBM_THIN_BUCKET_WIDTH = 1024
HBM_NUM_GROUPS_PER_THIN_BUCKET = 11
HBM_NUMBER_OF_BUCKETS = 12 * 1024
HBM_NUM_REPLICATIONS = 4


class lpm_hw_to_logic_converter_gb(lpm_hw_to_logic_converter_base):

    def __init__(self, hw_src, extended_tcam=True, is_hbm_enabled=False):
        super().__init__(hw_src, extended_tcam, is_hbm_enabled)

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
        ret_key = self.decode_distributor_key(k, m)
        return lpm_distributor_entry(ret_key, v, group_number, core)

    # return value is lpm_prefix
    def decode_distributor_key(self, key, mask):
        is_ipv4 = ((key >> (DISTRIBUTOR_TCAM_WIDTH - 1)) == 0)
        msb_offset = 1 if is_ipv4 else 2

        key_width = bin(mask).count('1') - msb_offset
        if key_width <= 0:
            return lpm_prefix(int(not is_ipv4), ADDRESS_TYPE_LENGTH)

        key_value = (key & mask)
        ret_key = lpm_prefix(int(not is_ipv4), ADDRESS_TYPE_LENGTH)
        ret_key <<= key_width
        ret_key.value |= get_bits(key_value, DISTRIBUTOR_TCAM_WIDTH - 1 - msb_offset,
                                  DISTRIBUTOR_TCAM_WIDTH - msb_offset - key_width)
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
        NON_ENTRY_DATA_WIDTH = ENCODING_WIDTH + 2 * L1_DEFAULT_POINTER_LENGTH + 2 * (L1_DEFAULT_LENGTH_WIDTH + 1)
        bits_offset = 0
        number_of_bucket1_shared_entries = get_bits(row_data, bits_offset + ENCODING_WIDTH - 1, bits_offset)
        bits_offset += ENCODING_WIDTH
        l1_row_buckets = [lpm_bucket() for _ in range(2)]
        assert number_of_bucket1_shared_entries <= NUMBER_OF_SHARED_ENTRIES
        default0 = get_bits(row_data, bits_offset + L1_DEFAULT_POINTER_LENGTH - 1, bits_offset)
        bits_offset += L1_DEFAULT_POINTER_LENGTH
        default0_hit_width = get_bits(row_data, bits_offset + L1_DEFAULT_LENGTH_WIDTH - 1, bits_offset)
        bits_offset += L1_DEFAULT_LENGTH_WIDTH + 1
        default1 = get_bits(row_data, bits_offset + L1_DEFAULT_POINTER_LENGTH - 1, bits_offset)
        bits_offset += L1_DEFAULT_POINTER_LENGTH
        default1_hit_width = get_bits(row_data, bits_offset + L1_DEFAULT_LENGTH_WIDTH - 1, bits_offset)
        bits_offset += L1_DEFAULT_LENGTH_WIDTH + 1
        # offset is 26
        l1_row_buckets[0].default = lpm_default(default0, is_pointer=True, default_hit_width=default0_hit_width)
        l1_row_buckets[1].default = lpm_default(default1, is_pointer=True, default_hit_width=default1_hit_width)

        # Bucket 1 shared entries:
        for _ in range(0, number_of_bucket1_shared_entries):
            entry = get_bits(row_data, bits_offset + L1_ENTRY_LENGTH - 1, bits_offset)
            index = (bits_offset - NON_ENTRY_DATA_WIDTH) // L1_ENTRY_LENGTH
            entry_instance = lpm_hw_to_logic_converter_gb.l1_entry_to_lpm_entry(entry, is_shared=True, entry_index=index)
            bits_offset += L1_ENTRY_LENGTH
            if not entry_instance.valid:
                continue
            l1_row_buckets[1].entries.append(entry_instance)

        # Bucket 0 shared entries:
        for _ in range(0, NUMBER_OF_SHARED_ENTRIES - number_of_bucket1_shared_entries):
            entry = get_bits(row_data, bits_offset + L1_ENTRY_LENGTH - 1, bits_offset)
            index = (bits_offset - NON_ENTRY_DATA_WIDTH) // L1_ENTRY_LENGTH
            entry_instance = lpm_hw_to_logic_converter_gb.l1_entry_to_lpm_entry(entry, is_shared=True, entry_index=index)
            bits_offset += L1_ENTRY_LENGTH
            if not entry_instance.valid:
                continue
            l1_row_buckets[0].entries.append(entry_instance)

        # Bucket 0 fixed entries:
        for _ in range(0, NUMBER_OF_FIXED_ENTRIES):
            entry = get_bits(row_data, bits_offset + L1_ENTRY_LENGTH - 1, bits_offset)
            index = (bits_offset - NON_ENTRY_DATA_WIDTH) // L1_ENTRY_LENGTH
            entry_instance = lpm_hw_to_logic_converter_gb.l1_entry_to_lpm_entry(entry, is_shared=False, entry_index=index)
            bits_offset += L1_ENTRY_LENGTH
            if not entry_instance.valid:
                continue
            l1_row_buckets[0].entries.append(entry_instance)

        # Bucket 1 fixed entries:
        for _ in range(0, NUMBER_OF_FIXED_ENTRIES):
            entry = get_bits(row_data, bits_offset + L1_ENTRY_LENGTH - 1, bits_offset)
            index = (bits_offset - NON_ENTRY_DATA_WIDTH) // L1_ENTRY_LENGTH
            entry_instance = lpm_hw_to_logic_converter_gb.l1_entry_to_lpm_entry(entry, is_shared=False, entry_index=index)
            bits_offset += L1_ENTRY_LENGTH
            if not entry_instance.valid:
                continue
            l1_row_buckets[1].entries.append(entry_instance)

        return l1_row_buckets

    @staticmethod
    def l1_entry_to_lpm_entry(entry, is_shared, entry_index):
        offset = 0
        payload = get_bits(entry, offset + L1_PAYLOAD_LENGTH - 1, offset)
        offset += L1_PAYLOAD_LENGTH
        prefix = get_bits(entry, offset + L1_PREFIX_LENGTH - 1, offset)
        offset += L1_PREFIX_LENGTH
        if prefix == 0:
            return lpm_entry(lpm_prefix(0, 0), 0, valid=False, is_shared=is_shared, index=entry_index)
        is_double_line_in_hbm = bool(get_bits(entry, offset, offset))  # Currently should be always false.
        prefix = lpm_hw_to_logic_converter_gb.decode_bucket_prefix(prefix)
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
    def l2_raw_group_to_lpm_entries(raw_group, is_even_bucket, is_shared, group_index):
        is_double = raw_group & 0x1
        offset = 1
        ret_entries = []
        if is_shared:
            raw_prefix0 = get_bits(raw_group, offset + L2_PREFIX_LENGTH - 1, offset)
            prefix0 = lpm_hw_to_logic_converter_gb.decode_bucket_prefix(raw_prefix0) if raw_prefix0 > 0 else None
            offset += L2_PREFIX_LENGTH
            is_prefix0_leaf = bool(get_bits(raw_group, offset, offset))
            offset += L2_ENTRY_TYPE_WIDTH
            payload0 = get_bits(raw_group, offset + L2_PAYLOAD_WIDTH - 1, offset)
            offset += L2_PAYLOAD_WIDTH
            raw_prefix1 = get_bits(raw_group, offset + L2_PREFIX_LENGTH - 1, offset)
            prefix1 = lpm_hw_to_logic_converter_gb.decode_bucket_prefix(raw_prefix1) if raw_prefix1 > 0 else None
            offset += L2_PREFIX_LENGTH
            is_prefix1_leaf = bool(get_bits(raw_group, offset, offset))
            offset += L2_ENTRY_TYPE_WIDTH
            payload1 = get_bits(raw_group, offset + L2_PAYLOAD_WIDTH - 1, offset)
        else:
            raw_prefix0 = get_bits(raw_group, offset + L2_PREFIX_LENGTH - 1, offset)
            prefix0 = lpm_hw_to_logic_converter_gb.decode_bucket_prefix(raw_prefix0) if raw_prefix0 > 0 else None
            offset += L2_PREFIX_LENGTH
            is_prefix0_leaf = bool(get_bits(raw_group, offset, offset))
            offset += L2_ENTRY_TYPE_WIDTH
            payload0 = get_bits(raw_group, offset + L2_PAYLOAD_WIDTH - 1, offset)
            offset += L2_PAYLOAD_WIDTH + (1 if is_even_bucket else 0)
            raw_prefix1 = get_bits(raw_group, offset + L2_PREFIX_LENGTH - 1, offset)
            prefix1 = lpm_hw_to_logic_converter_gb.decode_bucket_prefix(raw_prefix1) if raw_prefix1 > 0 else None
            offset += L2_PREFIX_LENGTH
            is_prefix1_leaf = bool(get_bits(raw_group, offset, offset))
            offset += L2_ENTRY_TYPE_WIDTH
            payload1 = get_bits(raw_group, offset + L2_PAYLOAD_WIDTH - 1, offset)

        if is_double:
            assert prefix1 is not None and prefix0 is not None
            ret_key = lpm_prefix((prefix1.value << prefix0.width) | prefix0.value, prefix1.width + prefix0.width)
            assert ret_key.width <= (L2_PREFIX_LENGTH - 1) * 2
            ret_entries.append(lpm_entry(ret_key, payload=payload0, valid=True, is_shared=is_shared))
        else:
            if prefix0 is not None:
                assert prefix0.width <= L2_PREFIX_LENGTH - 1
                ret_entries.append(
                    lpm_entry(
                        prefix0,
                        payload=payload0,
                        valid=True,
                        is_shared=is_shared,
                        index=group_index * 2,
                        is_leaf=is_prefix0_leaf))
            if prefix1 is not None:
                assert prefix1.width <= L2_PREFIX_LENGTH - 1
                ret_entries.append(
                    lpm_entry(
                        prefix1,
                        payload=payload1,
                        valid=True,
                        is_shared=is_shared,
                        index=group_index * 2 + 1,
                        is_leaf=is_prefix1_leaf))
        return ret_entries

    @staticmethod
    def get_buckets_from_l2_row(row, row_width):
        NON_ENTRY_DATA_WIDTH = L2_ECC + L2_IS_NARROW_WIDTH + L2_ENCODING_WIDTH + 2 * L2_ENTRY_TYPE_WIDTH + 2 * L2_DEFAULT_WIDTH
        ret_buckets = [lpm_bucket() for _ in range(2)]
        offset = 0
        offset += L2_ECC + L2_IS_NARROW_WIDTH
        shared_to_1 = get_bits(row, offset + L2_ENCODING_WIDTH - 1, offset)
        offset += L2_ENCODING_WIDTH
        offset += L2_ENTRY_TYPE_WIDTH
        # Defaults:
        default0 = get_bits(row, offset + L2_DEFAULT_WIDTH - 1, offset)
        ret_buckets[0].default = lpm_default(default0)
        offset += L2_DEFAULT_WIDTH + L2_ENTRY_TYPE_WIDTH
        default1 = get_bits(row, offset + L2_DEFAULT_WIDTH - 1, offset)
        ret_buckets[1].default = lpm_default(default1)
        offset += L2_DEFAULT_WIDTH

        # Bucket 1 shared groups:
        for _ in range(shared_to_1):
            raw_group = get_bits(row, offset + L2_GROUP_WIDTH - 1, offset)
            group_index = (offset - NON_ENTRY_DATA_WIDTH) // L2_GROUP_WIDTH
            entries = lpm_hw_to_logic_converter_gb.l2_raw_group_to_lpm_entries(
                raw_group, is_even_bucket=False, is_shared=True, group_index=group_index)
            offset += L2_GROUP_WIDTH
            ret_buckets[1].entries += entries

        # Bucket 0 shared groups:
        for _ in range(L2_NUMBER_OF_SHARED_GROUPS - shared_to_1):
            raw_group = get_bits(row, offset + L2_GROUP_WIDTH - 1, offset)
            group_index = (offset - NON_ENTRY_DATA_WIDTH) // L2_GROUP_WIDTH
            entries = lpm_hw_to_logic_converter_gb.l2_raw_group_to_lpm_entries(
                raw_group, is_even_bucket=True, is_shared=True, group_index=group_index)
            ret_buckets[0].entries += entries
            offset += L2_GROUP_WIDTH

        while offset < row_width:
            group0_index = (offset - NON_ENTRY_DATA_WIDTH) // L2_GROUP_WIDTH
            group0_entry0 = get_bits(row, offset + L2_ENTRY_WIDTH + L2_IS_NARROW_WIDTH - 1, offset)
            offset += L2_ENTRY_WIDTH + L2_IS_NARROW_WIDTH
            group1_entry0 = get_bits(row, offset + L2_ENTRY_WIDTH + L2_IS_NARROW_WIDTH - 1, offset)
            offset += L2_ENTRY_WIDTH + L2_IS_NARROW_WIDTH
            group0_entry1 = get_bits(row, offset + L2_ENTRY_WIDTH - 1, offset)
            offset += L2_ENTRY_WIDTH
            group1_entry1 = get_bits(row, offset + L2_ENTRY_WIDTH - 1, offset)
            offset += L2_ENTRY_WIDTH
            group0 = (group0_entry0 << L2_ENTRY_WIDTH) | group0_entry1
            group1 = (group1_entry0 << L2_ENTRY_WIDTH) | group1_entry1

            b0_entries = lpm_hw_to_logic_converter_gb.l2_raw_group_to_lpm_entries(
                raw_group, is_even_bucket=True, is_shared=False, group_index=group0_index)
            b1_entries = lpm_hw_to_logic_converter_gb.l2_raw_group_to_lpm_entries(
                raw_group, is_even_bucket=True, is_shared=False, group_index=group0_index + 1)
            ret_buckets[0].entries += b0_entries
            ret_buckets[1].entries += b1_entries

        return ret_buckets

    def get_l2_number_of_buckets(self):
        return L2_NUMBER_OF_BUCKETS + int(self.is_hbm_enabled) * HBM_NUMBER_OF_BUCKETS

    def read_l2_bucket(self, core_idx, bucket_idx):
        if bucket_idx < L2_NUMBER_OF_BUCKETS:
            return self.read_l2_sram_bucket(core_idx, bucket_idx)
        else:
            return self.read_l2_hbm_bucket(core_idx, bucket_idx)

    def read_l2_hbm_bucket(self, core_idx, bucket_idx):
        use_fat_hbm_lines = False
        number_of_hbm_thin_lines = 2 if use_fat_hbm_lines else 1
        hbm_data = self.hw_src.read_hbm_line(core_idx, bucket_idx, replica=0, read_fat_hbm_line=use_fat_hbm_lines)

        bucket = lpm_bucket()
        for thin_line_idx in range(number_of_hbm_thin_lines):
            group_offset = HBM_THIN_BUCKET_WIDTH * thin_line_idx
            for group_idx in range(HBM_NUM_GROUPS_PER_THIN_BUCKET):
                group_data = get_bits(hbm_data, group_offset + L2_GROUP_WIDTH - 1, group_offset)
                is_double = get_bits(group_data, 0, 0)
                raw_prefix0 = get_bits(group_data, 17, 1)
                if raw_prefix0 > 0:
                    prefix0 = self.decode_bucket_prefix(raw_prefix0)
                    is_prefix0_leaf = get_bits(group_data, 35, 35)
                    payload0 = get_bits(group_data, 63, 36)
                    if not is_double:
                        bucket.entries.append(
                            lpm_entry(
                                prefix0,
                                payload0,
                                valid=True,
                                is_shared=False,
                                is_leaf=is_prefix0_leaf,
                                index=thin_line_idx *
                                HBM_NUM_GROUPS_PER_THIN_BUCKET +
                                group_idx))

                raw_prefix1 = get_bits(group_data, 34, 18)
                if raw_prefix1 > 0:
                    prefix1 = self.decode_bucket_prefix(raw_prefix1)
                    is_prefix1_leaf = get_bits(group_data, 64, 64)
                    payload1 = get_bits(group_data, 92, 65)
                    if not is_double:
                        bucket.entries.append(
                            lpm_entry(
                                prefix1,
                                payload1,
                                valid=True,
                                is_shared=False,
                                is_leaf=is_prefix1_leaf,
                                index=thin_line_idx *
                                HBM_NUM_GROUPS_PER_THIN_BUCKET +
                                group_idx +
                                1))

                if is_double:
                    # This is not asserted because unreachable HBM buckets contain invalid data.
                    if raw_prefix1 > 0 and raw_prefix0 > 0:
                        ret_key = lpm_prefix((prefix1.value << prefix0.width) | prefix0.value, prefix1.width + prefix0.width)
                        assert ret_key.width <= (L2_PREFIX_LENGTH - 1) * 2
                        bucket.entries.append(
                            lpm_entry(
                                ret_key,
                                payload=payload0,
                                is_leaf=is_prefix0_leaf,
                                valid=True,
                                is_shared=False,
                                index=thin_line_idx *
                                HBM_NUM_GROUPS_PER_THIN_BUCKET +
                                group_idx))

                group_offset += L2_GROUP_WIDTH

        bucket.default = lpm_default(0)
        return bucket

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
        return l2_buckets[bucket_number_in_row]

    @staticmethod
    def encode_lpm_key(vrf, ip_str):
        addr = ipaddress.ip_address(ip_str)
        is_ipv6 = (addr.version == 6)
        ip = int(addr)
        ip_len = IPV6_LENGTH if is_ipv6 else IPV4_LENGTH
        full_key = (is_ipv6 << (VRF_LENGTH + ip_len)) | (vrf << ip_len) | ip
        full_len = VRF_LENGTH + ip_len + 1
        ret_key = lpm_hw_to_logic_converter_gb.encode_prefix(full_key, full_len)
        return ret_key

    @staticmethod
    def encode_prefix(prefix, width):
        assert prefix.bit_length() <= width
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
