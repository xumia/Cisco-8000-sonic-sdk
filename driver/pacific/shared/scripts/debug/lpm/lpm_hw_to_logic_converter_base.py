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
from bit_utils import get_bits


# TCAM
TCAM_WIDTH = 40
TCAM_PAYLOAD_START = 0
TCAM_HIT_WIDTH_START = 13  # TCAM payload is 0:12 - L1 bucket index, 13:19 - Hit width.
TCAM_PAYLOAD_WIDTH = 20
TCAM_LONG_LINES = 240
NUMBER_OF_ROWS_PER_TCAM_BANK = 512
TCAM_BROKEN_BIT_INDEX = 16
TCAM_IPV6_HW_TCAMS_ORDER = [1, 0, 3, 2]  # Search IPv6 in TCAM order.
NUMBER_OF_TCAM_BANKS_PER_BANKSET = 4


# @brief Convert raw data of the LPM hardware memory from given source into logical structures
# TCAM raw data is converted to TCAM entries
# SRAM raw data is converted to buckets
class lpm_hw_to_logic_converter_base(ABC):

    def __init__(self, hw_src, extended_tcam=True, is_hbm_enabled=True):
        self.hw_src = hw_src
        self.is_tcam_extended = extended_tcam
        self.is_hbm_enabled = is_hbm_enabled

    # @brief Encode ip and vrf into a lpm key.
    #
    # param[in]  ip_str         IPv6 or IPv4 as string.
    # param[in]  vrf            VRF number.
    # param[out] ret_key        Key in LPM format.
    @staticmethod
    @abstractmethod
    def encode_lpm_key(vrf, ip_str):
        pass

    # @brief Returns the number of distributor rows.
    @abstractmethod
    def get_distributor_number_of_rows(self):
        pass

    # @brief Reads a single distributor row.
    #
    # param[in] row_idx                Row index to read.
    # param[out] distributor_entry     Distributor entry which contains key,mask,value,group,core
    @abstractmethod
    def read_distributor_row(self, row_idx):
        pass

    # @brief Returns the number of tcam rows.
    def get_tcam_number_of_rows(self):
        return NUMBER_OF_ROWS_PER_TCAM_BANK * NUMBER_OF_TCAM_BANKS_PER_BANKSET * (1 if not self.is_tcam_extended else 2)

    # @brief Reads a tcam row.
    #
    # param[in]  core_idx       Core index to read.
    # param[int] row_idx        Row index to read.
    # param[out] tcam_entry     TCAM entry containing key,length,valid,payload,hit_width.
    def read_tcam_row(self, core_idx, row_idx):
        # Physical index is 0-4 and row is 0-511.
        tcam_physical_idx = row_idx // NUMBER_OF_ROWS_PER_TCAM_BANK
        tcam_pysical_row = row_idx % NUMBER_OF_ROWS_PER_TCAM_BANK
        k, m, v = self.read_small_tcam_row(core_idx, tcam_physical_idx, tcam_pysical_row)
        if not v:
            return lpm_tcam_entry(lpm_prefix(0, 0), False, payload=0, hit_width=0)

        is_row_ipv4 = ((k & 1) == 0)
        # HW bug fix - on TCAM index 2 IPv6 indicator is bit 16
        if tcam_physical_idx == TCAM_IPV6_HW_TCAMS_ORDER[-1]:
            is_row_ipv4 = (m & 1) and tcam_pysical_row != NUMBER_OF_ROWS_PER_TCAM_BANK - 1

        if is_row_ipv4:
            ret_key = lpm_prefix(0, width=1)
            payload = self.read_small_tcam_mem_row(core_idx, tcam_physical_idx, tcam_pysical_row)
            ret_l1_bucket, hit_width = self.parse_tcam_payload(payload)

            k >>= (TCAM_WIDTH - hit_width)
            m >>= (TCAM_WIDTH - hit_width)
            ret_key <<= hit_width
            ret_key.value |= (k & m)
            ret_valid = v

        # Key is IPv6:
        else:
            ret_key = lpm_prefix(1, width=1)
            # Long IPv6 can be found only on the first bankset (first 4 TCAMs)
            if row_idx < 4 * NUMBER_OF_ROWS_PER_TCAM_BANK:
                if row_idx >= NUMBER_OF_ROWS_PER_TCAM_BANK:
                    return lpm_tcam_entry(lpm_prefix(0, 0), False, payload=0, hit_width=0)

                search_range = TCAM_IPV6_HW_TCAMS_ORDER[:2] if row_idx >= TCAM_LONG_LINES else TCAM_IPV6_HW_TCAMS_ORDER
                tcam_mem_idx = 0
            else:
                if tcam_physical_idx & 1 != 1:
                    return lpm_tcam_entry(lpm_prefix(0, 0), False, payload=0, hit_width=0)
                search_range = [tcam_physical_idx, tcam_physical_idx - 1]
                tcam_mem_idx = search_range[-1]

            ret_valid = True
            for idx in search_range:
                k, m, v = self.read_small_tcam_row(core_idx, idx, tcam_pysical_row)
                key_width = bin(m).count('1') - 1 if v else 0
                ret_key <<= key_width
                ret_key.value |= (k >> (TCAM_WIDTH - key_width))
                ret_valid &= v
            payload = self.read_small_tcam_mem_row(core_idx, tcam_mem_idx, tcam_pysical_row)
            ret_l1_bucket, hit_width = self.parse_tcam_payload(payload)
        return lpm_tcam_entry(ret_key, ret_valid, payload=ret_l1_bucket, hit_width=hit_width + 1)

    # @brief Returns the number of l1 buckets.
    @abstractmethod
    def get_l1_number_of_buckets(self):
        pass

    # @brief Reads a L1 bucket.
    #
    # param[in]  core_idx       Core index to read.
    # param[in]  bucket_idx     Bucket index to read.
    # param[out] bucket         Bucket written in core core_idx with HW index bucket_idx.
    @abstractmethod
    def read_l1_bucket(self, core_idx, bucket_idx):
        pass

    # @brief Returns the number of l2 buckets.
    @abstractmethod
    def get_l2_number_of_buckets(self):
        pass

    # @brief Reads a L2 bucket.
    #
    # param[in]  core_idx       Core index to read.
    # param[in]  bucket_idx     Bucket index to read.
    # param[out] bucket         Bucket written in core core_idx with HW index bucket_idx.
    @abstractmethod
    def read_l2_bucket(self, core_idx, bucket_idx):
        pass

    # Generic TCAM functions implementation:

    def parse_tcam_payload(self, payload):
        l1_bucket_idx = get_bits(payload, TCAM_HIT_WIDTH_START - 1, TCAM_PAYLOAD_START)
        hit_width = get_bits(payload, TCAM_PAYLOAD_WIDTH - 1, TCAM_HIT_WIDTH_START)
        return l1_bucket_idx, hit_width

    # @Brief function to read tcam row as it one of four small TCAMS
    def read_small_tcam_row(self, core_idx, tcam_physical_idx, tcam_pysical_row):
        tcam_to_read_idx = tcam_physical_idx // 2
        tcam_read_line_number = NUMBER_OF_ROWS_PER_TCAM_BANK * (tcam_physical_idx % 2) + tcam_pysical_row
        return self.hw_src.read_core_lpm_tcam(core_idx, tcam_to_read_idx, tcam_read_line_number)

    # @Brief function to read tcam row as it one of four small TCAMS
    def read_small_tcam_mem_row(self, core_idx, tcam_physical_idx, tcam_pysical_row):
        tcam_to_read_idx = tcam_physical_idx // 2
        tcam_read_line_number = NUMBER_OF_ROWS_PER_TCAM_BANK * (tcam_physical_idx % 2) + tcam_pysical_row
        if tcam_to_read_idx > 1:
            tcam_read_line_number = (tcam_to_read_idx - 1) * 1024 + tcam_read_line_number
            tcam_to_read_idx = 1
        return self.hw_src.read_core_trie_mem(core_idx, tcam_to_read_idx, tcam_read_line_number)


class lpm_prefix:
    def __init__(self, val, width):
        self.value = val
        self.width = width
        self.is_ipv6 = (val >> (width - 1)) if width > 0 else 0

    def remove_msbs(self, number_of_bits):
        new_width = self.width - number_of_bits
        if new_width < 0:
            raise Exception("Width < 0")
        self.value = get_bits(self.value, new_width - 1, 0)
        self.width = new_width

    def remove_lsbs(self, number_of_bits):
        new_width = self.width - number_of_bits
        if new_width < 0:
            raise Exception("Width < 0")
        self.value >>= number_of_bits
        self.width = new_width

    @property
    def is_ipv4(self):
        return not self.is_ipv6

    def clone(self):
        retval = lpm_prefix(self.value, self.width)
        retval.is_ipv6 = self.is_ipv6
        return retval

    def __ilshift__(self, count):
        self.value <<= count
        self.width += count
        return self

    def __irshift__(self, count):
        self.value >>= count
        self.width -= count
        return self

    def get_msbs(self, number_of_bits):
        if number_of_bits > self.width:
            raise Exception("Requested too much bits.")
        value = self.value >> self.width - number_of_bits
        return lpm_prefix(value, number_of_bits)

    def is_containing(self, key):
        if self.width < key.width:
            return False
        return (self.value >> (self.width - key.width)) == key.value

    def __str__(self) -> str:
        return "prefix 0x%x width %d" % (self.value, self.width)

    def __eq__(self, other):
        return self.width == other.width and self.value == other.value


class lpm_tcam_entry:

    def __init__(self, key, valid, payload, hit_width):
        self.key = key
        self.valid = valid
        self.payload_l1_bucket = payload
        self.payload_hit_width = hit_width

    def __str__(self):
        return str(self.key) + " is valid? %d hit width %d payload 0x%x" % (self.valid,
                                                                            self.payload_l1_bucket, self.payload_hit_width)


class lpm_entry:

    def __init__(self, key, payload=None, valid=False, is_shared=False, is_leaf=None, index=0):
        self.key = key
        self.valid = valid
        self.payload = payload
        self.is_shared = is_shared
        self.is_leaf = is_leaf
        self.index = index

    def __str__(self):
        return str(self.key) + (" payload 0x%x " % self.payload) + "index %d is shared? %d" % (self.index, self.is_shared)\
            + (" is_leaf? %d" % (self.is_leaf) if self.is_leaf is not None else "")


class lpm_distributor_entry:

    def __init__(self, lpm_key, valid, group, core):
        self.key = lpm_key
        self.valid = valid
        self.group = group
        self.core = core

    def __eq__(self, other):
        if not self.valid and not other.valid:
            return True
        equal = True
        equal &= self.key == other.key
        equal &= self.group == other.group
        equal &= self.core == other.core
        return equal

    def __str__(self):
        return str(self.key) + " is valid? %d group %d core %d" % (self.valid, self.group, self.core)


class lpm_bucket:

    # in GB L1 default is pointer to L2
    def __init__(self):
        self.entries = []
        self.default = lpm_default(0)

    def __str__(self):
        retval = ""
        for entry in self.entries:
            retval += ("%s\n" % str(entry))
        retval += "Default Payload: 0x%x" % self.default.value
        return retval

    def __eq__(self, other):

        other_entries = sorted(other.entries, key=lambda e: (e.key.width, e.key.value))
        self_entries = sorted(self.entries, key=lambda e: (e.key.width, e.key.value))

        # Remove zero length entries which equal to defaults in order to be able to compare buckets based on logs and buckets based on HW.
        # In HW we write zero length entries as defaults while in logs they are printed as nodes.
        if len(other_entries) > 0 and other_entries[0].key.width == 0 and other_entries[0].payload == other.default.value:
            other_entries = list(filter(lambda e: e.key.width > 0, other_entries))

        if len(self_entries) > 0 and self_entries[0].key.width == 0 and self_entries[0].payload == self.default.value:
            self_entries = list(filter(lambda e: e.key.width > 0, self_entries))

        if not len(self_entries) == len(other_entries):
            return False

        equal = True
        for i in range(len(self.entries)):
            equal = equal and self_entries[i].key == other_entries[i].key
            equal = equal and self_entries[i].valid == other_entries[i].valid
            equal = equal and self_entries[i].payload == other_entries[i].payload
        equal = equal and self.default == other.default
        return equal

    def get_entries_payloads(self):
        ret_payloads = []
        for e in self.entries:
            ret_payloads.append(e.payload)
        return ret_payloads


class lpm_default:
    def __init__(self, value, is_pointer=False, default_hit_width=0):
        self.value = value
        self.is_pointer = is_pointer
        self.default_hit_width = default_hit_width

    def __eq__(self, other):
        return self.value == other.value and self.is_pointer == other.is_pointer and self.default_hit_width == other.default_hit_width
