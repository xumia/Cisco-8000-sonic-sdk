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

from lpm_model_base import lpm_model_base
from lpm_hw_source_pacific import NUMBER_OF_CORES
import sys
from typing import NamedTuple
from prettytable import PrettyTable
from lpm_hw_to_logic_converter_base import lpm_entry, lpm_prefix
from bit_utils import get_bits
import ipaddress

global_verbosity_level = 1
PRINT_TYPE_INFO = 0
PRINT_TYPE_ERROR = 1


class lpm_logical_model(lpm_model_base):

    def __init__(self, hw_to_logic_converter):
        self.converter = hw_to_logic_converter
        self.distributor = []
        for distributor_row in range(hw_to_logic_converter.get_distributor_number_of_rows()):
            distributor_entry = hw_to_logic_converter.read_distributor_row(distributor_row)
            self.distributor.append(distributor_entry)
        self.cores = [lpm_core(i) for i in range(NUMBER_OF_CORES)]
        for core in self.cores:
            for tcam_row in range(hw_to_logic_converter.get_tcam_number_of_rows()):
                tcam_entry = hw_to_logic_converter.read_tcam_row(core.id, tcam_row)
                core.tcam.append(tcam_entry)
            for l1_bucket_idx in range(hw_to_logic_converter.get_l1_number_of_buckets()):
                l1_bucket = hw_to_logic_converter.read_l1_bucket(core.id, l1_bucket_idx)
                core.l1_buckets.append(l1_bucket)
            for l2_bucket_idx in range(hw_to_logic_converter.get_l2_number_of_buckets()):
                l2_bucket = hw_to_logic_converter.read_l2_bucket(core.id, l2_bucket_idx)
                core.l2_buckets.append(l2_bucket)
        self.encode_key_func = hw_to_logic_converter.encode_lpm_key

    def lookup_distributor(self, key):
        return self.lookup_in_tcam_component(self.distributor, key)

    def lookup_tcam(self, core_idx, key):
        tcam_mem = self.cores[core_idx].tcam
        return self.lookup_in_tcam_component(tcam_mem, key)

    def lookup_in_tcam_component(self, tcam, key):
        for row_idx, entry in enumerate(tcam):
            if not entry.valid:
                continue
            if key.is_containing(entry.key):
                return entry, row_idx
        return None, None

    def lookup_in_bucket(self, bucket, key):
        bucket_entries = bucket.entries.copy()
        bucket_entries.sort(key=lambda e: e.key.width, reverse=True)
        for entry in bucket_entries:
            if entry.valid and key.is_containing(entry.key):
                return entry.key, entry.payload, False

        return None, bucket.default, True

    def lookup_key(self, key, vrf, ip_str, verbosity):
        global global_verbosity_level
        global_verbosity_level = verbosity
        remaining_key = key.clone()
        is_ipv6 = key.is_ipv6
        ret_l2_is_default = False

        distributor_entry, ret_distributor_row = self.lookup_distributor(remaining_key)
        ret_group = distributor_entry.group
        ret_core = distributor_entry.core
        if ret_distributor_row is None:
            severity_log('ERROR: Found Bug, Miss in distributor', severity=0, type=PRINT_TYPE_ERROR)
            return None

        severity_log('Distributor: Hit on line %d (key 0x%x  width %d) -> group %d -> core %d' % (
            ret_distributor_row, distributor_entry.key.value, distributor_entry.key.width, ret_group, ret_core), severity=1)

        tcam_entry, ret_tcam_hit_row = self.lookup_tcam(ret_core, remaining_key)

        if ret_tcam_hit_row is None:
            severity_log('ERROR: Found Bug, Miss in TCAM (group %d  core %d)' %
                         (ret_group, ret_core), severity=0, type=PRINT_TYPE_ERROR)
            return None

        ret_l1_bucket_idx = tcam_entry.payload_l1_bucket

        severity_log('TCAM: Hit on line %d (key 0x%x is_ipv6? %s  width %d) -> L1 row %d' %
                     (ret_tcam_hit_row, tcam_entry.key.value, is_ipv6, tcam_entry.payload_hit_width, ret_l1_bucket_idx), severity=1)

        if ret_l1_bucket_idx >= len(self.cores[ret_core].l1_buckets):
            severity_log(
                'ERROR: Found Bug, Miss in L1 (Invalid bucket) (group %d core %d tcam row %d  l1 bucket %d)' % (
                    ret_group, ret_core, ret_tcam_hit_row, ret_l1_bucket_idx), severity=0, type=PRINT_TYPE_ERROR)
            return None

        remaining_key.remove_msbs(tcam_entry.payload_hit_width)

        l1_bucket = self.cores[ret_core].l1_buckets[ret_l1_bucket_idx]
        hit_l1_key, hit_l1_payload, hit_l1_is_default = self.lookup_in_bucket(l1_bucket, remaining_key)

        ret_l2_bucket_idx = hit_l1_payload

        if hit_l1_is_default:
            severity_log('Miss in L1 Entries. Will use default', 1)
            if not hit_l1_payload.is_pointer:  # In Pacific L1 default is final payload.
                ret_payload = hit_l1_payload.value

                severity_log('prefix: original 0x%x  length %d  remaining 0x%x  length %d' %
                             (key.value, key.width, remaining_key.value, remaining_key.width), severity=1)
                severity_log('L1: Hit on bucket %d (Default) -> Final Payload 0x%x' % (ret_l1_bucket_idx, ret_payload), severity=1)

                severity_log('Lookup: VRF=%03d  IP=%s  G=%-3d  C=%-2d  T=%-5d  L1=%-4d  P=0x%05x' %
                             (vrf, ip_str, ret_group, ret_core, ret_tcam_hit_row, ret_l1_bucket_idx, ret_payload), severity=0)

                return lookup_result(
                    ret_distributor_row,
                    ret_group,
                    ret_core,
                    ret_tcam_hit_row,
                    ret_l1_bucket_idx,
                    True,
                    None,
                    None,
                    ret_payload)

            else:  # In GB L1 payload is pointer to L2
                ret_l2_bucket_idx = hit_l1_payload.value
                remaining_key = key.clone()
                new_width_to_remove = hit_l1_payload.default_hit_width
                remaining_key.remove_msbs(new_width_to_remove)
        else:
            remaining_key.remove_msbs(hit_l1_key.width)

        default_string = "(default)" if hit_l1_is_default else "(key 0x%x  width %d)" % (hit_l1_key.value, hit_l1_key.width)

        severity_log('L1: Hit on bucket %d %s -> L2 bucket %d' %
                     (ret_l1_bucket_idx, default_string, ret_l2_bucket_idx), severity=1)

        if ret_l2_bucket_idx >= len(self.cores[ret_core].l2_buckets):
            severity_log('ERROR: Found Bug, Miss in L2 (Invalid bucket) (group %d core %d tcam row %d  l1 bucket %d  l2 bucket %d)' % (
                ret_group, ret_core, ret_tcam_hit_row, ret_l1_bucket_idx, ret_l2_bucket_idx), severity=0, type=PRINT_TYPE_ERROR)
            return None

        l2_bucket = self.cores[ret_core].l2_buckets[ret_l2_bucket_idx]
        hit_l2_key, ret_payload, hit_l2_is_default = self.lookup_in_bucket(l2_bucket, remaining_key)

        if hit_l2_is_default:
            ret_l2_is_default = True
            ret_payload = ret_payload.value
            severity_log('Miss in L2 Entries. Will use default', severity=1)
            severity_log('prefix: original 0x%x  length %d  remaining 0x%x  length %d' %
                         (key.value, key.width, remaining_key.value, remaining_key.width), severity=1)
            severity_log('L2: Hit on bucket %d (Default) -> Final Payload 0x%x' % (ret_l2_bucket_idx, ret_payload), severity=1)

        else:
            severity_log('L2: Hit on bucket %d (key 0x%x  width %d) -> Final Payload 0x%x\n' %
                         (ret_l2_bucket_idx, hit_l2_key.value, hit_l2_key.width, ret_payload), severity=1)

        severity_log('Lookup: VRF=%03d  IP=%s  G=%-3d  C=%-2d  T=%-5d  L1=%-4d  L2=%-6d  P=0x%05x\n' %
                     (vrf, ip_str, ret_group, ret_core, ret_tcam_hit_row, ret_l1_bucket_idx, ret_l2_bucket_idx, ret_payload),
                     severity=0)

        return lookup_result(
            ret_distributor_row,
            ret_group,
            ret_core,
            ret_tcam_hit_row,
            ret_l1_bucket_idx,
            False,
            ret_l2_bucket_idx,
            ret_l2_is_default,
            ret_payload)

    def lookup(self, vrf, ip_str, verbosity=1):
        key = self.encode_key_func(vrf, ip_str)
        return self.lookup_key(key, vrf, ip_str, verbosity)

    def print_lpm(self, fp=None, skip_unreachable=True):
        fd = open(fp, "w") if fp is not None else sys.stdout
        print('================ LPM =================', file=fd)
        print('    --------- Distributor ------------', file=fd)
        for i, entry in enumerate(self.distributor):
            if not entry.valid:
                continue
            print('row %-3d: key 0x%020x  width %-4d group %-4d    core %-2d' %
                  (i, entry.key.value, entry.key.width, entry.group, entry.core), file=fd)
        print('', file=fd)
        for core_idx, core in enumerate(self.cores):
            print(' ~~~~~~~~~ Core %d ~~~~~~~~~~ ' % core_idx, file=fd)
            print(' ------------ Core %d::TCAM ------------- ' % core_idx, file=fd)
            tcam_payloads = []
            l1_payloads = []
            for k, tcam_entry in enumerate(core.tcam):
                if not tcam_entry.valid:
                    continue
                tcam_payloads.append(tcam_entry.payload_l1_bucket)
                print(
                    'row %-5d: key 0x%-40x  width %-4d  payload %-5d  IPv%d' %
                    (k,
                     tcam_entry.key.value,
                     tcam_entry.key.width,
                     tcam_entry.payload_l1_bucket,
                     6 if tcam_entry.key.is_ipv6 else 4), file=fd)

            print(' ------------- Core %d::L1 -------------- ' % core_idx, file=fd)
            for k, l1_bucket in enumerate(core.l1_buckets):
                is_pointed_by_tcam = k in tcam_payloads
                if not is_pointed_by_tcam and skip_unreachable:
                    continue
                print('L1 Bucket %-5d:%s' % (k, ' (unreachable)' if not is_pointed_by_tcam else ''), file=fd)
                for e in l1_bucket.entries:
                    if is_pointed_by_tcam:
                        l1_payloads.append(e.payload)
                    print('key 0x%08x  width %-3d  payload %-5d' % (e.key.value, e.key.width, e.payload), file=fd)
                if l1_bucket.default is None:
                    print('Default: None', file=fd)
                else:
                    if l1_bucket.default.is_pointer:
                        print('Default: L2 pointer 0x%05x Width to recover %d' %
                              (l1_bucket.default.value, l1_bucket.default.default_hit_width), file=fd)
                    else:
                        print('Default: payload 0x%05x' % (l1_bucket.default.value), file=fd)
                print(' ----- ', file=fd)

            print(' ------------- Core %d::L2 -------------- ' % core_idx, file=fd)
            for k, l2_bucket in enumerate(core.l2_buckets):
                is_pointed_by_l1 = k in l1_payloads
                if not is_pointed_by_l1 and skip_unreachable:
                    continue
                print('L2 Bucket %-5d:%s' % (k, ' (unreachable)' if not is_pointed_by_l1 else ' '), file=fd)
                for e in l2_bucket.entries:
                    print('key 0x%08x  width %-3d  payload 0x%05x' % (e.key.value, e.key.width, e.payload), file=fd)
                if l2_bucket.default is None:
                    print('Default: None', file=fd)
                else:
                    print('Default: payload 0x%05x' % (l2_bucket.default.value), file=fd)
                print(' ----- ', file=fd)
            print('', file=fd)
        if fp is not None:
            fd.close()

    def compare(self, model2, verbose=True):
        def print_if_verbose(str):
            FAIL_COLOR = '\033[91m'
            ENDC = '\033[0m'
            if verbose:
                print(FAIL_COLOR + str + ENDC)

        if not len(self.distributor) == len(model2.distributor):
            print_if_verbose("Distributors number of rows don't match %d != %d" % (len(self.distributor), len(model2.distributor)))
            return False

        for line_idx in range(len(self.distributor)):
            if not self.distributor[line_idx] == model2.distributor[line_idx]:
                print_if_verbose("Distributors entries in line %d don't match :" % line_idx)
                print_if_verbose(
                    "Key 0x%x width %d valid %d group %d core %d" %
                    (self.distributor[line_idx].key.value,
                     self.distributor[line_idx].key.width,
                     self.distributor[line_idx].valid,
                     self.distributor[line_idx].group,
                     self.distributor[line_idx].core))
                print_if_verbose(
                    "Key 0x%x width %d valid %d group %d core %d" %
                    (model2.distributor[line_idx].key.value,
                     model2.distributor[line_idx].key.width,
                     model2.distributor[line_idx].valid,
                     model2.distributor[line_idx].group,
                     model2.distributor[line_idx].core))
                return False

        if not len(self.cores) == len(model2.cores):
            print_if_verbose("Number of cores don't match %d != %d" % (len(self.cores), len(model2.cores)))
            return False

        for i in range(len(self.cores)):
            core1, core2 = self.cores[i], model2.cores[i]

            if not len(core1.tcam) == len(core2.tcam):
                print_if_verbose("Number of TCAM rows don't match. %d != %d" % (len(core1.tcam), len(core2.tcam)))
                return False
            tcam_payloads = []
            for tcam_idx in range(len(core1.tcam)):
                if core1.tcam[tcam_idx].valid == core2.tcam[tcam_idx].valid and core2.tcam[tcam_idx].valid == 0:
                    continue
                tcam_equal = True
                tcam_equal &= core1.tcam[tcam_idx].key == core2.tcam[tcam_idx].key
                tcam_equal &= core1.tcam[tcam_idx].payload_hit_width == core2.tcam[tcam_idx].payload_hit_width
                tcam_equal &= core1.tcam[tcam_idx].valid == core2.tcam[tcam_idx].valid
                tcam_equal &= core1.tcam[tcam_idx].payload_l1_bucket == core2.tcam[tcam_idx].payload_l1_bucket
                if not tcam_equal:
                    print_if_verbose("TCAM entries mismatch in core %d line %s:" % (i, tcam_idx))
                    print_if_verbose(
                        "key 0x%x width %d payload %d valid %d" %
                        (core1.tcam[tcam_idx].key.value,
                         core1.tcam[tcam_idx].key.width,
                         core1.tcam[tcam_idx].payload_l1_bucket,
                         core1.tcam[tcam_idx].valid))
                    print_if_verbose(
                        "key 0x%x width %d payload %d valid %d" %
                        (core2.tcam[tcam_idx].key.value,
                         core2.tcam[tcam_idx].key.width,
                         core2.tcam[tcam_idx].payload_l1_bucket,
                         core2.tcam[tcam_idx].valid))
                    return False
                tcam_payloads.append(core1.tcam[tcam_idx].payload_l1_bucket)

            l1_payloads = []
            for l1_idx in range(len(core1.l1_buckets)):
                if l1_idx not in tcam_payloads:
                    continue
                if not core1.l1_buckets[l1_idx] == core2.l1_buckets[l1_idx]:
                    print_if_verbose("Mismatch: Core %d level L1 Bucket index %d." % (i, l1_idx))
                    return False
                l1_payloads += core1.l1_buckets[l1_idx].get_entries_payloads()
                if core1.l1_buckets[l1_idx].default.is_pointer:
                    l1_payloads.append(core1.l1_buckets[l1_idx].default.value)

            for l2_idx in range(len(core1.l2_buckets)):
                if l2_idx not in l1_payloads:
                    continue
                if not core1.l2_buckets[l2_idx] == core2.l2_buckets[l2_idx]:
                    print_if_verbose("Mismatch: Core %d level L2 Bucket index %d." % (i, l2_idx))
                    return False
        return True

    def print_prefixes(self, fp):
        # Gather keys
        keys_in_lpm = set()
        for core in self.cores:
            for tcam_entry in core.tcam:
                if not tcam_entry.valid:
                    continue
                tcam_width = tcam_entry.payload_hit_width
                tcam_key = tcam_entry.key.value >> (tcam_entry.key.width - tcam_width)
                l1_bucket = core.l1_buckets[tcam_entry.payload_l1_bucket]
                for l1_entry in (l1_bucket.entries):
                    l1_key = (tcam_key << l1_entry.key.width) | l1_entry.key.value
                    l1_width = tcam_width + l1_entry.key.width
                    l2_bucket = core.l2_buckets[l1_entry.payload]
                    for l2_entry in l2_bucket.entries:
                        l2_key = (l1_key << l2_entry.key.width) | l2_entry.key.value
                        l2_width = l1_width + l2_entry.key.width
                        keys_in_lpm.add((l2_key, l2_width, l2_entry.payload))

        # Convert keys to string and print
        vrf_length = 11
        table = PrettyTable()
        table.field_names = ["VRF", "Prefix", "Payload"]
        for key, width, payload in keys_in_lpm:
            if width < vrf_length + 1:
                table.add_row(["LPM internal", hex(key), hex(payload)])
                continue
            else:
                vrf_str = hex(get_bits(key, width - 2, width - vrf_length - 1))
                prefix_str = key_to_str(key, width)
                payload_str = hex(payload)
                table.add_row([vrf_str, prefix_str, payload_str])
        with open(fp, "w") as fp:
            print(table.get_string(sortby='VRF', sort_key=lambda row: int(row[0], 16)), file=fp)


def key_to_str(key, width):
    vrf_length = 11
    if width == vrf_length + 1:
        return "0.0.0.0/0"
    decoded_prefix, decoded_width = decode_prefix(key, width)
    is_ipv6 = bool(get_bits(key, width - 1, width - 1))
    full_ip_width = 128 if is_ipv6 else 32
    ip_width = decoded_width - vrf_length - 1
    ip_value = get_bits(decoded_prefix, ip_width - 1, 0) << full_ip_width - ip_width
    ip_constructor = ipaddress.IPv6Address if is_ipv6 else ipaddress.IPv4Address
    return "%s/%d" % (str(ip_constructor(ip_value)), ip_width)


def decode_prefix(prefix, width):
    is_ipv6 = (prefix >> (width - 1)) == 1
    if is_ipv6:
        return (prefix, width)

    broken_bit = 20
    encoded_key_len = 45
    bits_above_broken_bit = encoded_key_len - (broken_bit + 1)
    if width <= bits_above_broken_bit:
        return (prefix, width)

    assert encoded_key_len >= width
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


class lpm_core:
    def __init__(self, core_id):
        self.id = core_id
        self.tcam = []
        self.l1_buckets = []
        self.l2_buckets = []


class lookup_result(NamedTuple):
    distributor_row: int
    group: int
    core: int
    tcam_row: int
    l1_bucket_idx: int
    is_l1_default: bool
    l2_bucket_idx: int
    is_l2_default: bool
    payload: int


def severity_log(txt, severity=0, type=PRINT_TYPE_INFO):
    FAIL_COLOR = '\033[91m'
    ENDC = '\033[0m'

    if type == PRINT_TYPE_ERROR:
        txt = FAIL_COLOR + txt + ENDC
    if global_verbosity_level > severity:
        print(txt)
