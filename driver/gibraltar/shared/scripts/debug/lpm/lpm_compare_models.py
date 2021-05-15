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

from lpm_debug_utils import lpm_helper
import gzip
import json
from typing import NamedTuple
import argparse
from copy import deepcopy


class lpm_key(NamedTuple):
    value: int
    width: int


class lpm_entry(NamedTuple):
    value: int
    width: int
    payload: int


class lpm_bucket():

    def __init__(self, root=None, default=None, hw_index=None):
        self.root = root
        self.default = default
        self.hw_index = hw_index
        self.entries = []


def print_if_verbose(printable_object, verbose):
    if verbose:
        print(printable_object)


def get_logically_equivalent_l2_bucket(l2_bucket):
    """
    This function return a logically equivalent bucket in the sense of default entries inside the bucket.
    Arguments:
        l2_bucket{lpm_bucket} -- L2 bucket to remove it's duplication of default representations.
    Returns:
        A logically equivalent bucket.
    """
    l2_bucket = deepcopy(l2_bucket)
    if len(l2_bucket.entries) == 0:
        return l2_bucket

    if len(l2_bucket.entries) == 1 and l2_bucket.entries[0].width == 0:
        l2_bucket.default = l2_bucket.entries[0].payload
        l2_bucket.entries = []
        return l2_bucket

    if len(l2_bucket.entries) == 2:
        entry0_width = l2_bucket.entries[0].width - l2_bucket.root.width
        entry1_width = l2_bucket.entries[1].width - l2_bucket.root.width
        assert entry0_width >= 0 and entry1_width >= 0

        if entry0_width == 1 and entry1_width == 1:
            entry0_lsb = l2_bucket.entries[0].value & 1
            entry1_lsb = l2_bucket.entries[1].value & 1
            assert (entry0_lsb != entry1_lsb)
            if l2_bucket.entries[0].payload == l2_bucket.entries[1].payload:
                l2_bucket.default = l2_bucket.entries[0].payload
                l2_bucket.entries = []
                return l2_bucket

    for entry in l2_bucket.entries:
        if l2_bucket.root.width == entry.width:
            l2_bucket.entries.remove(entry)
            l2_bucket.default = entry.payload
            return l2_bucket

    return l2_bucket


def extract_buckets_from_sw_model(lpm_dump):
    """
    Extract the cores' L1 and L2 buckets from LPM json dump.
    Arguments:
        lpm_dump -- LPM json dump to extract the buckets from.
    Returns:
        cores {list} -- a list of (l1_buckets,l2_buckets) where l1/2_buckets is a dictionary of L1/2 roots -> L1/2 buckets.
    """

    return get_buckets_from_sw_tree_dump(lpm_dump["tree"])


def get_buckets_from_sw_tree_dump(tree_dump):
    """
    Extract L1 and L2 buckets per core from LPM dump.
    Arguments:
        lpm_dump -- LPM dump to extract the buckets from.
    Returns:
        tuple -- a list of cores where a core is a tuple (l1_buckets,l2_buckets) where l1/2_buckets is a dictionary of L1/2 roots -> L1/2 buckets.
    """
    def extract_buckets_from_tree(node, current_l1, current_l2, current_core, cores):

        data = node["bucketing_data"]

        if data['l1_sw_index'] != -1:
            l1_index = str(data['l1_sw_index'])

            current_core = tree_dump["buckets"]["l1_buckets"][l1_index]["core"]
            l1_buckets = cores[current_core][0]

            l1_root_value = int(
                tree_dump['buckets']["l1_buckets"][l1_index]["root"]["key"], 16)
            l1_root_width = int(
                tree_dump['buckets']["l1_buckets"][l1_index]["root"]["key_width"])

            current_l1 = l1_root = lpm_key(l1_root_value, l1_root_width)
            default_payload = tree_dump['buckets']["l1_buckets"][l1_index]["default_payload"]
            hw_index = tree_dump['buckets']["l1_buckets"][l1_index]["hw_index"]
            assert l1_buckets is not None
            l1_buckets[l1_root] = lpm_bucket(
                root=l1_root, default=default_payload, hw_index=hw_index)

        if data['l2_sw_index'] != -1:
            assert current_l1 is not None
            assert current_core is not None

            l1_buckets = cores[current_core][0]
            l2_buckets = cores[current_core][1]

            l2_index = str(data['l2_sw_index'])
            l2_root_value = int(
                tree_dump['buckets']["l2_buckets"][l2_index]["root"]["key"], 16)
            l2_root_width = tree_dump['buckets']["l2_buckets"][l2_index]["root"]["key_width"]
            current_l2 = l2_root = lpm_key(l2_root_value, l2_root_width)

            default_payload = tree_dump['buckets']["l2_buckets"][l2_index]["default_payload"]
            hw_index = tree_dump['buckets']["l2_buckets"][l2_index]["hw_index"]
            l2_buckets[l2_root] = lpm_bucket(
                root=l2_root, default=default_payload, hw_index=hw_index)

            l1_buckets[current_l1].entries.append(l2_root)

        if node["is_valid"] or data["group_id"] != -1:
            assert current_l2 is not None
            assert current_core is not None

            l2_buckets = cores[current_core][1]

            entry = lpm_entry(
                int(node['key'], 16), node['key_width'], node['payload'])

            l2_buckets[current_l2].entries.append(entry)

        if 'left' in node:
            extract_buckets_from_tree(node['left'], current_l1,
                                      current_l2, current_core, cores)
        if 'right' in node:
            extract_buckets_from_tree(node['right'], current_l1,
                                      current_l2, current_core, cores)

    cores = [[{}, {}] for _ in range(16)]

    extract_buckets_from_tree(
        tree_dump["root"], None, None, None, cores)

    return cores


def extract_buckets_from_hw_model(hw_model):
    """
    Extract the cores' L1 and L2 buckets from LPM HW model.
    Arguments:
        hw_model -- Logical model of the LPM hardware.
    Returns:
        cores {list} -- a list of (l1_buckets,l2_buckets) where l1/2_buckets is a dictionary of L1/2 roots -> L1/2 buckets.
    """

    cores = []
    for core_idx, core in enumerate(hw_model.cores):
        l1_buckets_dict = {}
        l2_buckets_dict = {}
        # Skip TCAM last bucket which is written to HW by default.
        for tcam_entry_idx, tcam_entry in enumerate(core.tcam[:-1]):
            if tcam_entry.valid:
                l1_root_value = tcam_entry.key.value
                l1_root_width = tcam_entry.key.width
                l1_root = lpm_key(l1_root_value, l1_root_width)
                l1_hw_index = tcam_entry.payload_l1_bucket
                if l1_hw_index >= len(core.l1_buckets):
                    print("Warning: TCAM line %d points to exceeds L1 bucket: %d" % (tcam_entry_idx, l1_hw_index))
                    # In case bucket is out of range, we would still like the comparison to
                    # continue in order to determine whether the issue occurs in SW too.
                    l1_buckets_dict[l1_root] = lpm_bucket(
                        root=l1_root, default=-1, hw_index=l1_hw_index)
                    continue

                else:
                    l1_bucket = core.l1_buckets[l1_hw_index]
                    l1_buckets_dict[l1_root] = lpm_bucket(
                        root=l1_root, default=l1_bucket.default.value, hw_index=l1_hw_index)

                # This patch is due to HW bug which limits the TCAM hit length to 128.
                if l1_root_width > 128:
                    l1_root_value >>= l1_root_width - 128
                    l1_root_width = 128

                for l1_entry in l1_bucket.entries:
                    l2_root_value = (
                        l1_root_value << l1_entry.key.width) | l1_entry.key.value
                    l2_root_width = l1_root_width + l1_entry.key.width
                    l2_root = lpm_key(l2_root_value, l2_root_width)
                    l1_buckets_dict[l1_root].entries.append(l2_root)

                    l2_hw_index = l1_entry.payload
                    if (l2_hw_index > len(core.l2_buckets)):
                        print("Warning: L1 bucket %d points to exceeds L2 bucket: %d" % (l1_hw_index, l2_hw_index))
                        continue
                    l2_bucket = core.l2_buckets[l2_hw_index]
                    l2_buckets_dict[l2_root] = lpm_bucket(
                        root=l2_root, default=l2_bucket.default.value, hw_index=l2_hw_index)

                    for entry in l2_bucket.entries:
                        entry_value = (l2_root_value <<
                                       entry.key.width) | entry.key.value
                        entry_width = l2_root_width + entry.key.width
                        final_entry = lpm_entry(
                            entry_value, entry_width, entry.payload)

                        l2_buckets_dict[l2_root].entries.append(final_entry)

        cores.append((l1_buckets_dict, l2_buckets_dict))

    return cores


def compare_buckets(core_idx, level, lhs_bucket, rhs_bucket, verbose):
    """
    This function compares between two buckets of given level.
    Arguments:
        core_idx -- Core index the buckets belong to.
        level {str} -- buckets' level, "L1" or "L2".
        lhs_bucket {lpm_bucket} -- Left hand side bucket to compare.
        rhs_bucket {lpm_bucket} -- Right hand side bucket to compare.
        verbose {bool} -- Bool whether to print compare results.
    Returns:
        Bool -- Bool whether the left hand side bucket is equal to the right hand side bucket.
    """
    assert lhs_bucket.root == rhs_bucket.root
    assert level in ["L1", "L2"]

    if level == "L2":
        lhs_bucket = get_logically_equivalent_l2_bucket(lhs_bucket)
        rhs_bucket = get_logically_equivalent_l2_bucket(rhs_bucket)

    root = lhs_bucket.root
    if lhs_bucket.default != rhs_bucket.default:
        print_if_verbose("Core %d: Default value of %s bucket with root 0x%x/%d is not equal. 0x%x != 0x%x" %
                         (core_idx, level, root.value, root.width, lhs_bucket.default, rhs_bucket.default), verbose)
        return False

    if lhs_bucket.hw_index != rhs_bucket.hw_index:
        print_if_verbose("Core %d: HW index of %s bucket with root 0x%x/%d is not equal. 0x%x != 0x%x" %
                         (core_idx, level, root.value, root.width, lhs_bucket.hw_index, rhs_bucket.hw_index), verbose)
        return False

    lhs_entries = set(lhs_bucket.entries)
    rhs_entries = set(rhs_bucket.entries)
    if lhs_entries != rhs_entries:
        print_if_verbose("Core %d: %s entries of %s with root 0x%x/%d and HW index %d are not equal" %
                         (core_idx, level, level, root.value, root.width, lhs_bucket.hw_index), verbose)
        print_if_verbose("Left hand side entries:", verbose)
        print_if_verbose(sorted(list(lhs_entries)), verbose)
        print_if_verbose("Right hand side entries:", verbose)
        print_if_verbose(sorted(list(rhs_entries)), verbose)
        return False

    return True


def compare_cores_level_buckets(core_idx, level, lhs_buckets, rhs_buckets, verbose):
    """
    This function compares between all buckets in core of given level where {lhs,rhs}_buckets are root->bucket dictionary.
    Arguments:
        core_idx -- Core index the buckets belong to.
        level {str} -- buckets' level, "L1" or "L2".
        lhs_buckets -- Left hand side buckets to compare.
        rhs_buckets -- Right hand side buckets to compare.
        verbose {bool} -- Bool whether to print compare results.
    Returns:
        Bool -- Bool whether the left hand side buckets are equal to the right hand side buckets.
    """

    lhs_roots = set(lhs_buckets.keys())
    rhs_roots = set(rhs_buckets.keys())

    if lhs_roots != rhs_roots:
        print_if_verbose(
            "Core %d: %s roots are not equal in both models, different L1 roots:" % (core_idx, level), verbose)
        print_if_verbose("Left hand side different roots:", verbose)
        print_if_verbose(lhs_roots - rhs_roots, verbose)
        print_if_verbose("Right hand side different roots:", verbose)
        print_if_verbose(rhs_roots - lhs_roots, verbose)
        return False

    for root in lhs_roots:
        if not compare_buckets(core_idx, level, lhs_buckets[root], rhs_buckets[root], verbose):
            return False
    return True


def compare_cores(core_idx, lhs_buckets, rhs_buckets, verbose=True):
    """
    This function compares between tuple of (l1_buckets,l2_buckets) of a core where l1/2_buckets is a dictionary of L1/2 roots -> L1/2 buckets.
    Arguments:
        core_idx -- Core index that is being compared.
        lhs_buckets -- Left hand side (l1_buckets,l2_buckets) to compare.
        rhs_buckets -- Right hand side (l1_buckets,l2_buckets) to compare.
        verbose {bool} -- Bool whether to print compare results.
    Returns:
        Bool -- Bool whether the left hand side buckets are equal to the right hand side buckets.
    """

    lhs_l1_buckets, lhs_l2_buckets = lhs_buckets
    rhs_l1_buckets, rhs_l2_buckets = rhs_buckets

    equal = True
    equal = compare_cores_level_buckets(
        core_idx, "L1", lhs_l1_buckets, rhs_l1_buckets, verbose) and equal
    equal = compare_cores_level_buckets(
        core_idx, "L2", lhs_l2_buckets, rhs_l2_buckets, verbose) and equal

    return equal


def get_cores_buckets_from_path(model_path, device):
    """
    Returns the model's cores' bucket from a model in given path, model can be HW model or SW model.
    Arguments:
        model_path -- Model path, CSV HW memory dump or GZ logical LPM json dump.
    Returns:
        list -- Cores list where every core is (l1_bucket,l2_buckets) tuple.
    """
    assert device in ["PACIFIC", "GB"]
    suffix = model_path.split(".")[-1]
    if suffix == "gz":
        with gzip.open(model_path) as lpm_dump_file:
            lpm_dump = json.loads(lpm_dump_file.read())
            cores_buckets = extract_buckets_from_sw_model(lpm_dump)
    if suffix == "csv":
        device = lpm_helper.PACIFIC if device == 'PACIFIC' else lpm_helper.GB
        lpm_debug = lpm_helper.load_from_csv(model_path, device)
        hw_model = lpm_debug.get_lpm_model()
        cores_buckets = extract_buckets_from_hw_model(hw_model)

    return cores_buckets


def compare_models(lhs_model, rhs_model, device_type):
    lhs_core_buckets = get_cores_buckets_from_path(lhs_model, device_type)
    rhs_core_buckets = get_cores_buckets_from_path(rhs_model, device_type)
    check_len_of_core = len(lhs_core_buckets) == len(rhs_core_buckets)
    assert(check_len_of_core)
    num_of_cores = len(lhs_core_buckets)
    equal = True
    for core_idx in range(num_of_cores):
        if lhs_core_buckets[core_idx] == rhs_core_buckets[core_idx] == [{}, {}]:
            continue

        equal = compare_cores(
            core_idx, lhs_core_buckets[core_idx], rhs_core_buckets[core_idx], verbose=True) and equal

    return equal


if __name__ == "__main__":
    SCRIPT_DESCRIPTION = "This script compares between HW CSV dump and logical LPM json dump."
    parser = argparse.ArgumentParser(description=SCRIPT_DESCRIPTION)

    parser.add_argument('models', type=str, nargs=2,
                        help="The path of the LPM models (Whether LPM memory CSV format or logical LPM jsom dump (gzipped).")

    parser.add_argument('device', nargs='?',
                        help="The device of the LPM models {PACIFIC,GB}.", choices=["PACIFIC", "GB"], default="PACIFIC")

    args = parser.parse_args()
    equal = compare_models(args.models[0], args.models[1], args.device)
    assert(equal)
