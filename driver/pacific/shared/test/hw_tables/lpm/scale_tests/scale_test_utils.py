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

import lpm_test_utils
import math
import hw_tablescli
import ipaddress
import random
from parser_formats import lpm_instruction
from genereate_lookups import generate_lookups_for_instructions
from lpm_test_utils import PAYLOAD_WIDTH
from collections import OrderedDict
from argument_parser import args_parser

BASE_IPV4_PREFIX = ipaddress.IPv4Network('10.0.0.0/24')
BASE_IPV6_PREFIX = ipaddress.IPv6Network('4000:0::/64')


class lpm_prefix:
    def __init__(self, vrf, ip):
        self.vrf = vrf
        self.ip_network = ip

    def get_key_value(self):
        prefix_len = self.ip_network.prefixlen
        max_length = self.ip_network.max_prefixlen
        is_ipv6 = self.ip_network.version == 6
        key_value = is_ipv6 << (lpm_test_utils.VRF_LENGTH + prefix_len) | self.vrf << prefix_len
        key_value |= int(self.ip_network.network_address) >> (max_length - prefix_len)
        return key_value

    def __hash__(self):
        return hash((self.get_key_value(), self.ip_network.prefixlen))

    def __eq__(self, other):
        return isinstance(other, type(self)) and (self.ip_network == other.ip_network and self.vrf == other.vrf)


# Generate num_entries consecutive prefixes starting from base_prefix to max in that range
def generate_consecutive_prefixes(num_entries, base_prefix=BASE_IPV4_PREFIX, vrf=0, step=1, fail=True):
    assert vrf >= 0 and vrf < (2 ** lpm_test_utils.VRF_LENGTH)
    assert num_entries >= 0
    ip_base = base_prefix.network_address
    prefix_len = base_prefix.prefixlen
    log_stride = base_prefix.max_prefixlen - prefix_len
    prefix_list = []
    try:
        for i in range(num_entries):
            prefix = ip_base + ((i * step) << log_stride)
            ip = ipaddress.ip_network((prefix, prefix_len))
            prefix_list.append(lpm_prefix(vrf, ip))
    except ipaddress.AddressValueError as ae:
        if fail:
            print("Out of range! Prefix length too small to generate %d number of entries" % num_entries)
            raise ae
        else:
            return prefix_list
    assert num_entries == len(prefix_list)
    return prefix_list


def lpm_generate_and_insert_consecutive_prefixes(logical_lpm, num_entries, prefix=BASE_IPV4_PREFIX, vrf=0, step=1, shuffle=False):
    prefixes = generate_consecutive_prefixes(num_entries, prefix, vrf, step)
    if shuffle or args_parser.random:
        random_generator = random.Random(0 if args_parser.seed is None else args_parser.seed)
        random_generator.shuffle(prefixes)
    do_lpm_insert_and_verify_prefixes(logical_lpm, num_entries, prefixes)


def perform_action(logical_lpm, instruction):
    key_value, key_width = instruction.get_key_and_width()
    key = lpm_test_utils.generate_lpm_key(key_value, key_width)
    if instruction.action == lpm_instruction.INSERT:
        payload = payload_value
        status = logical_lpm.insert(key, payload)
    elif instruction.action == lpm_instruction.REMOVE:
        status = logical_lpm.remove(key)
    elif instruction.action == lpm_instruction.MODIFY:
        payload = payload_value
        status = logical_lpm.modify(key, payload)
    else:
        print("Unrecognized lpm action!")
        raise ValueError("Invalid action")
    assert status is None


# Insert set of prefixes and verify
def do_lpm_insert_and_verify_prefixes(logical_lpm, num_entries, prefixes, fail_on_oor=True):
    assert len(prefixes) == num_entries
    inserted_entries = 0
    instructions = []
    random_generator = random.Random(0 if args_parser.seed is None else args_parser.seed)
    for prefix in prefixes:
        try:
            payload = random_generator.randint(0, (1 << PAYLOAD_WIDTH) - 1)
            instruction = lpm_instruction(lpm_instruction.INSERT, prefix.ip_network, prefix.vrf, payload)
            perform_action(logical_lpm, instruction)
            inserted_entries += 1
            instructions.append(instruction)
        except hw_tablescli.BaseException as e:
            lpm_test_utils.print_utilization(logical_lpm)
            if fail_on_oor:
                print("Error: Failed inserting prefix! Succeeded number of prefixes %d out of %d" % (inserted_entries, num_entries))
                raise e
            else:
                break
    print("Successfully inserted %d prefixes out of %d!" % (inserted_entries, num_entries))
    assert (not fail_on_oor) or (inserted_entries == num_entries)
    verify_correctness(logical_lpm, instructions)


# Generates set of addresses and performs lookup
def verify_correctness(logical_lpm, instructions):
    if args_parser.disable_verify:
        return
    incorrect_lookups = 0
    lookups = generate_lookups_for_instructions(instructions)
    for prefix_value, prefix_length, payload in lookups:
        lookup_key = lpm_test_utils.generate_lpm_key(prefix_value, prefix_length)
        result = logical_lpm.lookup(lookup_key)
        if result[1] != payload:
            incorrect_lookups += 1

    if incorrect_lookups > 0:
        print("Incorrect lookups occured: %d out of %d " % (incorrect_lookups, len(lookups)))
    assert incorrect_lookups == 0


def lpm_generate_and_insert_consecutive_groups(logical_lpm, base_prefixes, distribution, vrf=0, shuffle=False):
    prefixes = lpm_generate_consecutive_groups(base_prefixes, distribution, vrf)
    if shuffle or args_parser.random:
        random_generator = random.Random(0 if args_parser.seed is None else args_parser.seed)
        random_generator.shuffle(prefixes)
    do_lpm_insert_and_verify_prefixes(logical_lpm, len(prefixes), prefixes)


# Generates different groups of consecutive prefixes
def lpm_generate_consecutive_groups(base_prefixes, distribution, vrf, step=1, fail_on_overlap=True):
    assert len(base_prefixes) == len(distribution)
    prefixes = []
    for index, base_prefix in enumerate(base_prefixes):
        num_entries = distribution[index]
        prefixes += generate_consecutive_prefixes(num_entries, base_prefix, vrf, step, fail_on_overlap)
    unique_prefixes = list(OrderedDict.fromkeys(prefixes))
    if fail_on_overlap and len(unique_prefixes) != len(prefixes):
        raise Exception('Error: Base prefixes overlap!')
    elif not fail_on_overlap:
        return list(unique_prefixes)
    return prefixes


def lpm_generate_and_insert_many_groups_of_consecutive_prefixes(
        logical_lpm, base_prefix, vrf, num_groups, num_entries_per_group, group_prefix_length):
    prefixes = generate_many_groups_of_consecutive_prefixes(
        base_prefix, vrf, num_groups, num_entries_per_group, group_prefix_length)
    if args_parser.random:
        random_generator = random.Random(0 if args_parser.seed is None else args_parser.seed)
        random_generator.shuffle(prefixes)
    do_lpm_insert_and_verify_prefixes(logical_lpm, len(prefixes), prefixes)


def generate_many_groups_of_consecutive_prefixes(base_prefix, vrf, num_groups, num_entries_per_group, group_prefix_length):
    assert num_groups > 0 and num_entries_per_group > 0 and group_prefix_length > 0
    if math.ceil(math.log2(num_groups)) > group_prefix_length:
        raise Exception('Error: Not enough width to generate groups!')
    distribution = []
    base_prefixes = []
    prefix_len = base_prefix.prefixlen
    max_prefixlen = base_prefix.max_prefixlen
    assert group_prefix_length + math.ceil(math.log2(num_entries_per_group)) <= prefix_len
    base_ip = base_prefix.network_address
    log_stride = max_prefixlen - group_prefix_length
    for i in range(num_groups):
        base = base_ip + (i << log_stride)
        base_prefixes.append(ipaddress.ip_network((base, prefix_len)))
        distribution.append(num_entries_per_group)
    prefixes = lpm_generate_consecutive_groups(base_prefixes, distribution, vrf)
    return prefixes


def do_lpm_remove_prefixes(logical_lpm, prefixes, num_entries):
    removed_entries = 0
    random_generator = random.Random(0 if args_parser.seed is None else args_parser.seed)
    for prefix in prefixes:
        try:
            payload = random_generator.randint(0, (1 << PAYLOAD_WIDTH) - 1)
            instruction = lpm_instruction(lpm_instruction.REMOVE, prefix.ip_network, prefix.vrf, payload)
            perform_action(logical_lpm, instruction)
            removed_entries += 1
        except hw_tablescli.BaseException as e:
            print("Error: Removed %d prefixes out of %d" % (removed_entries, num_entries))
            raise e
    assert removed_entries == num_entries
    print("Successfully removed %d prefixes out of %d!" % (removed_entries, num_entries))


def lpm_insert_remove_consecutive_prefixes(logical_lpm, num_entries, base_prefix=BASE_IPV4_PREFIX, vrf=0, shuffle=False):
    prefixes = generate_consecutive_prefixes(num_entries, base_prefix, vrf)
    if shuffle or args_parser.random:
        random_generator = random.Random(0 if args_parser.seed is None else args_parser.seed)
        random_generator.shuffle(prefixes)
    do_lpm_insert_and_verify_prefixes(logical_lpm, num_entries, prefixes)
    do_lpm_remove_prefixes(logical_lpm, prefixes, num_entries)


def lpm_insert_remove_consecutive_prefixes_many_rounds(
        logical_lpm,
        num_entries,
        base_prefix,
        vrf=0,
        num_to_delete=None,
        rounds=1,
        shuffle=False):
    if num_to_delete is None:
        num_to_delete = num_entries
    assert num_to_delete <= num_entries and num_to_delete >= 0
    assert rounds > 0
    prefixes = generate_consecutive_prefixes(num_entries, base_prefix, vrf)
    do_lpm_insert_and_verify_prefixes(logical_lpm, num_entries, prefixes)
    random_generator = random.Random(0 if args_parser.seed is None else args_parser.seed)
    prefixes_to_remove = prefixes[:num_to_delete] if shuffle == False else random_generator.sample(prefixes, num_to_delete)
    for i in range(rounds):
        do_lpm_remove_prefixes(logical_lpm, prefixes_to_remove, num_to_delete)
        print("Inserting entries that are removed in round %d" % (i + 1))
        do_lpm_insert_and_verify_prefixes(logical_lpm, num_to_delete, prefixes_to_remove)
        print("Successfully finished round %d!" % (i + 1))
    print("Successfully inserted/removed %d in %d rounds!" % (num_to_delete, rounds))


def create_lpm_action(instruction):
    action = hw_tablescli.lpm_action_desc()
    key_value, key_width = instruction.get_key_and_width()
    key = lpm_test_utils.generate_lpm_key(key_value, key_width)
    payload = None
    if instruction.payload is not None:
        payload = payload_value
    if instruction.action == lpm_instruction.INSERT:
        action.m_action = hw_tablescli.lpm_action_e_INSERT
        action.m_payload = payload
        action.latency_sensitive = False
    elif instruction.action == lpm_instruction.REMOVE:
        action.m_action = hw_tablescli.lpm_action_e_REMOVE
    elif instruction.action == lpm_instruction.MODIFY:
        action.m_action = hw_tablescli.lpm_action_e_MODIFY
        action.m_payload = payload
    else:
        raise Exception('Error: Unknown type of lpm action!')
    action.m_key = key
    return action


def lpm_bulk_update(logical_lpm, instructions, num_of_bulk_entries):
    num_of_bulk_entries = min(num_of_bulk_entries, len(instructions))
    actions = hw_tablescli.lpm_action_desc_vec_t()
    num_of_updated_entries = 0
    try:
        for index, instruction in enumerate(instructions):
            action = create_lpm_action(instruction)
            actions.push_back(action)
            if ((index + 1) % num_of_bulk_entries) == 0:
                logical_lpm.update(actions)
                actions.clear()
                num_of_updated_entries += num_of_bulk_entries
        actions_size = actions.size()
        if actions_size != 0:
            logical_lpm.update(actions)
            num_of_updated_entries += actions_size
    except hw_tablescli.BaseException as e:
        print("Error: Failed during bulk update! Succeeded number of updated entries is %d out of %d" %
              (num_of_updated_entries, len(instructions)))
        raise e
    assert num_of_updated_entries == len(instructions)
    verify_correctness(logical_lpm, instructions)
    print("Successfully executed bulk update of %d entries with bulk size %d!" % (num_of_updated_entries, num_of_bulk_entries))


def lpm_bulk_update_and_insert_consecutive_prefixes(
        logical_lpm,
        num_of_bulk_entries,
        num_entries,
        base_prefix=BASE_IPV4_PREFIX,
        vrf=0,
        shuffle=False):
    prefixes = generate_consecutive_prefixes(num_entries, base_prefix, vrf)
    random_generator = random.Random(0 if args_parser.seed is None else args_parser.seed)
    if shuffle or args_parser.random:
        random_generator.shuffle(prefixes)
    instructions = []
    for prefix in prefixes:
        payload = random_generator.randint(0, (1 << PAYLOAD_WIDTH) - 1)
        instruction = lpm_instruction(lpm_instruction.INSERT, prefix.ip_network, prefix.vrf, payload)
        instructions.append(instruction)
    lpm_bulk_update(logical_lpm, instructions, num_of_bulk_entries)
