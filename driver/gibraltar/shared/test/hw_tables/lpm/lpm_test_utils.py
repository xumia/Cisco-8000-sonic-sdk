#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import hw_tablescli
import gzip
import os
import re
import ipaddress
import parser_formats
import random
import math
import time
import decor


from datetime import datetime
from parser_formats import lpm_instruction
from genereate_lookups import generate_lookups_for_instructions
from collections import OrderedDict
from argument_parser import args_parser
import terminaltables
from bit_utils import get_bits
import decor

VRF_LENGTH = 11

# base ipv4 address used for generating prefixes
BASE_IPV4_PREFIX = ipaddress.IPv4Network('10.0.0.0/24')

# base ipv6 address used for generating prefixes
BASE_IPV6_PREFIX = ipaddress.IPv6Network('4000:0::/64')

MAX_ACTION_COUNT = -1
REQUIRED_ONE_BY_ONE_RATE = 3100
LOW_THRESHOLD = 0  # TODO later
MAX_VRF = 2**VRF_LENGTH - 1
PAYLOAD_WIDTH = 20 if decor.is_pacific() else 28

LPM_PARSE_FUNCTIONS = {
    'CEF': parser_formats.match_cef,
    'CODES': parser_formats.match_codes,
    'IP_TABLE': parser_formats.match_ip_table,
    'LPM_LOG': parser_formats.match_lpm_log,
    'BGP_TABLE': parser_formats.match_bgp_table,
    'OLD_FORMAT': parser_formats.match_old_format,
    "XR_OVER_JUPYTER": parser_formats.match_xr_over_jupyter_routing_table}


def generate_lpm_key(val, width):
    return hw_tablescli.lpm_key(hex(val)[2:], width)


def create_action_desc(action, key, payload):
    action_desc = hw_tablescli.lpm_action_desc()
    action_desc.m_action = action
    action_desc.m_key = key
    action_desc.m_payload = payload

    return action_desc


def parse_lpm_input(file_path, file_format, max_entries=-1, filter_full_addresses=True):

    parse_function = LPM_PARSE_FUNCTIONS[file_format]

    file_name, extension = os.path.splitext(file_path)

    if extension == ".gz":
        file = gzip.open(filename=file_path, mode="r")

    else:
        file = open(file_path, mode="r")

    instructions = parse_function(opened_file=file, max_entries=max_entries)
    file.close()
    if any(not isinstance(instruction, lpm_instruction) for instruction in instructions):
        raise Exception("Unsupported type of instruction.")

    if filter_full_addresses:
        instructions = filter_full_address_length_prefixes(instructions)

    return instructions


def add_unique_payloads_to_lpm_instructions(instructions):
    """
    Gets a list of instructions and adds a unique payload to each address that is inserted
    :param instructions:
    :return:
    """
    payload = 1
    for instruction in instructions:
        if instruction.action in (lpm_instruction.INSERT, lpm_instruction.MODIFY):
            instruction.payload = payload
            payload += 1
    return instructions


def filter_full_address_length_prefixes(instructions):
    """
    Gets a list of instructions and filter /32 IPV4 and /128 IPV6 addrresses
    :param instructions:
    :return: Filtered list
    """
    ret_instructions = []
    for instruction in instructions:
        if (isinstance(instruction.ip_address, ipaddress.IPv6Network) and (instruction.ip_address.prefixlen == 128)):
            continue

        ret_instructions.append(instruction)

    return ret_instructions


def print_utilization(logical_lpm):
    headers = ['Core ID',
               'L2 Entries',
               'L2 IPv4 Entries',
               'L2 IPv6 Entries',
               'TCAM Single Entries',
               'TCAM Double Entries',
               'TCAM Quad Entries',
               'TCAM Utilization',
               'Weighted TCAM load']

    data_rows = []

    tree = logical_lpm.get_tree()
    l2_stats = tree.get_occupancy(hw_tablescli.lpm_level_e_L2)
    for core_id in range(logical_lpm.get_num_cores()):
        core = logical_lpm.get_core(core_id)
        tcam = core.get_tcam()

        tcam_stats = tcam.get_occupancy()
        l2_stats_core = l2_stats[core_id]

        l2_entries = l2_stats_core.sram_single_entries + l2_stats_core.sram_double_entries + l2_stats_core.hbm_entries
        l2_ipv4_entries = l2_stats_core.sram_ipv4_entries + l2_stats_core.hbm_ipv4_entries
        l2_ipv6_entries = l2_stats_core.sram_ipv6_entries + l2_stats_core.hbm_ipv6_entries
        tcam_rows = tcam_stats.occupied_cells

        tcam_size = tcam.get_num_cells()

        weighted_tcam_load = tcam_stats.num_single_entries + tcam_stats.num_double_entries * 4 + tcam_stats.num_quad_entries * 8

        data_row = [core_id,
                    l2_entries,
                    l2_ipv4_entries,
                    l2_ipv6_entries,
                    tcam_stats.num_single_entries,
                    tcam_stats.num_double_entries,
                    tcam_stats.num_quad_entries,
                    100 * tcam_rows // tcam_size,
                    weighted_tcam_load]

        data_rows.append(data_row)

    table = terminaltables.AsciiTable([headers] + data_rows)

    print(table.table)


def is_valgrind():
    return os.environ.get("IS_VALGRIND") is not None


def is_run_slow():
    return os.environ.get("RUN_SLOW_TESTS") == "True" or os.environ.get("RUN_SLOW_TESTS") == "1"


def encode_lpm_prefix(prefix, width):
    is_ipv6 = (prefix >> (width - 1)) == 1
    if not decor.is_pacific():
        # The key is encoded only in Pacific due to HW bug.
        return (prefix, width)
    if is_ipv6:
        return (prefix, width)

    broken_bit = 20
    decoded_key_len = 44
    encoded_key_len = 45
    bits_above_broken_bit = encoded_key_len - (broken_bit + 1)
    if width <= bits_above_broken_bit:
        return (prefix, width)

    prefix_padded = prefix << (decoded_key_len - width)
    prefix_msb = get_bits(prefix_padded, decoded_key_len - 1, broken_bit)
    prefix_lsb = get_bits(prefix_padded, broken_bit - 1, 0)
    encoded_prefix_padded = (prefix_msb << (broken_bit + 1)) | prefix_lsb
    encoded_prefix = encoded_prefix_padded >> (decoded_key_len - width)

    return (encoded_prefix, width + 1)


class lpm_prefix:
    def __init__(self, vrf, ip):
        self.vrf = vrf
        self.ip_network = ip

    def get_key_value(self):
        prefix_len = self.ip_network.prefixlen
        max_length = self.ip_network.max_prefixlen
        is_ipv6 = self.ip_network.version == 6
        key_msbs = is_ipv6 << (VRF_LENGTH + prefix_len) | self.vrf << prefix_len
        key_lsbs = int(self.ip_network.network_address) >> (max_length - prefix_len)
        key_value = key_msbs | key_lsbs
        return key_value

    def __hash__(self):
        return hash((self.get_key_value(), self.ip_network.prefixlen))

    def __eq__(self, other):
        return isinstance(other, type(self)) and (self.ip_network == other.ip_network and self.vrf == other.vrf)


def generate_consecutive_prefixes(num_entries, step=1, vrf=0, base_prefix=BASE_IPV4_PREFIX, fail=True):
    assert vrf >= 0 and vrf < (2 ** VRF_LENGTH)
    assert num_entries >= 0
    ip_base = base_prefix.network_address
    prefix_len = base_prefix.prefixlen
    log_stride = base_prefix.max_prefixlen - prefix_len
    prefix_list = []
    try:
        for i in range(num_entries):
            prefix = ip_base + ((i * step) << log_stride)
            ip = ipaddress.ip_network((prefix, prefix_len))
            prefix = lpm_prefix(vrf, ip)
            prefix_list.append(prefix)
    except ipaddress.AddressValueError as ae:
        if fail:
            print("Out of range! Prefix length too small to generate %d number of entries" % num_entries)
            raise ae
        else:
            return prefix_list
    assert num_entries == len(prefix_list)
    return prefix_list


def generate_many_groups_of_consecutive_prefixes(
        num_entries,
        step=1,
        num_groups=1,
        group_prefix_length=1,
        vrf=0,
        base_prefix=BASE_IPV4_PREFIX,
        fail=True):
    assert num_groups > 0 and num_entries > 0 and group_prefix_length > 0
    if math.ceil(math.log2(num_groups)) > group_prefix_length:
        raise Exception('Error: Not enough width to generate groups!')
    prefix_len = base_prefix.prefixlen
    max_prefixlen = base_prefix.max_prefixlen
    assert group_prefix_length + math.ceil(math.log2(num_entries)) <= prefix_len
    base_ip = base_prefix.network_address
    log_stride = max_prefixlen - group_prefix_length
    lpm_groups_parameters = []
    for i in range(num_groups):
        base = base_ip + (i << log_stride)
        lpm_groups_parameters.append(
            lpm_groups_desc(
                num_entries=num_entries,
                step=step,
                vrf=vrf,
                base_prefix=ipaddress.ip_network(
                    (base,
                     prefix_len))))
    prefixes = generate_groups_of_consecutive(lpm_groups_parameters, fail)
    return prefixes

# Generates different groups of consecutive prefixes


def generate_groups_of_consecutive(lpm_groups_parameters, fail=True):
    prefixes = []
    for index in range(len(lpm_groups_parameters)):
        prefixes += generate_consecutive_prefixes(
            lpm_groups_parameters[index].num_entries,
            lpm_groups_parameters[index].step,
            lpm_groups_parameters[index].vrf,
            lpm_groups_parameters[index].base_prefix,
            fail)
    unique_prefixes = list(OrderedDict.fromkeys(prefixes))
    if fail and len(unique_prefixes) != len(prefixes):
        raise Exception('Error: Base prefixes overlap!')
    elif not fail:
        return list(unique_prefixes)
    return prefixes


def generate_random_prefixes(
        protocols,
        num_entries,
        seed=args_parser.seed):
    print("seed = %s" % str(seed))
    random_generator = random.Random(seed)
    prefix_list = []
    try:
        for i in range(num_entries):
            vrf = random_generator.randint(0, MAX_VRF)
            protocol = random_generator.choice(protocols)
            max_prefixlen = 128 if protocol == 'IPV6' else 32
            prefix_len = random_generator.randint(1, max_prefixlen)
            base_value = random_generator.getrandbits(prefix_len)
            base_ip_value = base_value << (max_prefixlen - prefix_len)
            ip = ipaddress.ip_network(base_ip_value, prefix_len)
            prefix = lpm_prefix(vrf, ip)
            prefix_list.append(prefix)
    except ipaddress.AddressValueError as ae:
        print("Out of range! Prefix length too small to generate %d number of entries" % num_entries)
        raise ae
    assert num_entries == len(prefix_list)
    return prefix_list


def generate_random_groups_of_consecutive_prefixes(
        protocols,
        max_num_groups=100,
        max_num_entries_per_group=10000,
        seed=args_parser.seed):
    print("seed = %s" % str(seed))
    random_generator = random.Random(seed)
    num_groups = random_generator.randint(1, max_num_groups)
    lpm_groups_parameters = []
    for groups in range(num_groups):
        protocol = random_generator.choice(protocols)
        max_prefixlen = 128 if protocol == 'IPV6' else 32
        prefix_len = random_generator.randint(1, max_prefixlen)
        max_entries = 2**prefix_len
        base_value = random_generator.getrandbits(prefix_len)
        base_ip_value = base_value << (max_prefixlen - prefix_len)
        num_entries_per_group = random_generator.randint(1, min(max_entries - base_value, max_num_entries_per_group))
        vrf = random_generator.randint(0, MAX_VRF)
        step = random_generator.randint(1, 10)
        lpm_groups_parameters.append(
            lpm_groups_desc(
                num_entries=num_entries_per_group,
                step=step,
                vrf=vrf,
                base_prefix=ipaddress.ip_network(
                    (base_ip_value,
                     prefix_len))))
    return generate_groups_of_consecutive(lpm_groups_parameters, fail=False)


def generate_instructions_from_file(file_path, file_format, max_entries=-1, bulk_size=1):

    parse_function = LPM_PARSE_FUNCTIONS[file_format]

    file_name, extension = os.path.splitext(file_path)

    if extension == ".gz":
        file = gzip.open(filename=file_path, mode="r")

    else:
        file = open(file_path, mode="r")

    instructions = parse_function(opened_file=file, max_entries=max_entries)
    file.close()
    if any(not isinstance(instruction, lpm_instruction) for instruction in instructions):
        raise Exception("Unsupported type of instruction.")

    filtered_instructions = filter_full_address_length_prefixes(instructions)

    payload = 1
    for instruction in filtered_instructions:
        if instruction.action in (lpm_instruction.INSERT, lpm_instruction.MODIFY):
            instruction.payload = payload
            payload += 1
    return filtered_instructions


def randomize_list(instructions, seed=args_parser.seed):
    print("seed = %s" % str(seed))
    random_generator = random.Random(args_parser.seed)
    random_generator.shuffle(instructions)


def populate_with_actions(logical_lpm,
                          prefixes,
                          action):
    random_generator = random.Random(args_parser.seed)
    instructions = []
    for index in range(len(prefixes)):
        lpm_prefix = None
        payload = None
        lpm_prefix = prefixes[index]
        payload = random_generator.randint(0, (1 << PAYLOAD_WIDTH) - 1)
        instruction = lpm_instruction(action, lpm_prefix.ip_network, lpm_prefix.vrf, payload)
        instructions.append(instruction)
    return instructions


def populate_with_actions_safe(logical_lpm,
                               prefixes,
                               actions=[lpm_instruction.INSERT, lpm_instruction.REMOVE, lpm_instruction.MODIFY]):
    random_generator = random.Random(args_parser.seed)
    instructions = []
    inserted_prefixes = []
    number_of_inserted = 0
    while number_of_inserted < len(prefixes):
        if len(inserted_prefixes) == 0:
            action = lpm_instruction.INSERT
        else:
            action = random_generator.choice(actions)
        if action == lpm_instruction.INSERT:
            lpm_prefix = prefixes[number_of_inserted]
            inserted_prefixes.append(lpm_prefix)
            payload = random_generator.randint(0, (1 << PAYLOAD_WIDTH) - 1)
            number_of_inserted += 1
        elif action == lpm_instruction.REMOVE or action == lpm_instruction.MODIFY:
            random_index = random_generator.randint(0, len(inserted_prefixes) - 1)
            lpm_prefix = inserted_prefixes[random_index]
            if action == lpm_instruction.MODIFY:
                payload = random_generator.randint(0, (1 << PAYLOAD_WIDTH) - 1)
            if action == lpm_instruction.REMOVE:
                payload = random_generator.randint(0, (1 << PAYLOAD_WIDTH) - 1)
                inserted_prefixes.remove(lpm_prefix)
        instruction = lpm_instruction(action, lpm_prefix.ip_network, lpm_prefix.vrf, payload)
        instructions.append(instruction)
    return instructions

# Generates set of addresses and performs lookup


def verify_correctness(logical_lpm, instructions):
    incorrect_lookups = 0
    lookups = generate_lookups_for_instructions(instructions)
    for prefix_value, prefix_length, payload in lookups:
        lookup_key = generate_lpm_key(prefix_value, prefix_length)
        result = logical_lpm.lookup(lookup_key)
        if result[1] != payload:
            incorrect_lookups += 1

    if incorrect_lookups > 0:
        print("Incorrect lookups occured: %d out of %d " % (incorrect_lookups, len(lookups)))
    assert incorrect_lookups == 0


def perform_action(logical_lpm, instruction):
    key_value, key_width = instruction.get_key_and_width()
    key = generate_lpm_key(key_value, key_width)
    if instruction.action == lpm_instruction.INSERT:
        payload = instruction.payload
        status = logical_lpm.insert(key, payload)
    elif instruction.action == lpm_instruction.REMOVE:
        status = logical_lpm.remove(key)
    elif instruction.action == lpm_instruction.MODIFY:
        payload = instruction.payload
        status = logical_lpm.modify(key, payload)
    else:
        print("Unrecognized lpm action!")
        raise ValueError("Invalid action")

    assert status is None


def create_lpm_action(instruction):
    action = hw_tablescli.lpm_action_desc()
    action.m_latency_sensitive = instruction.latency_sensitive
    key_value, key_width = instruction.get_key_and_width()
    key = generate_lpm_key(key_value, key_width)
    payload = None
    if instruction.payload is not None:
        payload = instruction.payload
    if instruction.action == lpm_instruction.INSERT:
        action.m_action = hw_tablescli.lpm_action_e_INSERT
        action.m_payload = payload
    elif instruction.action == lpm_instruction.REMOVE:
        action.m_action = hw_tablescli.lpm_action_e_REMOVE
    elif instruction.action == lpm_instruction.MODIFY:
        action.m_action = hw_tablescli.lpm_action_e_MODIFY
        action.m_payload = payload
    else:
        raise Exception('Error: Unknown type of lpm action!')
    action.m_key = key
    return action


def execute_one_by_one(logical_lpm, instructions, fail=True, run_verification=True):
    execute_bulk(logical_lpm, instructions, bulk_size=1, run_verification=run_verification)


def execute_bulk(logical_lpm, instructions, bulk_size, run_verification=True):
    actions = hw_tablescli.lpm_action_desc_vec_t()
    num_of_updated_entries = 0
    try:
        for index, instruction in enumerate(instructions):
            action = create_lpm_action(instruction)
            actions.push_back(action)
            if ((index + 1) % bulk_size) == 0:
                logical_lpm.update(actions)
                actions.clear()
                num_of_updated_entries += bulk_size
        actions_size = actions.size()
        if actions_size != 0:
            logical_lpm.update(actions)
            num_of_updated_entries += actions_size
    except hw_tablescli.BaseException as e:
        print("Error: Failed during bulk update! Succeeded number of updated entries is %d out of %d" %
              (num_of_updated_entries, len(instructions)))
        raise e
    assert num_of_updated_entries == len(instructions)
    if run_verification:
        verify_correctness(logical_lpm, instructions)
    num_of_bulk_entries = min(bulk_size, len(instructions))
    print(" * Successfully executed bulk update of %d entries with bulk size %d!" % (num_of_updated_entries, num_of_bulk_entries))


class lpm_groups_desc:
    num_entries = 0
    step = 0
    vrf = 0
    base_prefix = ipaddress.IPv4Network('0.0.0.0')

    def __init__(self, num_entries, step, vrf, base_prefix):
        self.num_entries = num_entries
        self.step = step
        self.vrf = vrf
        self.base_prefix = base_prefix
