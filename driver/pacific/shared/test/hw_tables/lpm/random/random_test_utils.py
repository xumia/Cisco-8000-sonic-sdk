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

import lpm_test_utils
import random
import ipaddress
import hw_tablescli
from parser_formats import lpm_instruction
from scale_tests import scale_test_utils
from scale_tests.argument_parser import args_parser
from lpm_test_utils import PAYLOAD_WIDTH


def generate_random_lpm_groups_of_prefixes(logical_lpm, max_num_groups, max_num_entries_per_group, protocols):
    print("seed = %s" % str(args_parser.seed))
    random_generator = random.Random(args_parser.seed)
    distribution = []
    base_prefixes = []
    num_groups = random_generator.randint(1, max_num_groups)
    while num_groups > 0:
        protocol = random_generator.choice(protocols)
        max_prefixlen = 128 if protocol == 'IPV6' else 32
        prefix_len = random_generator.randint(1, max_prefixlen)
        max_entries = 2**prefix_len
        base_value = random_generator.getrandbits(prefix_len)
        base_ip_value = base_value << (max_prefixlen - prefix_len)
        num_entries_per_group = random_generator.randint(1, min(max_entries - base_value, max_num_entries_per_group))
        if base_ip_value not in base_prefixes:
            base_prefixes.append(ipaddress.ip_network((base_ip_value, prefix_len)))
            distribution.append(num_entries_per_group)
            num_groups -= 1
        if num_groups <= 0:
            break
    vrf = random_generator.randint(0, 2**lpm_test_utils.VRF_LENGTH - 1)
    step = random_generator.randint(1, 10)
    return scale_test_utils.lpm_generate_consecutive_groups(base_prefixes, distribution, vrf, step, fail_on_overlap=False)


def lpm_generate_and_insert_random_groups(
        logical_lpm,
        protocols=['IPV4'],
        max_num_groups=100,
        max_num_entries_per_group=10000,
        shuffle=False):
    prefixes = generate_random_lpm_groups_of_prefixes(logical_lpm, max_num_groups, max_num_entries_per_group, protocols)
    if shuffle:
        random_generator = random.Random(args_parser.seed)
        random_generator.shuffle(prefixes)
    scale_test_utils.do_lpm_insert_and_verify_prefixes(logical_lpm, len(prefixes), prefixes, fail_on_oor=False)


# Generates random groups of entries and performs random actions
def lpm_random_generated_actions(
        logical_lpm,
        protocols,
        actions=[lpm_instruction.INSERT, lpm_instruction.REMOVE, lpm_instruction.MODIFY],
        max_num_groups=100,
        max_num_entries_per_group=10000,
        shuffle=False):
    prefixes = generate_random_lpm_groups_of_prefixes(logical_lpm, max_num_groups, max_num_entries_per_group, protocols)
    random_generator = random.Random(args_parser.seed)
    if shuffle:
        random_generator.shuffle(prefixes)
    inserted_prefixes = []
    number_of_inserted = 0
    num_inserted = 0
    num_removed = 0
    num_modified = 0
    while number_of_inserted < len(prefixes):
        lpm_prefix = None
        payload = None
        if len(inserted_prefixes) == 0:
            action = lpm_instruction.INSERT
        else:
            action = random_generator.choice(actions)
        if action == lpm_instruction.INSERT:
            lpm_prefix = prefixes[number_of_inserted]
            payload = random_generator.randint(0, (1 << PAYLOAD_WIDTH) - 1)
            number_of_inserted += 1
        elif action == lpm_instruction.REMOVE or action == lpm_instruction.MODIFY:
            random_index = random_generator.randint(0, len(inserted_prefixes) - 1)
            lpm_prefix = inserted_prefixes[random_index]
            if action == lpm_instruction.MODIFY:
                payload = random_generator.randint(0, (1 << PAYLOAD_WIDTH) - 1)
            if action == lpm_instruction.REMOVE:
                inserted_prefixes.remove(lpm_prefix)
        instruction = lpm_instruction(action, lpm_prefix.ip_network, lpm_prefix.vrf, payload)
        try:
            scale_test_utils.perform_action(logical_lpm, instruction)
            if action == lpm_instruction.INSERT:
                inserted_prefixes.append(lpm_prefix)
                num_inserted += 1
            elif action == lpm_instruction.REMOVE:
                num_removed += 1
            else:
                num_modified += 1
        except hw_tablescli.BaseException as e:
            if action == lpm_instruction.MODIFY or action == lpm_instruction.REMOVE:
                raise e
    print("number of inserted entries=%d, number of modified entries=%d, number of removed entries=%d" %
          (num_inserted, num_modified, num_removed))
