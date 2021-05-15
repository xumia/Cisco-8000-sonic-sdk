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
import ipaddress

IPV4_LENGTH = 32

IPV6_LEGNTH = 128

VRF_LENGTH = 11

IP_TYPE_LENGTH = 1


class lpm_instruction:
    # Actions Constants:
    INSERT = 1
    REMOVE = 2
    MODIFY = 3
    REBALANCE = 4

    def __init__(self, action, ip_address, vrf=0, payload=None, latency_sensitive=False):
        self.action = action
        self.ip_address = ip_address
        self.vrf = vrf
        self.payload = payload
        self.latency_sensitive = latency_sensitive

    def get_key_and_width(self):
        address_type = 0 if isinstance(self.ip_address, ipaddress.IPv4Network) else 1
        full_address_length = IPV4_LENGTH if address_type == 0 else IPV6_LEGNTH
        key_value = address_type << self.ip_address.prefixlen + VRF_LENGTH
        key_value += self.vrf << self.ip_address.prefixlen
        key_value += int(self.ip_address.network_address) >> (
            full_address_length - self.ip_address.prefixlen)
        key_width = IP_TYPE_LENGTH + VRF_LENGTH + self.ip_address.prefixlen
        return key_value, key_width

    def __hash__(self):
        return hash((self.action, self.ip_address, self.vrf, self.payload, self.latency_sensitive))

    def __eq__(self, other):
        return self.action == other.action and self.ip_address == other.ip_address and self.vrf == other.vrf and self.payload == other.payload and self.latency_sensitive == other.latency_sensitive

    def __str__(self):
        return 'VRF:' + str(self.vrf) + ', IP: ' + str(self.ip_address) + ' , Action: ' + str(self.action)


def match_old_format(opened_file, max_entries=-1):
    old_format_regex = r'lpm_(?P<action>[a-z:\.]+) ((?P<address>[0-9a-f]+) (?P<width>[0-9]+)(?P<payload> [0-9a-f]+)?)?'
    instructions = []
    for line in opened_file:
        if len(instructions) >= max_entries >= 0:
            break

        match = re.match(old_format_regex, line.decode('utf-8'))
        if match is None:
            continue

        action = match['action']
        if action == 'insert':
            lpm_action = lpm_instruction.INSERT
        elif action == 'modify':
            lpm_action = lpm_instruction.MODIFY
        elif action == 'remove':
            lpm_action = lpm_instruction.REMOVE
        elif action == 'rebalance':
            lpm_action = lpm_instruction.REBALANCE
        else:
            continue

        ip_address = None
        vrf = 0
        payload = None

        if lpm_action in [lpm_instruction.INSERT, lpm_instruction.REMOVE, lpm_instruction.MODIFY]:
            key = int(match['address'], base=16)
            width = int(match['width'])
            payload = None
            is_ipv6 = key >> width - 1
            full_prefix_len = IPV6_LEGNTH if is_ipv6 else IPV4_LENGTH
            prefix_width = width - VRF_LENGTH - IP_TYPE_LENGTH if width > VRF_LENGTH + IP_TYPE_LENGTH else 0
            prefix = (key & (2 ** prefix_width - 1)) << (full_prefix_len - prefix_width)
            vrf = ((2 ** (width - 1) - 1) & key) >> prefix_width
            ip_address = ipaddress.IPv6Network((prefix, prefix_width)) if is_ipv6 else ipaddress.IPv4Network((prefix, prefix_width))
            assert ip_address.prefixlen == prefix_width

        if lpm_action in [lpm_instruction.INSERT, lpm_instruction.MODIFY]:
            payload = int(match['payload'], base=16)

        latency_sensitive = False
        if re.search("True", line.decode('utf-8')):
            latency_sensitive = True

        instruction = lpm_instruction(lpm_action, ip_address, vrf, payload, latency_sensitive)
        instructions.append(instruction)

    return instructions


def match_cef(opened_file, max_entries=-1):
    cef_match_regex = r'(?P<address>[0-9a-f:\.]+)/(?P<width>([0-9]+))'
    vrf_match_str = r'^VRF'
    instructions = []
    vrf = 0
    for line in opened_file:
        is_recursive = False
        latency_sensitive = False
        if len(instructions) >= max_entries >= 0:
            break

        vrf_match = re.match(vrf_match_str, line.decode('utf-8'))

        if vrf_match is not None:
            vrf += 1
            continue

        match = re.match(cef_match_regex, line.decode('utf-8'))
        if match is None:
            continue

        if re.search("<recursive>", line.decode('utf-8')):
            is_recursive = True

        full_ip_string = '%s/%s' % (match['address'], match['width'])
        ip_string_without_width = '%s' % (match['address'])
        if ('0.0.0.0' != ip_string_without_width and '255.255.255.255' !=
                ip_string_without_width and match['width'] == '32' and not is_recursive and (':' not in match['address']) and vrf != 0):
            latency_sensitive = True

        ip_address = ipaddress.ip_network(full_ip_string)
        instruction = lpm_instruction(lpm_instruction.INSERT, ip_address, vrf, payload=None, latency_sensitive=latency_sensitive)
        instructions.append(instruction)

    return instructions


def match_codes(opened_file, max_entries=-1):
    codes_match_regex = r'(?:(?:[BCLOSi][\* ][ILE> ][A12 ] )|(?:\*[ >][ i]))(?P<address>[0-9a-f:\.]+)/(?P<width>([0-9]+))\s(?P<sensitive>(([a-zA-Z0-9_\[\]\/]+)\s(\w+)\s(\w+)))?'
    instructions = []
    for line in opened_file:
        latency_sensitive = False
        if len(instructions) >= max_entries >= 0:
            break

        match = re.match(codes_match_regex, line.decode('utf-8'))
        if match is None:
            continue

        ip_address = ipaddress.ip_network('%s/%s' % (match['address'], match['width']))
        if (match['sensitive'] == 'is directly connected' and match['address'] !=
                '0.0.0.0' and match['address'] != '255.255.255.255' and (':' not in match['address'])):
            latency_sensitive = True

        instruction = lpm_instruction(lpm_instruction.INSERT, ip_address, vrf=0, payload=None, latency_sensitive=latency_sensitive)
        instructions.append(instruction)
    return instructions


def match_xr_over_jupyter_routing_table(opened_file, max_entries=-1):
    ipv6_regex_template = r'(?P<address>[0-9a-f:]+)/(?P<width>([0-9]+))'
    ipv4_regex_template = r'(?P<address>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/(?P<width>[0-9]+)'
    instructions = set()
    for line in opened_file:
        if len(instructions) >= max_entries >= 0:
            break
        # line=line.decode('utf-8')
        first_column_word = line.split(" ")[0]
        match = re.match(ipv6_regex_template, first_column_word)
        if match is None:
            match = re.match(ipv4_regex_template, first_column_word)
        if match is None:
            continue

        ip_address = ipaddress.ip_network('%s/%s' % (match['address'], match['width']))
        instruction = lpm_instruction(lpm_instruction.INSERT, ip_address)
        instructions.add(instruction)

    return instructions


def match_ip_table(opened_file, max_entries=-1):
    ipv6_regex_template = r'(?P<address>[0-9a-f:\.]+)/(?P<width>([0-9]+))'

    ipv4_regex_template = r'(?P<address>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/(?P<width>[0-9]+)'
    instructions = []
    for line in opened_file:
        if len(instructions) >= max_entries >= 0:
            break

        match = re.match(ipv6_regex_template, line.decode('utf-8'))
        if match is None:
            match = re.match(ipv4_regex_template, line.decode('utf-8'))
        if match is None:
            continue

        ip_address = ipaddress.ip_network('%s/%s' % (match['address'], match['width']))
        instruction = lpm_instruction(lpm_instruction.INSERT, ip_address)
        instructions.append(instruction)
    return instructions


def match_lpm_log(opened_file, max_entries=-1):
    def action_key_width_to_lpm_instruction(action, key, width):
        actions = {'INSERT': lpm_instruction.INSERT, 'MODIFY': lpm_instruction.MODIFY}
        vrf_size = 11
        ipv4_flag = 0
        max_v4_prefix_length = 44
        max_v6_prefix_length = 140
        prefix_start_index = vrf_size + 1

        binary_full_key = bin(int('1' + key, 16))[-width:]

        vrf = int(binary_full_key[1:12], 2)

        if int(binary_full_key[0]) is ipv4_flag:
            missing_bits = max_v4_prefix_length - width
            ip_convert_function = ipaddress.IPv4Address
        else:
            missing_bits = max_v6_prefix_length - width
            ip_convert_function = ipaddress.IPv6Address

        full_ip_decimal = int(int(binary_full_key[prefix_start_index:], 2) * (2 ** missing_bits)) if binary_full_key[
            prefix_start_index:] is not '' else 0
        ip_address = ip_convert_function(full_ip_decimal)
        prefix_length = width - vrf_size - 1
        ip_network = ipaddress.ip_network('%s/%s' % (ip_address, prefix_length))
        instruction = lpm_instruction(actions[action], ip_network, vrf)
        return instruction

    log_action_regex = r'LPM ACTION:\s(?P<action>[A-Z]+)\s'
    key_encode_regex = r'encode_lpm_key\(k=0x(?P<key>[0-9a-f]+) w=(?P<width>[0-9]+)\)'

    instructions = []
    last_line = ''
    for line in opened_file:
        if len(instructions) >= max_entries >= 0:
            break

        action_match = re.search(log_action_regex, line.decode('utf-8'))

        if action_match is not None:
            key_match = re.search(key_encode_regex, line.decode('utf-8'))
            if key_match is not None:
                instruction = action_key_width_to_lpm_instruction(action_match['action'], key_match['key'],
                                                                  int(key_match['width']))
                instructions.append(instruction)
        last_line = line
    return instructions


def match_bgp_table(opened_file, max_entries=-1):
    ipv6_regex_template = r'.. (?P<address>[0-9a-f:\.]+)/(?P<width>([0-9]+))'

    ipv4_regex_template = r'.. (?P<address>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/(?P<width>[0-9]+)'
    instructions = []
    for line in opened_file:
        if len(instructions) >= max_entries >= 0:
            break

        match = re.match(ipv6_regex_template, line.decode('utf-8'))
        if match is None:
            match = re.match(ipv4_regex_template, line.decode('utf-8'))
        if match is None:
            continue

        ip_address = ipaddress.ip_network('%s/%s' % (match['address'], match['width']))
        instruction = lpm_instruction(lpm_instruction.INSERT, ip_address)
        instructions.append(instruction)
    return instructions
