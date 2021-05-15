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

import re
import sys
import random
import argparse
import copy
import os
import pickle
import ipaddress
import generate_lookups
from bit_utils import get_bits

disable_bucket_override_check = True
skip_unreachable = True
randomize_prefix_padding = False

verbosity = 0

vrf_len = 11

in_progress_prefix = None
in_progress_prefix_len = None
in_progress_payload = None
modify_prefix = None
modify_prefix_len = None
modify_payload = None
to_be_removed_prefix = None
to_be_removed_prefix_len = None
to_be_removed_payload = None
prefixes = {}

n_matched_lines = 0


def ip_to_str(ip, is_ipv6):
    if is_ipv6:
        ip_as_hex_str = '%032x' % ip
        ip_groups_str = [ip_as_hex_str[i:i + 4] for i in range(0, 32, 4)]
        ip_str = ':'.join(ip_groups_str)
    else:
        ip_as_hex_str = '%08x' % ip
        ip_groups_str = ['%d' % int(ip_as_hex_str[i:i + 2], 16) for i in range(0, 8, 2)]
        ip_str = '.'.join(ip_groups_str)

    return ip_str


def log_match(lno, l, match=True):
    global n_matched_lines

    if match:
        n_matched_lines += 1

    if match and (verbosity > 1):
        print('Matched line %d: %s' % (lno, l.strip('\n')))
    if not match and (verbosity > 2):
        print('No match for line %d: %s' % (lno, l.strip('\n')))


def get_covering_prefixes(prefix, prefix_len, include_self=True, is_encoded=True):
    res = []
    if not is_encoded:
        prefix, prefix_len = encode_prefix(prefix, prefix_len)

    len_range = range(prefix_len + 1) if include_self else range(prefix_len)
    for covering_len in reversed(len_range):
        covering_prefix = prefix >> (prefix_len - covering_len)
        res.append((covering_prefix, covering_len))
    return res


def get_covering_prefixes_in_database(prefix, prefix_len, all_prefixes, include_self=True, is_encoded=True):
    res = []
    candidates = get_covering_prefixes(prefix, prefix_len, include_self, is_encoded)

    for (covering_prefix, covering_len) in candidate:
        if (covering_prefix, covering_len) in all_prefixes:
            res.append(all_prefixes[(covering_prefix, covering_len)])
    return res


def get_distributer_entries_with_covering_prefixes(
        prefix,
        prefix_len,
        distributer,
        group_to_core,
        include_self=True,
        is_encoded=True):
    covering_prefixes = get_covering_prefixes(prefix, prefix_len, include_self, is_encoded)

    covering_distributer_rows = [(r, x) for (r, x) in distributer.items() if (x['key'], x['width']) in covering_prefixes]

    return {r: {'key': x['key'], 'length': x['width'], 'group': x['payload'],
                'core': group_to_core[x['payload']]} for (r, x) in covering_distributer_rows}


def print_tree_entries(tree, core, row):
    for entry in tree[core][row]['entries']:
        print('key 0x%x  width %d  payload 0x%x' % (entry['key'], entry['width'], entry['payload']))
    if tree[core][row]['default'] is not None:
        print('default payload 0x%x' % tree[core][row]['default'])


def ip_str_to_key(vrf, ip_str, perform_encoding=True):
    addr = ipaddress.ip_address(ip_str)
    is_ipv6 = (addr.version == 6)
    ip = int(addr.packed.hex(), 16)
    ip_len = 128 if is_ipv6 else 32
    full_key = (is_ipv6 << (vrf_len + ip_len)) | (vrf << ip_len) | ip
    full_len = vrf_len + ip_len + 1

    if perform_encoding:
        (full_key, full_len) = encode_prefix(full_key, full_len)

    return (full_key, full_len)


def prefix_str_to_key(vrf, prefix_str, perform_encoding=True):
    network = ipaddress.ip_network(prefix_str)

    is_ipv6 = network.version == 6
    ip_len = 128 if is_ipv6 else 32

    full_ip = int(network.network_address.packed.hex(), 16)

    prefix_padded = (is_ipv6 << (vrf_len + ip_len)) | (vrf << ip_len) | full_ip
    shift_by = ip_len - network.prefixlen

    prefix = prefix_padded >> shift_by
    prefix_len = 1 + vrf_len + network.prefixlen

    if perform_encoding:
        prefix, prefix_len = encode_prefix(prefix, prefix_len)

    return prefix, prefix_len


def lookup_ip(v_vrf_ip, full_length, distributer, group_to_core, tcams, l1, l2, is_ip_encoded=True, verbosity=1):
    if not is_ip_encoded:
        (v_vrf_ip, full_length) = encode_prefix(v_vrf_ip, full_length)

    is_ipv6 = (v_vrf_ip >> (full_length - 1)) == 1

    payload = None
    distributer_hits = []
    for k, v in distributer.items():
        if full_length >= v['width'] and get_bits(v_vrf_ip, full_length - 1, full_length - v['width']) == v['key']:
            distributer_hits.append({'row': k, 'width': v['width'], 'payload': v['payload'], 'key': v['key']})
    distributer_hits = sorted(distributer_hits, key=lambda x: x['row'])
    if len(distributer_hits) == 0:
        print('ERROR: Miss in distributer')
        print_distributer(distributer)
        return None
    hit = distributer_hits[0]
    group = hit['payload']
    core = group_to_core[group]
    if verbosity > 1:
        print('Distributer: Hit on line %d (key 0x%x  width %d) -> group %d -> core %d' %
              (hit['row'], hit['key'], hit['width'], group, core))

    remaining_width = full_length
    remaining_prefix = v_vrf_ip

    tcam_hits = []
    for k, v in tcams[core].items():
        if ((v['is_ipv6'] == is_ipv6) and ((v['width'] == 0) or (remaining_width >= v['width'] and get_bits(
                remaining_prefix, remaining_width - 1, remaining_width - v['width']) == v['key']))):
            tcam_hits.append({'row': k, 'width': v['width'], 'payload': v['payload'], 'key': v['key'], 'is_ipv6': v['is_ipv6']})
    tcam_hits = sorted(tcam_hits, key=lambda x: x['row'])
    if len(tcam_hits) == 0:
        print('ERROR: Miss in TCAM (group %d  core %d)' % (group, core))
        return None
    tcam_hit = tcam_hits[0]
    l1_row = tcam_hit['payload']
    if verbosity > 1:
        print('TCAM: Hit on line %d (key 0x%x is_ipv6? %s  width %d) -> L1 row %d' %
              (tcam_hit['row'], tcam_hit['key'], tcam_hit['is_ipv6'], tcam_hit['width'], tcam_hit['payload']))

    truncated_tcam_width = tcam_hit['width']
    if truncated_tcam_width > 127:
        truncated_tcam_width = 127  # due to bug

    remaining_width = full_length - truncated_tcam_width
    remaining_prefix = get_bits(remaining_prefix, remaining_width - 1, 0)

    if l1_row not in l1[core]:
        print('ERROR: Miss in L1 (Invalid row) (group %d core %d tcam row %d  l1 row %d)' % (group, core, tcam_hit['row'], l1_row))
        return None

    l1_hits = []
    for entry in l1[core][l1_row]['entries']:
        if (entry['width'] == 0) or get_bits(remaining_prefix, remaining_width - 1,
                                             remaining_width - entry['width']) == entry['key']:
            l1_hits.append({'key': entry['key'], 'width': entry['width'], 'payload': entry['payload']})
    if len(l1_hits) == 0:
        payload = l1[core][l1_row]['default']
        if verbosity > 1:
            print('Miss in L1 Entries. Will use default')
            print('prefix: original 0x%x  length %d  remaining 0x%x  length %d' %
                  (v_vrf_ip, full_length, remaining_prefix, remaining_width))
            print('l1_row %d:' % l1_row)
            print_tree_entries(l1, core, l1_row)
            print('L1: Hit on line %d (Default) -> Final Payload 0x%x' % (l1_row, payload))

        if payload is not None:
            if verbosity > 1:
                print('Prefix 0x%x  Payload 0x%x' % (v_vrf_ip, payload))
                print('')

            ip_len = 128 if is_ipv6 else 32
            v_vrf_ip, _ = decode_prefix(v_vrf_ip, full_length)
            vrf = get_bits(v_vrf_ip, ip_len + vrf_len - 1, ip_len)
            ip = get_bits(v_vrf_ip, ip_len - 1, 0)

            if verbosity > 0:
                print('Lookup: VRF=%03d  IP=%s  G=%-3d  C=%-2d  T=%-5d  L1=%-4d  P=0x%05x' %
                      (vrf, ip_to_str(ip, is_ipv6), group, core, tcam_hit['row'], l1_row, payload))
                print('')

        if payload is None:
            print('ERROR: Payload is None')
        return payload

    l1_hits = sorted(l1_hits, key=lambda x: x['width'], reverse=True)
    l1_hit = l1_hits[0]
    if verbosity > 1:
        print('L1: Hit on line %d (key 0x%x  width %d) -> L2 row %d' % (l1_row, l1_hit['key'], l1_hit['width'], l1_hit['payload']))

    l2_row = l1_hit['payload']
    remaining_width = remaining_width - l1_hit['width']
    remaining_prefix = get_bits(remaining_prefix, remaining_width - 1, 0)

    if l2_row not in l2[core]:
        print('ERROR: Miss in L2 (Invalid row) (group %d core %d tcam row %d  l1 row %d  l2 row %d)' %
              (group, core, tcam_hit['row'], l1_row, l2_row))
        return None

    l2_hits = []
    for entry in l2[core][l2_row]['entries']:
        if (entry['width'] == 0) or get_bits(remaining_prefix, remaining_width - 1,
                                             remaining_width - entry['width']) == entry['key']:
            l2_hits.append({'key': entry['key'], 'width': entry['width'], 'payload': entry['payload']})
    if len(l2_hits) == 0:
        payload = l2[core][l2_row]['default']
        if verbosity > 1:
            print('Miss in L2 Entries. Will use default')
            print('prefix: original 0x%x  length %d  remaining 0x%x  length %d' %
                  (v_vrf_ip, full_length, remaining_prefix, remaining_width))
            print('l2_row %d:' % l2_row)
            print_tree_entries(l2, core, l2_row)
            print('L2: Hit on line %d (Default) -> Final Payload 0x%x' % (l2_row, payload))
    else:
        l2_hits = sorted(l2_hits, key=lambda x: x['width'], reverse=True)
        l2_hit = l2_hits[0]
        payload = l2_hit['payload']
        if verbosity > 1:
            print('L2: Hit on line %d (key 0x%x  width %d) -> Final Payload 0x%x' %
                  (l2_row, l2_hit['key'], l2_hit['width'], l2_hit['payload']))

    if verbosity > 1:
        print('Prefix 0x%x  Payload 0x%x' % (v_vrf_ip, payload))
        print('')

    ip_len = 128 if is_ipv6 else 32
    v_vrf_ip, _ = decode_prefix(v_vrf_ip, full_length)
    vrf = get_bits(v_vrf_ip, ip_len + vrf_len - 1, ip_len)
    ip = get_bits(v_vrf_ip, ip_len - 1, 0)

    if verbosity > 0:
        print('Lookup: VRF=%03d  IP=%s  G=%-3d  C=%-2d  T=%-5d  L1=%-4d  L2=%-6d  P=0x%05x' %
              (vrf, ip_to_str(ip, is_ipv6), group, core, tcam_hit['row'], l1_row, l2_row, payload))
        print('')

    return payload


def print_prefixes():
    global prefixes
    for p in prefixes.values():
        print('prefix 0x%x  len %d   payload 0x%x' % (p['prefix'], p['prefix_len'], p['payload']))


def generate_ip_from_prefix(prefix_tree, prefix, prefix_len, is_encoded=True, randomize_padding=False):
    if not is_encoded:
        prefix, prefix_len = encode_prefix(prefix, prefix_len)
    is_ipv6 = (prefix >> (prefix_len - 1) == 1)
    ip_len = 128 if is_ipv6 else 32
    full_length = vrf_len + ip_len + 1
    if not is_ipv6:
        full_length += 1  # due to HW bug

    full_ip = generate_lookups.address_for_prefix(prefix_tree, prefix, prefix_len, full_length, randomize_padding)
    if full_ip is None:
        return None

    full_ip = int(full_ip, 16)

    return {'v_vrf_ip': full_ip, 'full_length': full_length, 'is_ipv6': is_ipv6,
            'original_prefix': prefix, 'original_length': prefix_len}


def format_prefix(prefix, prefix_len, is_encoded=True):
    is_ipv6 = (prefix >> (prefix_len - 1)) == 1

    if is_encoded:
        prefix, prefix_len = decode_prefix(prefix, prefix_len)

    ip_len = 128 if is_ipv6 else 32
    full_len = vrf_len + ip_len + 1
    prefix_shifted = prefix << (full_len - prefix_len)

    ip = get_bits(prefix_shifted, ip_len - 1, 0)
    vrf = get_bits(prefix_shifted, ip_len + vrf_len - 1, ip_len)

    mask = ((1 << prefix_len) - 1) << (full_len - prefix_len)
    ip_prefix_len = prefix_len - vrf_len - 1
    if ip_prefix_len < 0:
        ip_prefix_len = 0

    vrf_str = 'VRF=%03d   ' % vrf
    if (prefix_len - 1 < vrf_len):
        vrf_str += '/%02d' % (prefix_len - 1)

    if is_ipv6:
        net_addr = ipaddress.IPv6Network(ip).supernet(new_prefix=ip_prefix_len)
    else:
        net_addr = ipaddress.IPv4Network(ip).supernet(new_prefix=ip_prefix_len)

    return '%s  %s' % (vrf_str, net_addr)


def generate_prefix_tree(
        prefixes,
        in_progress_prefix=None,
        in_progress_prefix_len=None,
        in_progress_payload=None,
        to_be_removed_prefix=None,
        to_be_removed_prefix_len=None,
        to_be_removed_payload=None):
    prefix_tree = generate_lookups.PrefixTree([(p['prefix'], p['prefix_len'], p['payload']) for p in prefixes.values()])
    if in_progress_prefix is not None:
        prefix_tree.insert(in_progress_prefix, in_progress_prefix_len, in_progress_payload)
    if to_be_removed_prefix is not None:
        prefix_tree.insert(to_be_removed_prefix, to_be_removed_prefix_len, to_be_removed_payload)

    return prefix_tree


def check_lpm_state(prefixes_to_check, lno, l, distributer, group_to_core, tcams, l1, l2, fail_on_error):
    ok = True
    if verbosity > 1:
        print('checking')

    if prefixes_to_check == 'All':
        current_prefixes_to_check = prefixes.values()
    elif prefixes_to_check == 'None':
        current_prefixes_to_check = []
    else:
        current_prefixes_to_check = [
            p for p in prefixes.values() if {
                'prefix': p['prefix'],
                'prefix_len': p['prefix_len']} in prefixes_to_check]

    if (verbosity > 1) and len(current_prefixes_to_check) == 0:
        print('Nothing to check')

    n_prefixes_to_check = len(current_prefixes_to_check)
    if n_prefixes_to_check > 0:
        if verbosity > 2:
            print('Checking %d prefixes' % n_prefixes_to_check, file=sys.stderr)
        prefix_tree = generate_prefix_tree(
            prefixes,
            in_progress_prefix,
            in_progress_prefix_len,
            in_progress_payload,
            to_be_removed_prefix,
            to_be_removed_prefix_len,
            to_be_removed_payload)
    else:
        prefix_tree = None

    for i_p, p in enumerate(current_prefixes_to_check):
        if i_p % 1000 == 999:
            print('Checked %d/%d prefixes' % (i_p, n_prefixes_to_check), file=sys.stderr)
        full_ip = generate_ip_from_prefix(prefix_tree, p['prefix'], p['prefix_len'], randomize_padding=randomize_prefix_padding)
        if full_ip is None:
            print('WARNING: Failed to generate an IP for (prefix 0x%x  len %d  [%s]) which is not shadowed by another prefix' % (
                p['prefix'], p['prefix_len'], format_prefix(p['prefix'], p['prefix_len'])))
            continue
        v_vrf_ip = full_ip['v_vrf_ip']
        full_length = full_ip['full_length']
        if verbosity > 0:
            print('Checking IP 0x%x length %d (original prefix 0x%x  len %d [%s])' %
                  (v_vrf_ip, full_length, p['prefix'], p['prefix_len'], format_prefix(p['prefix'], p['prefix_len'])))
        lookup_payload = lookup_ip(
            v_vrf_ip,
            full_length,
            distributer,
            group_to_core,
            tcams,
            l1,
            l2,
            is_ip_encoded=True,
            verbosity=verbosity)

        possible_payloads = [p['payload']]
        if (p['prefix'] == modify_prefix and p['prefix_len'] == modify_prefix_len):
            possible_payloads.append(modify_payload)
        if (p['prefix'] == to_be_removed_prefix and p['prefix_len'] == to_be_removed_prefix_len):
            possible_payloads.append(to_be_removed_payload)

        if lookup_payload is None:
            print('ERROR: IP 0x%x (created from prefix 0x%x and length %d) not found in LPM (expected hit with payload one of [%s])\n\n' % (
                v_vrf_ip, p['prefix'], p['prefix_len'], ','.join(['0x%x' % pld for pld in possible_payloads])))
            ok = False
            if fail_on_error:
                return ok
            continue

        if lookup_payload not in possible_payloads:
            print('ERROR: IP 0x%x (created from prefix 0x%x and length %d) found in LPM with payload 0x%x while expected one of [%s]\n\n' %
                  (v_vrf_ip, p['prefix'], p['prefix_len'], lookup_payload, ','.join(['0x%x' % pld for pld in possible_payloads])))
            ok = False
            if fail_on_error:
                return ok
            continue
    return ok


def commit_in_progress_prefixes():
    global in_progress_prefix
    global in_progress_prefix_len
    global in_progress_payload
    global modify_prefix
    global modify_prefix_len
    global modify_payload
    global to_be_removed_prefix
    global to_be_removed_prefix_len
    global to_be_removed_payload
    global prefixes
    if in_progress_prefix is not None:
        if verbosity > 1:
            print('UPDATE: committed key 0x%x len %d payload 0x%x to LPM' %
                  (in_progress_prefix, in_progress_prefix_len, in_progress_payload))
        prefixes[(in_progress_prefix, in_progress_prefix_len)] = {
            'prefix': in_progress_prefix, 'prefix_len': in_progress_prefix_len, 'payload': in_progress_payload}
        in_progress_prefix = None
        in_progress_prefix_len = None
        in_progress_payload = None

    if modify_prefix is not None:
        if (modify_prefix, modify_prefix_len) not in prefixes:
            print('Could not find modified route')
            return False
        if verbosity > 1:
            print('UPDATE: committing modify on key 0x%x len %d: payload 0x%x->0x%x' %
                  (modify_prefix, modify_prefix_len, prefixes[(modify_prefix, modify_prefix_len)]['payload'], modify_payload))
        prefixes[(modify_prefix, modify_prefix_len)]['payload'] = modify_payload
        modify_prefix = None
        modify_prefix_len = None
        modify_payload = None

    to_be_removed_prefix = None
    to_be_removed_prefix_len = None
    to_be_removed_payload = None

    return True


def print_distributer(distributer):
    print('------------------------------')
    print('Distributer state')
    for k, v in sorted(distributer.items()):
        print('row %-3d: key 0x%x  width %d  payload 0x%x' % (k, v['key'], v['width'], v['payload']))
    print('------------------------------')


def print_lpm(distributer, group_to_core, tcams, l1, l2):
    print('================ LPM =================')
    print('    --------- Distributer ------------')
    dist_payloads = []
    for k, v in sorted(distributer.items()):
        print('row %-3d: key 0x%020x  width %-4d  group %-4d    core %-2d' %
              (k, v['key'], v['width'], v['payload'], group_to_core[v['payload']]))
        dist_payloads.append(v['payload'])
    print('')
    print('    --------- Group->Core ------------')
    for g, c in enumerate(group_to_core):
        if g in dist_payloads:
            print('group %-4d --> core %-3d' % (g, c))
    print('')
    for icore in range(16):
        print(' ~~~~~~~~~ Core %d ~~~~~~~~~~ ' % icore)
        if (len(tcams[icore]) == 0) and (len(l1[icore]) == 0) and (len(l2[icore]) == 0):
            print('Empty')
            continue
        print(' ------------ Core %d::TCAM ------------- ' % icore)
        tcam_payloads = []
        l1_payloads = []
        for k, v in sorted(tcams[icore].items()):
            tcam_payloads.append(v['payload'])
            print('row %-5d: key 0x%-40x  width %-4d  payload %-5d  IPv%d' %
                  (k, v['key'], v['width'], v['payload'], 6 if v['is_ipv6'] else 4))
        print(' ------------- Core %d::L1 -------------- ' % icore)
        for k, v in sorted(l1[icore].items()):
            is_pointed_by_tcam = k in tcam_payloads
            if not is_pointed_by_tcam and skip_unreachable:
                continue
            print('L1 Bucket %-5d:%s' % (k, ' (unreachable)' if not is_pointed_by_tcam else ''))
            for e in v['entries']:
                if is_pointed_by_tcam:
                    l1_payloads.append(e['payload'])
                print('key 0x%08x  width %-3d  payload %-5d' % (e['key'], e['width'], e['payload']))
            if v['default'] is None:
                print('Default: None')
            else:
                print('Default: payload 0x%05x' % (v['default']))
            print(' ----- ')
        print(' ------------- Core %d::L2 -------------- ' % icore)
        for k, v in sorted(l2[icore].items()):
            is_pointed_by_l1 = k in l1_payloads
            if not is_pointed_by_l1 and skip_unreachable:
                continue
            print('L2 Bucket %-5d:%s' % (k, ' (unreachable)' if not is_pointed_by_l1 else ' '))
            for e in v['entries']:
                print('key 0x%08x  width %-3d  payload 0x%05x' % (e['key'], e['width'], e['payload']))
            if v['default'] is None:
                print('Default: None')
            else:
                print('Default: payload 0x%05x' % (v['default']))
            print(' ----- ')
        print('')


def decode_prefix(prefix, width):
    is_ipv6 = (prefix >> (width - 1)) == 1
    if is_ipv6:
        return (prefix, width)

    broken_bit = 20
    encoded_key_len = 45
    bits_above_broken_bit = encoded_key_len - (broken_bit + 1)
    if width <= bits_above_broken_bit:
        return (prefix, width)

    if encoded_key_len < width:
        import pdb
        pdb.set_trace()
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


def encode_prefix(prefix, width):
    is_ipv6 = (prefix >> (width - 1)) == 1
    if is_ipv6:
        return (prefix, width)

    broken_bit = 20
    decoded_key_len = 44
    encoded_key_len = 45
    bits_above_broken_bit = encoded_key_len - (broken_bit + 1)
    if width <= bits_above_broken_bit:
        return (prefix, width)

    prefix_padded = prefix << (decoded_key_len - width)
    prefix_msb = get_bits(prefix_padded, width - 1, broken_bit)
    prefix_lsb = get_bits(prefix_padded, broken_bit - 1, 0)
    encoded_prefix_padded = (prefix_msb << (broken_bit + 1)) | prefix_lsb
    encoded_prefix = encoded_prefix_padded >> (decoded_key_len - width)

    return (encoded_prefix, width + 1)


def print_lpm_dense(distributer, group_to_core, tcams, l1, l2):
    for icore in range(16):
        for tcam_row, tcam_data in sorted(tcams[icore].items()):
            n_spanned_entries_by_tcam_row = 0
            is_ipv6 = tcam_data['is_ipv6']
            ip_len = 128 if is_ipv6 else 32
            full_length = vrf_len + 1 + ip_len
            tcam_width = tcam_data['width']
            tcam_prefix = tcam_data['key']
            l1_bucket_idx = tcam_data['payload']

            for l1_entry in sorted(l1[icore][l1_bucket_idx]['entries'], key=lambda x: x['width'], reverse=True):
                l1_prefix = l1_entry['key']
                l1_width = l1_entry['width']
                l2_bucket_idx = l1_entry['payload']
                prefix_upto_l1 = (tcam_prefix << l1_width) | l1_prefix
                default_l2_prefix = prefix_upto_l1 << (full_length - l1_width - tcam_width)
                default_l2_vrf = get_bits(default_l2_prefix, ip_len + vrf_len - 1, ip_len)
                default_l2_ip = get_bits(default_l2_prefix, ip_len - 1, 0)
                default_l2_ip_str = ip_to_str(default_l2_ip, is_ipv6)
                default_l2_ip_len = ip_len - (full_length - l1_width - tcam_width)

                for l2_entry in sorted(l2[icore][l2_bucket_idx]['entries'], key=lambda x: x['width'], reverse=True):
                    n_spanned_entries_by_tcam_row += 1
                    l2_prefix = l2_entry['key']
                    l2_width = l2_entry['width']
                    l2_prefix_msb = (tcam_prefix << (l1_width + l2_width)) | (l1_prefix << l2_width) | l2_prefix
                    l2_prefix_msb_width = l1_width + l2_width + tcam_width
                    if not is_ipv6:
                        (l2_prefix_msb, l2_prefix_msb_width) = decode_prefix(l2_prefix_msb, l2_prefix_msb_width)

                    l2_prefix = l2_prefix_msb << (full_length - l2_prefix_msb_width)
                    l2_vrf = get_bits(l2_prefix, ip_len + vrf_len - 1, ip_len)
                    l2_ip = get_bits(l2_prefix, ip_len - 1, 0)
                    l2_ip_len = ip_len - (full_length - l2_prefix_msb_width)
                    l2_ip_str = ip_to_str(l2_ip, is_ipv6)
                    print(
                        '   C=%-3d  T=%-5d (TW=%-3d)  L1=%-5d (L1W=%-3d)  L2=%-5d (L2W=%-3d)   P=0x%05x    VRF=%-3x  PREFIX=%s/%d' %
                        (icore,
                         tcam_row,
                         tcam_width,
                         l1_bucket_idx,
                         l1_width,
                         l2_bucket_idx,
                         l2_width,
                         l2_entry['payload'],
                            l2_vrf,
                            l2_ip_str,
                            l2_ip_len))
                print(
                    '*  C=%-3d  T=%-5d (TW=%-3d)  L1=%-5d (L1W=%-3d)  L2=%-5d (L2W=%-3d)   P=0x%05x    VRF=%-3x  PREFIX=%s/%d' %
                    (icore,
                     tcam_row,
                     tcam_width,
                     l1_bucket_idx,
                     l1_width,
                     l2_bucket_idx,
                     0,
                     l2_entry['payload'],
                        default_l2_vrf,
                        default_l2_ip_str,
                        default_l2_ip_len))
                print('')
            print('   C=%-3d  T=%-5d (TW=%-3d)    Spanned Entries=%d' %
                  (icore, tcam_row, tcam_width, n_spanned_entries_by_tcam_row))
            print('\n')
        print('\n\n')
    print('\n\n\n')


def is_key_v6(key, width):
    return get_bits(key, width - 1, width - 1)


def initialize_lpm_components(state_fname):
    ncores = 16
    ngroups = 128
    distributer = {}
    group_to_core = [0 for _ in range(0, ngroups)]
    tcams = [{} for _ in range(0, ncores)]
    l1 = [{} for _ in range(0, ncores)]
    l2 = [{} for _ in range(0, ncores)]

    if state_fname is None:
        return (distributer, group_to_core, tcams, l1, l2)

    current_core = -1
    parsing_state = None

    with open(state_fname, 'r') as f:
        lines = f.readlines()

    for l in lines:
        m = None

        if m is None:
            m = re.match('.*v4 Distributer.*', l)
            if m is not None:
                parsing_state = 'v4_Distributer'

        if m is None:
            m = re.match('.*v6 Distributer.*', l)
            if m is not None:
                parsing_state = 'v6_Distributer'

        if m is None:
            m = re.match(
                '.*TCAM line (?P<line>([0-9]*)): *\(Key 0x(?P<key>([0-9a-f]*)) *Width (?P<width>([0-9]*)) *Payload 0x(?P<payload>([0-9a-f]*))\).*',
                l)
            if m is not None:
                line = int(m['line'])
                key = int(m['key'], 16)
                width = int(m['width'])
                payload = int(m['payload'], 16)

                if parsing_state == 'v6_Distributer':
                    line += 64  # other half of distributer

                if parsing_state in ['v4_Distributer', 'v6_Distributer']:
                    distributer[line] = {'key': key, 'width': width, 'payload': payload}
                elif parsing_state == 'CORE':
                    is_ipv6 = is_key_v6(key, width)
                    key = get_bits(key, width - 1, 0)
                    tcams[current_core][line] = {'key': key, 'width': width, 'payload': payload, 'is_ipv6': is_ipv6}

        if m is None:
            m = re.match('.*group\[(?P<group>([0-9]*))\] -> core (?P<core>([0-9]*)).*', l)
            if m is not None:
                group = int(m['group'])
                core = int(m['core'])
                group_to_core[group] = core

        if m is None:
            m = re.match('.*State of core (?P<core>([0-9]*)).*', l)
            if m is not None:
                current_core = int(m['core'])
                parsing_state = 'CORE'

        if m is None:
            m = re.match(
                '.*L(?P<tree>([1-2])) Tree. Bucket hw index (?P<line>([0-9]*))  Node: \(Key 0x(?P<key>([0-9a-f]*)) *Width (?P<width>([0-9]*)) *Payload 0x(?P<payload>([0-9a-f]*))\) *Bucket root width: (?P<root_width>([0-9]*)).*',
                l)
            if m is not None:
                tree_id = int(m['tree'])
                line = int(m['line'])
                key = int(m['key'], 16)
                width = int(m['width'])
                payload = int(m['payload'], 16)
                root_width = int(m['root_width'])
                clean_width = width - root_width
                clean_key = get_bits(key, clean_width - 1, 0)

                if tree_id == 1:  # L1
                    tree = l1
                else:  # L2
                    tree = l2

                if line not in tree[current_core]:
                    print('tree L%d  core %d  line %d' % (tree_id, current_core, line))
                    tree[current_core][line] = {'entries': [], 'default': None}
                tree[current_core][line]['entries'].append({'key': clean_key, 'width': clean_width, 'payload': payload})

    print('Initial state of LPM:')
    print_lpm(distributer, group_to_core, tcams, l1, l2)

    return (distributer, group_to_core, tcams, l1, l2)


def is_l1_row_pointed_to(tcam, row):
    tcam_pointers = [(k, v) for (k, v) in tcam.items() if v['payload'] == row]
    if len(tcam_pointers) > 0:
        for t in tcam_pointers:
            print('TCAM row %d  key 0x%x  width %d  payload 0x%x' % (t[0], t[1]['key'], t[1]['width'], t[1]['payload']))
        return True
    return False


def is_l2_row_pointed_to(tcam, l1, row):
    tcam_l1_pointers = []
    for tcam_row, tcam_data in tcam.items():
        l1_row = tcam_data['payload']
        for l1_entry in l1[l1_row]['entries']:
            if l1_entry['payload'] == row:
                tcam_l1_pointers.append({'tcam_row': tcam_row, 'tcam_data': tcam_data,
                                         'l1_row': l1_row, 'l1_entry': l1_entry})

    if len(tcam_l1_pointers) > 0:
        for e in tcam_l1_pointers:
            print('TCAM row %d  key 0x%x  width %d  payload 0x%x --> L1 row %d  key 0x%x  width %d  payload 0x%x' %
                  (e['tcam_row'],
                   e['tcam_data']['key'],
                   e['tcam_data']['width'],
                   e['tcam_data']['payload'],
                   e['l1_row'],
                   e['l1_entry']['key'],
                   e['l1_entry']['width'],
                   e['l1_entry']['payload']))
        return True
    return False


def check_tree_row_new_or_only_refresh(level, core, row, tcams, l1, l2, saved_row_content):
    global verbosity

    if saved_row_content is None:
        return True

    tree = l1 if level == 1 else l2

    original_keys_sorted = sorted([{'key': e['key'], 'width': e['width']}
                                   for e in saved_row_content['entries']], key=lambda x: x['key'])

    current_keys_sorted = sorted([{'key': e['key'], 'width': e['width']}
                                  for e in tree[core][row]['entries']], key=lambda x: x['key'])

    if original_keys_sorted == current_keys_sorted:  # only payloads have changed
        return True

    if (level == 1) and is_l1_row_pointed_to(tcams[core], row):
        print('ERROR: Overriding L1 row %d which is pointed by tcam entries' % row)
        return False

    if (level == 2) and is_l2_row_pointed_to(tcams[core], l1[core], row):
        print('ERROR: Overriding L2 row %d which is pointed by TCAM->L1 entries' % row)
        return False

    return True


def dump_lpm_to_file(fname, distributer, group_to_core, tcams, l1, l2, prefixes):
    print('Dumping LPM to file %s' % fname, file=sys.stderr)
    with open(fname, 'wb') as f:
        pickle.dump(distributer, f)
        pickle.dump(group_to_core, f)
        pickle.dump(tcams, f)
        pickle.dump(l1, f)
        pickle.dump(l2, f)
        pickle.dump(prefixes, f)
    print('Dumping LPM done', file=sys.stderr)


def load_lpm_from_dump(fname):
    print('Loading LPM from dump file %s' % fname, file=sys.stderr)
    with open(fname, 'rb') as f:
        distributer = pickle.load(f)
        group_to_core = pickle.load(f)
        tcams = pickle.load(f)
        l1 = pickle.load(f)
        l2 = pickle.load(f)
        prefixes = pickle.load(f)
    print('Loading LPM done', file=sys.stderr)
    return (distributer, group_to_core, tcams, l1, l2, prefixes)


def verify_lpm_consistency(log_fname, state_fname, load_fname, dump_fname, prefixes_to_check, fail_on_error, check_boundary):
    global in_progress_prefix
    global in_progress_prefix_len
    global in_progress_payload
    global modify_prefix
    global modify_prefix_len
    global modify_payload
    global to_be_removed_prefix
    global to_be_removed_prefix_len
    global to_be_removed_payload
    global prefixes
    global verbosity

    has_errors = False
    check_is_enabled = (check_boundary not in ['never', 'end'])

    distributer, group_to_core, tcams, l1, l2 = initialize_lpm_components(state_fname)

    if load_fname is not None:
        distributer, group_to_core, tcams, l1, l2, prefixes = load_lpm_from_dump(load_fname)
        ok = check_lpm_state(prefixes_to_check, -1, 'DUMP', distributer, group_to_core, tcams, l1, l2, fail_on_error)
        if ok:
            print('Looks OK')
            print('Looks OK', file=sys.stderr)
            return (True, distributer, group_to_core, tcams, l1, l2)
        else:
            print('LPM not consistent after EOF')
            print('LPM not consistent after EOF', file=sys.stderr)
            return (False, distributer, group_to_core, tcams, l1, l2)

    with open(log_fname, 'r') as f:
        nlines = sum(1 for line in f)

    f = open(log_fname, 'r')

    for lidx, l in enumerate(f):
        lno = lidx + 1
        check_consistency = False
        m = None

        if lidx % 1000 == 0:
            print('Progress: Line %d/%d (matched %d)' % (lno, nlines, n_matched_lines), file=sys.stderr)

        if len(l) > 0 and l.strip(' ')[0] == '#':
            continue
        if 'LPM_CHECK_ON' in l:
            log_match(lno, l)
            check_is_enabled = True
            check_consistency = True
        elif 'LPM_CHECK_OFF' in l:
            log_match(lno, l)
            check_is_enabled = False
            continue
        elif 'LPM_PRINT_CONTENT_DENSE' in l:
            log_match(lno, l)
            print_lpm_dense(distributer, group_to_core, tcams, l1, l2)
            continue
        elif 'LPM_PRINT_CONTENT' in l:
            log_match(lno, l)
            print_lpm(distributer, group_to_core, tcams, l1, l2)
            continue
        elif 'LPM_SET_VERBOSITY' in l:
            m = re.match('.*LPM_SET_VERBOSITY (?P<verbosity>([0-9]+)).*', l)
            if m is not None:
                log_match(lno, l)
                verbosity = int(m['verbosity'])
        elif 'LPM_SET_PREFIXES_TO_CHECK ALL' in l:
            prefixes_to_check = 'All'
            ret = commit_in_progress_prefixes()
            if not ret:
                return (False, distributer, group_to_core, tcams, l1, l2)
        elif 'LPM_CHECK_EXIT' in l:
            log_match(lno, l)
            return (True, distributer, group_to_core, tcams, l1, l2)
        elif 'LPM_DO_LOOKUP' in l:
            m = re.match('.*LPM_DO_LOOKUP (?P<vrf>([0-9x]*)) (?P<ip>([0-9a-f.:]*)).*', l)
            if m is not None:
                log_match(lno, l)
                vrf = int(m['vrf'], 0)
                ip_str = m['ip']
                (v_vrf_ip, full_length) = ip_str_to_key(vrf, ip_str, perform_encoding=True)
                payload = lookup_ip(v_vrf_ip, full_length, distributer, group_to_core,
                                    tcams, l1, l2, is_ip_encoded=True, verbosity=2)
        elif 'LPM_SHOW_PREFIXES' in l:
            for p in prefixes.values():
                print('prefix 0x%x  length %d  payload 0x%x' % (p['prefix'], p['prefix_len'], p['payload']))
        elif 'COMMIT_IN_PROGRESS_PREFIXES' in l:
            log_match(lno, l)
            ret = commit_in_progress_prefixes()
            if not ret:
                return (False, distributer, group_to_core, tcams, l1, l2)
        elif 'DUMP_LPM_TO_FILE' in l:
            m = re.match('.*DUMP_LPM_TO_FILE (?P<fname>(.*\.dump)).*', l)
            if m is not None:
                log_match(lno, l)
                fname = m['fname']
                dump_lpm_to_file(fname, distributer, group_to_core, tcams, l1, l2, prefixes)
        elif '-TABLES-' not in l:
            continue

        if m is None and 'LPM ACTION: INSERT' in l:
            m = re.match(
                '.*LPM ACTION: INSERT key 0x(?P<key>([0-9a-f]*)) * key width (?P<width>([0-9]*)) *payload = (0x)?(?P<payload>([0-9a-f]*)).*', l)
            if m is not None:
                log_match(lno, l)
                ret = commit_in_progress_prefixes()
                if not ret:
                    return (False, distributer, group_to_core, tcams, l1, l2)
                in_progress_prefix = int(m['key'], 16)
                in_progress_prefix_len = int(m['width'], 10)
                in_progress_payload = int(m['payload'], 16)
                if (in_progress_prefix >> in_progress_prefix_len) != 0:
                    print('Prefix and prefix len do not match')
                    return (False, distributer, group_to_core, tcams, l1, l2)
                if verbosity > 1:
                    print('UPDATE: Going to insert key 0x%x len %d payload 0x%x to LPM' %
                          (in_progress_prefix, in_progress_prefix_len, in_progress_payload))
                check_consistency = check_is_enabled

        if m is None and 'LPM ACTION: REMOVE' in l:
            m = re.match('.*LPM ACTION: REMOVE key 0x(?P<key>([0-9a-f]*))   key width (?P<width>([0-9]*)).*', l)
            if m is not None:
                log_match(lno, l)
                ret = commit_in_progress_prefixes()
                if not ret:
                    return (False, distributer, group_to_core, tcams, l1, l2)
                prefix = int(m['key'], 16)
                prefix_len = int(m['width'], 10)
                if verbosity > 1:
                    print('UPDATE: Going to remove key 0x%x len %d from LPM' %
                          (prefix, prefix_len))
                if (prefix, prefix_len) not in prefixes:
                    if state_fname is None:
                        print('ERROR: Removing non existent prefix')
                        print('current prefixes:')
                        print_prefixes()
                        return (False, distributer, group_to_core, tcams, l1, l2)

                to_be_removed_prefix = prefix
                to_be_removed_prefix_len = prefix_len
                to_be_removed_payload = prefixes[(prefix, prefix_len)]['payload']
                del prefixes[(prefix, prefix_len)]
                check_consistency = check_is_enabled

        if m is None and 'LPM ACTION: MODIFY' in l:
            m = re.match(
                '.*LPM ACTION: MODIFY key 0x(?P<key>([0-9a-f]*)) * key width (?P<width>([0-9]*)) *payload = (0x)?(?P<payload>([0-9a-f]*)).*', l)
            if m is not None:
                log_match(lno, l)
                ret = commit_in_progress_prefixes()
                if not ret:
                    return (False, distributer, group_to_core, tcams, l1, l2)
                modify_prefix = int(m['key'], 16)
                modify_prefix_len = int(m['width'], 10)
                modify_payload = int(m['payload'], 16)
                if (modify_prefix, modify_prefix_len) not in prefixes:
                    print('ERROR: Going to modify non existent key 0x%x  len %d' % (modify_prefix, modify_prefix_len))
                    print('current prefixes:')
                    print_prefixes()
                    return (False, distributer, group_to_core, tcams, l1, l2)

                if verbosity > 1:
                    print('UPDATE: Going to modify payload of key 0x%x len %d in LPM from 0x%x to 0x%x' %
                          (modify_prefix, modify_prefix_len, prefixes[(modify_prefix, modify_prefix_len)]['payload'], modify_payload))
                check_consistency = check_is_enabled

        if m is None:
            if 'Rebalance starting' in l:
                log_match(lno, l)
                ret = commit_in_progress_prefixes()
                if not ret:
                    return (False, distributer, group_to_core, tcams, l1, l2)
                check_consistency = check_is_enabled

        if m is None and 'Write L' in l:
            m = re.match(
                '.*LPM Core (?P<core>([0-9]*)) Write L(?P<tree>([1-2])) Bucket Line (?P<line>([0-9]*))  #Nodes (?P<nnodes>([0-9]*))  root width (?P<rwidth>([0-9]*)):',
                l)
            if m is not None:
                log_match(lno, l)
                current_core = int(m['core'], 10)
                current_tree = int(m['tree'])
                current_row = int(m['line'], 10)
                n_nodes = int(m['nnodes'], 10)
                root_width = int(m['rwidth'], 10)
                nodes_seen = 0

                tree = l1 if current_tree == 1 else l2

                if (current_row in tree[current_core]) and not disable_bucket_override_check:
                    saved_row_content = copy.deepcopy(tree[current_core][current_row])
                else:
                    saved_row_content = None

                if verbosity > 1:
                    print('UPDATE: Going to update L%d row %d (core %d)' % (current_tree, current_row, current_core))
                tree[current_core][current_row] = {'entries': [], 'default': None}
                check_consistency = False

        if m is None and 'Node: key' in l:
            m = re.match('.*Node: key (?P<key>([0-9a-f]*)) width (?P<width>([0-9]*)) payload (?P<payload>([0-9a-f]*))', l)
            if m is not None:
                log_match(lno, l)
                key = int(m['key'], 16)
                width = int(m['width'], 10)
                payload = int(m['payload'], 16)
                clean_width = width - root_width
                clean_key = get_bits(key, clean_width - 1, 0)
                nodes_seen += 1

                if verbosity > 1:
                    print('UPDATE: Going to update L%d row %d (core %d). Adding entry: key 0x%x  length %d  payload 0x%x' %
                          (current_tree, current_row, current_core, clean_key, clean_width, payload))

                tree = l1 if current_tree == 1 else l2
                tree[current_core][current_row]['entries'].append({'key': clean_key, 'width': clean_width, 'payload': payload})
                check_consistency = False

        if m is None and 'Default bucket payload' in l:
            m = re.match('.*Default bucket payload (?P<payload>([0-9a-f]*))', l)
            if m is not None:
                log_match(lno, l)
                tree = l1 if current_tree == 1 else l2
                payload = int(m['payload'], 16)
                tree[current_core][current_row]['default'] = payload

                if not disable_bucket_override_check:
                    ok = check_tree_row_new_or_only_refresh(
                        current_tree, current_core, current_row, tcams, l1, l2, saved_row_content)
                    if not ok:
                        return (False, distributer, group_to_core, tcams, l1, l2)
                check_consistency = check_is_enabled and (check_boundary == 'any')

        if m is None and 'TCAM Wr' in l:
            m = re.match(
                '.*LPM: TCAM Wr *core = (?P<core>([0-9]*)) *row = (?P<row>([0-9]*)) *key = 0x(?P<key>([0-9a-f]*)) *key width = (?P<width>([0-9]*)) *payload = (?P<payload>([0-9]*))',
                l)
            if m is not None:
                log_match(lno, l)
                core = int(m['core'], 10)
                row = int(m['row'], 10)
                key = int(m['key'], 16)
                width = int(m['width'], 10)
                payload = int(m['payload'], 10)
                is_ipv6 = get_bits(key, width - 1, width - 1)
                key = get_bits(key, width - 1, 0)
                if row in tcams[core]:
                    if verbosity > 1:
                        print('Overriding a valid TCAM row (core %d row %d)' % (core, row))
                    if (tcams[core][row]['key'] == key) and (tcams[core][row]['width'] == width):
                        if verbosity > 1:
                            print('Only payload is being modified')
                    else:
                        print('ERROR: Override a valid TCAM row (core %d  row %d): key 0x%x/%d->0x%x/%d' %
                              (core, row, tcams[core][row]['key'], tcams[core][row]['width'], key, width))
                        print('%d: %s' % (lno, l))
                        return (False, distributer, group_to_core, tcams, l1, l2)

                if verbosity > 1:
                    print(
                        'UPDATE: Writing to TCAM core %d row %d: key 0x%x  len %d  payload 0x%x' %
                        (core, row, key, width, payload))
                tcams[core][row] = {'key': key, 'width': width, 'payload': payload, 'is_ipv6': is_ipv6}
                check_consistency = check_is_enabled and (check_boundary == 'any')

        if m is None and 'TCAM Iv' in l:
            m = re.match('.*LPM: TCAM Iv *core = (?P<core>([0-9]*)) *row = (?P<row>([0-9]*))', l)
            if m is not None:
                log_match(lno, l)
                core = int(m['core'], 10)
                row = int(m['row'], 10)
                if row in tcams[core]:
                    if verbosity > 1:
                        print('UPDATE: Invalidating TCAM core %d row %d' % (core, row))
                    tcams[core].pop(row)
                else:
                    print('WARNING: TCAM Invalidation of already invalid row %d  [log file line %d]' % (row, lno))
                    # return (False, distributer, group_to_core, tcams, l1, l2)
                check_consistency = check_is_enabled and (check_boundary == 'any')

        if m is None and 'assigning group' in l:
            m = re.match('.*assigning group (?P<group>([0-9]*)) to core (?P<core>([0-9]*))', l)
            if m is not None:
                log_match(lno, l)
                group = int(m['group'], 10)
                core = int(m['core'], 10)
                if verbosity > 1:
                    print('UPDATE: Assigning group %d to core %d' % (group, core))
                group_to_core[group] = core
                check_consistency = check_is_enabled and (check_boundary == 'any')

        if m is None and 'set_distributor_line' in l:
            m = re.match(
                '.*set_distributor_line\(line after offset = (?P<line>([0-9]*)), key = (?P<key>([0-9a-f]*)), key width = (?P<width>([0-9]*)), payload = (0x)?(?P<payload>([0-9a-f]*)).*', l)
            if m is not None:
                log_match(lno, l)
                row = int(m['line'], 10)
                key = int(m['key'], 16)
                width = int(m['width'], 10)
                payload = int(m['payload'], 16)
                if verbosity > 1:
                    print('UPDATE: Writing distributer row %d: key 0x%x  width %d  payload 0x%x' % (row, key, width, payload))
                if row in distributer:
                    print('ERROR: Distributer overriding an existing row %d [log file line %d]' % (row, lno))
                    print_distributer(distributer)
                    return (False, distributer, group_to_core, tcams, l1, l2)
                distributer[row] = {'key': key, 'width': width, 'payload': payload}
                check_consistency = check_is_enabled and (check_boundary == 'any')

        if m is None and 'remove_distributor_line' in l:
            m = re.match('.*remove_distributor_line\(line after offset = (?P<line>([0-9]*)).*', l)
            if m is not None:
                log_match(lno, l)
                row = int(m['line'], 10)
                if row in distributer:
                    distributer.pop(row)
                else:
                    print('ERROR: Distributer removing an invalid row %d  [log file line %d]' % (row, lno))
                    print_distributer(distributer)
                    return (False, distributer, group_to_core, tcams, l1, l2)
                check_consistency = check_is_enabled and (check_boundary == 'any')

        if m is None:
            log_match(lno, l, match=False)
        else:
            if verbosity > 3:
                print_lpm(distributer, group_to_core, tcams, l1, l2)

        if check_consistency:
            ok = check_lpm_state(prefixes_to_check, lno, l, distributer, group_to_core, tcams, l1, l2, fail_on_error)
            if not ok:
                print_lpm(distributer, group_to_core, tcams, l1, l2)
                has_errors = True
                print('ERROR: LPM not consistent after log line %d: %s' % (lno, l))
                if fail_on_error:
                    return (False, distributer, group_to_core, tcams, l1, l2)

    ret = commit_in_progress_prefixes()
    if not ret:
        return (False, distributer, group_to_core, tcams, l1, l2)

    if dump_fname is not None:
        dump_lpm_to_file(dump_fname, distributer, group_to_core, tcams, l1, l2, prefixes)

    # final check after finishing the log file
    if verbosity > 2:
        print_lpm(distributer, group_to_core, tcams, l1, l2)
    if check_boundary != 'never':
        ok = check_lpm_state(prefixes_to_check, -1, 'EOF', distributer, group_to_core, tcams, l1, l2, fail_on_error)
        if not ok:
            has_errors = True
            print('ERROR: LPM not consistent after EOF')
            if fail_on_error:
                return (False, distributer, group_to_core, tcams, l1, l2)

        if not has_errors:
            print('Looks OK')

    return (True, distributer, group_to_core, tcams, l1, l2)


def prefix_str_to_dict(p):
    try:
        prefix, len = p.split('/')
    except BaseException:
        return None

    try:
        prefix = int(prefix, 0)
        len = int(len, 10)
    except BaseException:
        return None

    return {'prefix': prefix,
            'prefix_len': len}


def prefixes_str_to_dict(ps):
    list_of_prefixes = ps.split(',')
    res = [prefix_str_to_dict(p) for p in list_of_prefixes]
    if None in res:
        return None
    return res


def main():
    global verbosity

    if sys.version_info[0] < 3:
        print('Must use python3')
        sys.exit(1)

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("input_file", help="log file to parse, or a dump file ending with .dump", type=str)
    parser.add_argument("-v", "--verbosity", action="count", help="Verbose. Can use multiple times")
    parser.add_argument("-e", "--no_fail_on_error", action="store_true", help="Don't fail on Error")
    parser.add_argument(
        "-b",
        "--check_boundary",
        choices=[
            'any',
            'action',
            'end',
            'never'],
        default='any',
        help='When to check consistency: any = After any HW update, action = after LPM ACTION, end = only in the end, never = do not check at all')
    parser.add_argument(
        "-p",
        "--prefixes_to_check",
        type=str,
        default='All',
        help="check only these perfixes, comma delimited. syntax: prefix/len, All, None")
    parser.add_argument(
        "-s",
        "--state",
        help="file containing LPM's initial state (as logged by logical_lpm::log_state())",
        type=str)
    parser.add_argument("-d", "--dump", help="dump LPM state to a file", type=str)
    args = parser.parse_args()

    _, input_ext = os.path.splitext(args.input_file)
    if input_ext == '.dump':
        is_input_file_log = False
        is_input_file_dump = True
    else:
        is_input_file_log = True
        is_input_file_dump = False

    fname = args.input_file if is_input_file_log else None
    verbosity = args.verbosity if args.verbosity else 0
    fail_on_error = not args.no_fail_on_error
    check_boundary = args.check_boundary

    if args.prefixes_to_check in ['All', 'None']:
        prefixes_to_check = args.prefixes_to_check
    else:
        prefixes_to_check = prefixes_str_to_dict(args.prefixes_to_check)
        if prefixes_to_check is None:
            print('prefix format is not good. use prefix/len')
            sys.exit(1)

    state_fname = args.state
    dump_fname = args.dump
    load_fname = args.input_file if is_input_file_dump else None

    if state_fname and load_fname:
        print('--state and --load cannot be used together', file=sys.stderr)
        sys.exit(1)

    if load_fname and dump_fname:
        print('Warning: --load and --dump both provided')
        if load_fname == dump_fname:
            print('Warning: requested to load and dump to same file. Will not dump as it will have no effect')
            dump_fname = None

    ok, distributer, group_to_core, tcams, l1, l2 = verify_lpm_consistency(
        fname, state_fname, load_fname, dump_fname, prefixes_to_check, fail_on_error, check_boundary)
    if not ok:
        print('Dumping current LPM state for your convenience, you are welcome')
        err_dump_fname = 'lpm.err.dump'
        dump_lpm_to_file(err_dump_fname, distributer, group_to_core, tcams, l1, l2, prefixes)
        sys.exit(1)


if __name__ == '__main__':
    random.seed(0)
    main()
