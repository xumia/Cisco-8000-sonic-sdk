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

debug = False
annotate = True
create_catch_all_on_vrf_creation = True
create_zero_ip_on_vrf_creation = False
random_payload = True
V4_VRF_LEN = 11
V6_VRF_LEN = 11


def generate_payload(randomize):
    return random.randint(1, (1 << 20) - 1) if randomize else 0


def v4_route_to_prefix(s_vrf, route):
    vrf = int(s_vrf)
    route_split = route.split('/')
    prefix = route_split[0]
    prefix_len = int(route_split[1])
    prefix_as_int = int(''.join(['%02x' % int(b) for b in prefix.split('.')]), 16)
    prefix_full = (vrf << 32) | prefix_as_int
    prefix_full_shifted = prefix_full >> (32 - prefix_len)
    prefix_full_len = prefix_len + V4_VRF_LEN + 1
    return {'prefix': prefix_full_shifted, 'prefix_len': prefix_full_len, 'route': route, 'ip': prefix_as_int, 'ip_len': prefix_len}


def v6_route_to_prefix(s_vrf, route):
    vrf = int(s_vrf)
    route_split = route.split('/')
    prefix = route_split[0]
    prefix_len = int(route_split[1])
    prefix_as_int = int(''.join(['%04x' % int(w, 16) for w in prefix.split(':')]), 16)
    prefix_full = (1 << (128 + V6_VRF_LEN)) | (vrf << 128) | prefix_as_int
    prefix_full_shifted = prefix_full >> (128 - prefix_len)
    prefix_full_len = prefix_len + V6_VRF_LEN + 1
    return {'prefix': prefix_full_shifted, 'prefix_len': prefix_full_len, 'route': route, 'ip': prefix_as_int, 'ip_len': prefix_len}


def vrf_to_prefixes(s_vrf):
    prefixes = []
    if create_catch_all_on_vrf_creation:
        v4_catch_all = v4_route_to_prefix(s_vrf, '0.0.0.0/0')
        v6_catch_all = v6_route_to_prefix(s_vrf, '0:0:0:0/0')
        prefixes.append(v4_catch_all)
        prefixes.append(v6_catch_all)
    if create_zero_ip_on_vrf_creation:
        v4_zero_ip = v4_route_to_prefix(s_vrf, '0.0.0.0/32')
        v6_zero_ip = v6_route_to_prefix(s_vrf, '0:0:0:0/128')
        prefixes.append(v4_zero_ip)
        prefixes.append(v6_zero_ip)
    return prefixes


configured_device = None
error_on_other_devices = False


def is_my_device(this_device):
    global configured_device
    global error_on_other_devices

    if this_device == configured_device:
        return True

    if configured_device is None:
        configured_device = this_device
        error_on_other_devices = True
        return True

    if error_on_other_devices:
        print("API log has multiple devices, please specify one", file=sys.stderr)
        sys.exit(1)
    return False


vrf_oid_to_vrf = {}

user_v4_catch_all_configured = []
user_v4_zero_ip_configured = []


def match_add_ipv4_route(line):
    global vrf_oid_to_vrf
    global user_v4_catch_all_configured
    global user_v4_zero_ip_configured

    if 'add_ipv4_route' not in line:
        return False

    m = re.match(
        r'.*leaba_sdk Device: (?P<device>([0-9]+)) .*la_vrf_impl\(oid = (?P<vrf_oid>([0-9]+))\)::add_ipv4_route\(prefix= prefix=(?P<route>([0-9\.\/]+)).*',
        line)
    if m is None:
        return False
    if not is_my_device(int(m['device'])):
        return True
    vrf = vrf_oid_to_vrf[m['vrf_oid']]
    p = v4_route_to_prefix(vrf, m['route'])

    if (p['prefix_len'] == 1 + V4_VRF_LEN) and (p['ip'] ==
                                                0) and create_catch_all_on_vrf_creation and (vrf not in user_v4_catch_all_configured):
        user_v4_catch_all_configured.append(vrf)
        if debug:
            print('AddRouteV4 vrf %s  route %s (converting to modify catch all entry)' % (vrf, m['route']))
        annotation = ' // vrf = %s  route = %s (add_ipv4_route -> modify catch all)' % (vrf, m['route']) if annotate else ''
        payload = generate_payload(random_payload)
        print('lpm_modify %x %d %x%s' % (p['prefix'], p['prefix_len'], payload, annotation))
    elif (p['prefix_len'] == 1 + V4_VRF_LEN + 32) and p['ip'] == 0 and create_zero_ip_on_vrf_creation and (vrf not in user_v4_zero_ip_configured):
        user_v4_zero_ip_configured.append(vrf)
        if debug:
            print('AddRouteV4 vrf %s  route %s (converting to modify 0.0.0.0/32)' % (vrf, m['route']))
        annotation = ' // vrf = %s  route = %s (add_ipv4_route -> modify illegal DIP)' % (vrf, m['route']) if annotate else ''
        payload = generate_payload(random_payload)
        print('lpm_modify %x %d %x%s' % (p['prefix'], p['prefix_len'], payload, annotation))
    else:
        if debug:
            print('AddRouteV4 vrf %s  route %s' % (vrf, m['route']))
        annotation = ' // vrf = %s  route = %s (add_ipv4_route)' % (vrf, m['route']) if annotate else ''
        payload = generate_payload(random_payload)
        print('lpm_insert %x %d %x%s' % (p['prefix'], p['prefix_len'], payload, annotation))
    return True


def match_modify_ipv4_route(line):
    global vrf_oid_to_vrf
    global user_v4_catch_all_configured

    if 'modify_ipv4_route' not in line:
        return False

    m = re.match(
        r'.*leaba_sdk Device: (?P<device>([0-9]+)) .*la_vrf_impl\(oid = (?P<vrf_oid>([0-9]+))\)::modify_ipv4_route\(prefix= prefix=(?P<route>([0-9\.\/]+)).*',
        line)
    if m is None:
        return FAlse
    if not is_my_device(int(m['device'])):
        return True
    vrf = vrf_oid_to_vrf[m['vrf_oid']]
    p = v4_route_to_prefix(vrf, m['route'])

    if debug:
        print('ModifyRouteV4 vrf %s  route %s' % (vrf, m['route']))
    annotation = ' // vrf = %s  route = %s (modify_ipv4_route)' % (vrf, m['route']) if annotate else ''
    payload = generate_payload(random_payload)
    print('lpm_modify %x %d %x%s' % (p['prefix'], p['prefix_len'], payload, annotation))
    return True


def match_delete_ipv4_route(line):
    global vrf_oid_to_vrf

    if 'delete_ipv4_route' not in line:
        return False

    m = re.match(
        r'.*leaba_sdk Device: (?P<device>([0-9]+)) .*la_vrf_impl\(oid = (?P<vrf_oid>([0-9]+))\)::delete_ipv4_route\(prefix= prefix=(?P<route>([0-9\.\/]+)).*',
        line)
    if m is None:
        return False
    if not is_my_device(int(m['device'])):
        return True
    vrf = vrf_oid_to_vrf[m['vrf_oid']]
    p = v4_route_to_prefix(vrf, m['route'])
    if debug:
        print('DeleteRouteV4 vrf %s  route %s' % (vrf, m['route']))
    annotation = ' // vrf = %s  route = %s (remove_ipv4_route)' % (vrf, m['route']) if annotate else ''
    print('lpm_remove %x %d%s' % (p['prefix'], p['prefix_len'], annotation))
    return True


user_v6_catch_all_configured = []
user_v6_zero_ip_configured = []


def match_add_ipv6_route(line, include_128):
    global vrf_oid_to_vrf
    global user_v6_catch_all_configured
    global user_v6_zero_ip_configured
    if 'add_ipv6_route' not in line:
        return False

    m = re.match(
        r'.*leaba_sdk Device: (?P<device>([0-9]+)) .*la_vrf_impl\(oid = (?P<vrf_oid>([0-9]+))\)::add_ipv6_route\(prefix= prefix=(?P<route>([0-9a-f:\/]+)).*',
        line)
    if m is None:
        return False
    if not is_my_device(int(m['device'])):
        return True
    vrf = vrf_oid_to_vrf[m['vrf_oid']]
    p = v6_route_to_prefix(vrf, m['route'])

    if (p['prefix_len'] == 1 + V6_VRF_LEN + 128) and not include_128:
        return True

    if (p['prefix_len'] == 1 + V6_VRF_LEN) and (p['ip'] ==
                                                0) and create_catch_all_on_vrf_creation and (vrf not in user_v6_catch_all_configured):
        user_v6_catch_all_configured.append(vrf)
        if debug:
            print('AddRouteV6 vrf %s  route %s (converting to modify catch all entry)' % (vrf, m['route']))
        annotation = ' // vrf = %s  route = %s (add_ipv6_route -> modify catch all)' % (vrf, m['route']) if annotate else ''
        payload = generate_payload(random_payload)
        print('lpm_modify %x %d %x%s' % (p['prefix'], p['prefix_len'], payload, annotation))
    elif (p['prefix_len'] == 1 + V6_VRF_LEN + 128) and (p['ip'] == 0) and create_zero_ip_on_vrf_creation and (vrf not in user_v6_zero_ip_configured):
        user_v6_zero_ip_configured.append(vrf)
        if debug:
            print('AddRouteV6 vrf %s  route %s (converting to modify ::0/128)' % (vrf, m['route']))
        annotation = ' // vrf = %s  route = %s (add_ipv6_route -> modify illegal DIP)' % (vrf, m['route']) if annotate else ''
        payload = generate_payload(random_payload)
        print('lpm_modify %x %d %x%s' % (p['prefix'], p['prefix_len'], payload, annotation))
    else:
        if debug:
            print('AddRouteV6 vrf %s  route %s' % (vrf, m['route']))
        annotation = ' // vrf = %s  route = %s (add_ipv6_route)' % (vrf, m['route']) if annotate else ''
        payload = generate_payload(random_payload)
        print('lpm_insert %x %d %x%s' % (p['prefix'], p['prefix_len'], payload, annotation))
    return True


def match_modify_ipv6_route(line, include_128):
    global vrf_oid_to_vrf
    if 'modify_ipv6_route' not in line:
        return False

    m = re.match(
        r'.*leaba_sdk Device: (?P<device>([0-9]+)) .*la_vrf_impl\(oid = (?P<vrf_oid>([0-9]+))\)::modify_ipv6_route\(prefix = prefix=(?P<route>([0-9a-f:\/]+)).*',
        line)
    if m is None:
        return False
    if not is_my_device(int(m['device'])):
        return True
    vrf = vrf_oid_to_vrf[m['vrf_oid']]
    p = v6_route_to_prefix(vrf, m['route'])

    if (p['prefix_len'] == 1 + V6_VRF_LEN + 128) and not include_128:
        return True

    if debug:
        print('ModifyRouteV6 vrf %s  route %s' % (vrf, m['route']))
    annotation = ' // vrf = %s  route = %s (modify_ipv6_route)' % (vrf,
                                                                   m['route']) if annotate else ''
    payload = generate_payload(random_payload)
    print('lpm_modify %x %d %x%s' % (p['prefix'], p['prefix_len'], payload, annotation))
    return True


def match_delete_ipv6_route(line, include_128):
    global vrf_oid_to_vrf
    if 'delete_ipv6_route' not in line:
        return False

    m = re.match(
        r'.*leaba_sdk Device: (?P<device>([0-9]+)) .*la_vrf_impl\(oid = (?P<vrf_oid>([0-9]+))\)::delete_ipv6_route\(prefix= prefix=(?P<route>([0-9a-f:\/]+)).*',
        line)
    if m is None:
        return False
    if not is_my_device(int(m['device'])):
        return True
    vrf = vrf_oid_to_vrf[m['vrf_oid']]
    p = v6_route_to_prefix(vrf, m['route'])

    if (p['prefix_len'] == 1 + V6_VRF_LEN + 128) and not include_128:
        return True

    if debug:
        print('DeleteRouteV6 vrf %s  route %s' % (vrf, m['route']))
    annotation = ' // vrf = %s  route = %s (delete_ipv6_route)' % (vrf, m['route']) if annotate else ''
    print('lpm_remove %x %d%s' % (p['prefix'], p['prefix_len'], annotation))
    return True


current_vrf_gid = None


def match_create_vrf(line):
    global vrf_oid_to_vrf
    global current_vrf_gid
    if 'create_vrf' not in line:
        return False

    m = re.match(r'.*leaba_sdk Device: (?P<device>([0-9]+)) .*la_device_impl.*::create_vrf\(vrf_gid= (?P<vrf>([0-9]+))\).*', line)
    if m is None:
        return False
    if not is_my_device(int(m['device'])):
        return True
    current_vrf_gid = m['vrf']
    if debug:
        print('Create vrf %s' % m['vrf'])
    return True


def match_vrf_created(line):
    global vrf_oid_to_vrf
    global current_vrf_gid
    if 'la_vrf_impl' not in line:
        return False
    if 'created successfully' not in line:
        return False

    m = re.match(
        r'.*leaba_sdk Device: (?P<device>([0-9]+)) .*la_vrf_impl\(oid = (?P<vrf_oid>([0-9]+))\) created successfully.*',
        line)
    if m is None:
        return False
    if not is_my_device(int(m['device'])):
        return True
    vrf_oid_to_vrf[m['vrf_oid']] = current_vrf_gid
    current_vrf_gid = None
    vrf = vrf_oid_to_vrf[m['vrf_oid']]
    prefixes = vrf_to_prefixes(vrf)
    if debug:
        print('Created vrf %s' % vrf)
    for p in prefixes:
        annotation = ' // vrf = %s  route = %s (create_vrf)' % (vrf, p['route']) if annotate else ''
        payload = generate_payload(random_payload)
        print('lpm_insert %x %d %x%s' % (p['prefix'], p['prefix_len'], payload, annotation))
    return True


current_ac_port_vrf = None


def match_create_ac_port(line):
    global current_ac_port_vrf
    global vrf_oid_to_vrf
    if 'create_l3_ac_port' not in line:
        return False

    m = re.match(
        r'.*leaba_sdk Device: (?P<device>([0-9]+)) .*la_device_impl.*create_l3_ac_port.*vrf= la_vrf_impl\(oid = (?P<vrf_oid>([0-9]+))\).*',
        line)
    if m is None:
        return False
    if not is_my_device(int(m['device'])):
        return True
    vrf = vrf_oid_to_vrf[m['vrf_oid']]
    if debug:
        print('Create L3 AC port to vrf %s' % vrf)
    current_ac_port_vrf = vrf
    return True


l3_port_to_vrf = {}


def match_ac_port_created(line):
    global current_ac_port_vrf
    global l3_port_to_vrf
    if 'la_l3_ac_port_impl' not in line:
        return False
    if 'created successfully' not in line:
        return False
    m = re.match(
        r'.*leaba_sdk Device: (?P<device>([0-9]+)) .*la_l3_ac_port_impl\(oid = (?P<l3_ac_port_oid>([0-9]+))\) created successfully.*',
        line)
    if m is None:
        return False
    if not is_my_device(int(m['device'])):
        return True
    if debug:
        print('L3 AC port created successfully %s' % m['l3_ac_port_oid'])
    l3_port_to_vrf[m['l3_ac_port_oid']] = current_ac_port_vrf
    current_ac_port_vrf = None
    return True


def match_add_ipv4_subnet(line):
    global l3_port_to_vrf
    if 'add_ipv4_subnet' not in line:
        return False

    m = re.match(
        r'.*leaba_sdk Device: (?P<device>([0-9]+)) .*la_l3_ac_port_impl\(oid = (?P<l3_ac_port_oid>([0-9]+))\)::add_ipv4_subnet\(subnet= prefix=(?P<route>([0-9\.\/]+)).*',
        line)
    if m is None:
        return False
    if not is_my_device(int(m['device'])):
        return True
    vrf = l3_port_to_vrf[m['l3_ac_port_oid']]
    p = v4_route_to_prefix(vrf, m['route'])
    if debug:
        print('AddSubnetV4 vrf %s  route %s' % (vrf, m['route']))
    annotation = ' // vrf = %s  route = %s (add_ipv4_subnet)' % (vrf, m['route']) if annotate else ''
    payload = generate_payload(random_payload)
    print('lpm_insert %x %d %x%s' % (p['prefix'], p['prefix_len'], payload, annotation))
    return True


def match_delete_ipv4_subnet(line):
    global l3_port_to_vrf
    if 'delete_ipv4_subnet' not in line:
        return False
    m = re.match(
        r'.*leaba_sdk Device: (?P<device>([0-9]+)) .*la_l3_ac_port_impl\(oid = (?P<l3_ac_port_oid>([0-9]+))\)::delete_ipv4_subnet\(subnet= prefix=(?P<route>([0-9\.\/]+)).*',
        line)
    if m is None:
        return False
    if not is_my_device(int(m['device'])):
        return True
    vrf = l3_port_to_vrf[m['l3_ac_port_oid']]
    p = v4_route_to_prefix(vrf, m['route'])
    if debug:
        print('DeleteSubnetV4 vrf %s  route %s' % (vrf, m['route']))
    annotation = ' // vrf = %s  route = %s (delete_ipv4_subnet)' % (vrf, m['route']) if annotate else ''
    print('lpm_remove %x %d%s' % (p['prefix'], p['prefix_len'], annotation))
    return True


def match_add_ipv6_subnet(line):
    global l3_port_to_vrf
    if 'add_ipv6_subnet' not in line:
        return False
    m = re.match(
        r'.*leaba_sdk Device: (?P<device>([0-9]+)) .*la_l3_ac_port_impl\(oid = (?P<l3_ac_port_oid>([0-9]+))\)::add_ipv6_subnet\(subnet= prefix=(?P<route>([0-9a-f:\/]+)).*',
        line)
    if m is None:
        return False
    if not is_my_device(int(m['device'])):
        return True
    vrf = l3_port_to_vrf[m['l3_ac_port_oid']]
    p = v6_route_to_prefix(vrf, m['route'])
    if debug:
        print('AddSubnetV6 vrf %s  route %s' % (vrf, m['route']))
    annotation = ' // vrf = %s  route = %s (add_ipv6_subnet)' % (vrf, m['route']) if annotate else ''
    payload = generate_payload(random_payload)
    print('lpm_insert %x %d %x%s' % (p['prefix'], p['prefix_len'], payload, annotation))
    return True


def match_delete_ipv6_subnet(line):
    global l3_port_to_vrf
    if 'delete_ipv6_subnet' not in line:
        return False

    m = re.match(
        r'.*leaba_sdk Device: (?P<device>([0-9]+)) .*la_l3_ac_port_impl\(oid = (?P<l3_ac_port_oid>([0-9]+))\)::delete_ipv6_subnet\(subnet= prefix=(?P<route>([0-9a-f:\/]+)).*',
        line)
    if m is None:
        return False
    if not is_my_device(int(m['device'])):
        return True
    vrf = l3_port_to_vrf[m['l3_ac_port_oid']]
    p = v6_route_to_prefix(vrf, m['route'])
    if debug:
        print('DeleteSubmnetV6 vrf %s  route %s' % (vrf, m['route']))
    annotation = ' // vrf = %s  route = %s (delete_ipv6_subnet)' % (vrf, m['route']) if annotate else ''
    print('lpm_remove %x %d%s' % (p['prefix'], p['prefix_len'], annotation))
    return True


def main():
    global configured_device

    parser = argparse.ArgumentParser()
    parser.add_argument("logfile", type=str, help="API log file")
    parser.add_argument(
        "-d",
        "--device",
        type=int,
        default=None,
        help="device to extract input for (required if log has more than 1 device)")
    parser.add_argument("--include_128", action="store_true", default=None,
                        help="include /128 prefixes (by default skipped because they go to EM")
    args = parser.parse_args()

    random.seed(0)

    fname = args.logfile
    with open(fname, 'r') as f:
        lines = f.readlines()

    configured_device = args.device

    for l in lines:
        matched = False
        if not matched:
            matched = match_create_vrf(l)
        if not matched:
            matched = match_vrf_created(l)
        if not matched:
            matched = match_add_ipv4_route(l)
        if not matched:
            matched = match_add_ipv6_route(l, args.include_128)
        if not matched:
            matched = match_modify_ipv4_route(l)
        if not matched:
            matched = match_modify_ipv6_route(l, args.include_128)
        if not matched:
            matched = match_delete_ipv4_route(l)
        if not matched:
            matched = match_delete_ipv6_route(l, args.include_128)
        if not matched:
            matched = match_create_ac_port(l)
        if not matched:
            matched = match_ac_port_created(l)
        if not matched:
            matched = match_add_ipv4_subnet(l)
        if not matched:
            matched = match_delete_ipv4_subnet(l)
        if not matched:
            matched = match_add_ipv6_subnet(l)
        if not matched:
            matched = match_delete_ipv6_subnet(l)


if __name__ == '__main__':
    main()
