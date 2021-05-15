#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

###
# Use NSIM simulator to test the snake topologies.
###


import argparse
from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *
from binascii import hexlify

sanity_module_directory = '%s/..' % (os.path.dirname(os.path.realpath(__file__)))
sys.path.append(sanity_module_directory)
import sanity
import packets
import device_utils
from sanity_constants import *

P2P_TEST_NAME = 'p2p'
BRIDGING_TEST_NAME = 'bridging'
ROUTING_TEST_NAME = 'routing'
BOARD_P2P_TEST_NAME = 'board-p2p'

available_tests = [P2P_TEST_NAME, BRIDGING_TEST_NAME, ROUTING_TEST_NAME, BOARD_P2P_TEST_NAME]


def main():
    # Parse commnad line arguments
    args = parse_command_line_arguments()

    # Create device
    device_id = 1
    device = device_utils.nsim_device(device_id)

    # Create low-level ports
    is_on_chip_loopbacks = BOARD_P2P_TEST_NAME not in args.configs
    sanity.configure_base_topology(
        device.la_dev,
        args.entry_slice,
        args.entry_ifg,
        args.entry_pif,
        is_on_chip_loopbacks,
        args.loopback_num,
        is_simulator=True)

    # Configure the topologies
    if P2P_TEST_NAME in args.configs:
        sanity.configure_p2p(device.la_dev)
    if BRIDGING_TEST_NAME in args.configs:
        sanity.configure_bridging(device.la_dev, packets.DST_MAC)
    if ROUTING_TEST_NAME in args.configs:
        sanity.configure_routing(device.la_dev, packets.DST_MAC, packets.SRC_MAC, packets.DIP)
    if BOARD_P2P_TEST_NAME in args.configs:
        sanity.configure_board_p2p(device.la_dev)

    # Run the test (if there's one)
    if args.test == P2P_TEST_NAME:
        run_p2p(device, args.entry_slice, args.entry_ifg, args.entry_pif, num_of_replications=1)
    elif args.test == BRIDGING_TEST_NAME:
        run_bridging(device, args.entry_slice, args.entry_ifg, args.entry_pif, num_of_replications=1)
    elif args.test == ROUTING_TEST_NAME:
        run_routing(device, args.entry_slice, args.entry_ifg, args.entry_pif)
    elif args.test == BOARD_P2P_TEST_NAME:
        entry_vid = sanity.snake_board_p2p_topology.BASE_VID1 if args.entry_vid == -1 else args.entry_vid
        run_board_p2p(device, entry_vid, args.entry_slice, args.entry_ifg, args.entry_pif)

    # Clean up
    if P2P_TEST_NAME in args.configs:
        sanity.teardown_p2p()
    if BRIDGING_TEST_NAME in args.configs:
        sanity.teardown_bridging()
    if ROUTING_TEST_NAME in args.configs:
        sanity.teardown_routing()
    if BOARD_P2P_TEST_NAME in args.configs:
        sanity.teardown_board_p2p()

    sanity.teardown_base_topolgy()
    device.teardown()


def parse_command_line_arguments():
    parser = argparse.ArgumentParser(
        description='Run sanity test',
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True)
    parser.add_argument(
        '-c',
        dest='configs',
        required=True,
        help='Toplogies to configure',
        action='append',
        choices=available_tests)
    parser.add_argument(
        '-t',
        dest='test',
        required=False,
        help='Test to simulate',
        choices=available_tests)
    parser.add_argument(
        '-l',
        dest='loopback_num',
        required=False,
        help='Number of on-chip loopbacks. Debug only. Relevant for on-chip loopbacks only',
        type=int,
        default=-1)
    parser.add_argument(
        '-v',
        dest='entry_vid',
        required=False,
        help='VID in first packet. Debug only',
        type=int,
        default=-1)
    parser.add_argument(
        '-s',
        dest='entry_slice',
        required=False,
        help='Entry slice. Debug only. Relevant for on-chip loopbacks only',
        type=int,
        default=0,
        choices=range(NUM_SLICES_PER_DEVICE))
    parser.add_argument(
        '-i',
        dest='entry_ifg',
        required=False,
        help='Entry IFG. Debug only. Relevant for on-chip loopbacks only',
        type=int,
        default=0,
        choices=range(NUM_IFGS_PER_SLICE))
    parser.add_argument(
        '-p',
        dest='entry_pif',
        required=False,
        help='Entry PIF. Debug only. Relevant for on-chip loopbacks only',
        type=int,
        default=0,
        choices=range(NUM_PIF_PER_IFG))

    args = parser.parse_args()

    if args.test is not None and args.test not in args.configs:
        print('Error: missing configuration of %s' % args.test, file=sys.stderr)
        sys.exit(2)

    configs = set(args.configs)

    if BOARD_P2P_TEST_NAME in configs and len(configs) > 1:
        print('Error: board topology is not consistent with other topologies', file=sys.stderr)
        sys.exit(2)

    return args

# Base snake functionality


def run_snake(device, base_vid1, entry_slice, entry_ifg, entry_pif, is_board=False, is_l3=False, base_ttl=0, num_of_replications=1):
    input_packet = packets.get_input_packet(base_vid1)
    device.inject(input_packet, entry_slice, entry_ifg, entry_pif, num_of_replications)
    device.run()
    (output_packet, output_slice, output_ifg, output_pif) = device.get_output_packet()

    expected_packet = get_expected_packet(base_vid1, is_board, is_l3, base_ttl)

    if output_slice != entry_slice:
        print('expected slice: %d' % entry_slice)
        print('output   slice: %d' % output_slice)
        return False

    if output_ifg != entry_ifg:
        print('expected ifg: %d' % entry_ifg)
        print('output   ifg: %d' % output_ifg)
        return False

    if output_pif != entry_pif:
        print('expected pif: %d' % entry_pif)
        print('output   pif: %d' % output_pif)
        return False

    if output_packet != expected_packet:
        print('expected packet: "%s"' % expected_packet)
        print('output   packet: "%s"' % output_packet)
        return False

    print('output   packet: "%s"' % output_packet)

    return True


def get_expected_packet(base_vid1, is_board, is_l3, base_ttl):
    if is_board:
        expected_vid1 = sanity.snake_board_p2p_topology.BASE_VID1 + \
            ((base_vid1 - sanity.snake_board_p2p_topology.BASE_VID1 + 1) % sanity.base_topology.mac_ports_num)
        expected_packet = packets.get_expected_packet(expected_vid1)
    else:
        if is_l3:
            expected_vid1 = base_vid1 + (sanity.base_topology.loopback_num + 1) * 2
            expected_ttl = base_ttl - (sanity.base_topology.loopback_num + 1)
            expected_packet = packets.get_expected_packet(expected_vid1, expected_ttl)
        else:
            expected_vid1 = base_vid1
            expected_packet = packets.get_expected_packet(expected_vid1)

    expected_packet_str = hexlify(bytes(expected_packet)).decode('ascii')

    return expected_packet_str


def run_p2p(device, entry_slice, entry_ifg, entry_pif, num_of_replications):
    is_success = run_snake(device, sanity.snake_p2p_topology.BASE_VID1,
                           entry_slice, entry_ifg, entry_pif, is_board=False, is_l3=False, base_ttl=0,
                           num_of_replications=num_of_replications)
    print('Snake P2P %s' % ('PASS' if is_success else 'FAIL'))


def run_bridging(device, entry_slice, entry_ifg, entry_pif, num_of_replications):
    is_success = run_snake(device, sanity.snake_bridging_topology.BASE_VID1,
                           entry_slice, entry_ifg, entry_pif, is_board=False, is_l3=False, base_ttl=0,
                           num_of_replications=num_of_replications)
    print('Snake bridging %s' % ('PASS' if is_success else 'FAIL'))


def run_routing(device, entry_slice, entry_ifg, entry_pif):
    is_success = run_snake(device,
                           sanity.snake_routing_topology.BASE_VID1,
                           entry_slice,
                           entry_ifg,
                           entry_pif,
                           is_l3=True,
                           base_ttl=packets.TTL)
    print('Snake routing %s' % ('PASS' if is_success else 'FAIL'))


def run_board_p2p(device, entry_vid, entry_slice, entry_ifg, entry_pif):
    is_success = run_snake(device, entry_vid, entry_slice, entry_ifg, entry_pif, is_board=True)
    print('Snake board-P2P %s' % ('PASS' if is_success else 'FAIL'))


if __name__ == '__main__':
    main()
