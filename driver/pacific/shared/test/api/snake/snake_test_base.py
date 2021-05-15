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

import time
from leaba import sdk

import snake_standalone
from snake_base import *

SLICE = 0
IFG = 0

ENTRY_VLAN = 0x100

# Traffic dwell time in seconds
TRAFFIC_DWELL_TIME = 5

# Traffic stop time in seconds
TRAFFIC_STOP_TIME = 5

try:
    import decor
    import sim_utils
    import network_objects
    from packet_test_defs import *
    PUNT_INJECT_PORT_MAC_ADDR = network_objects.mac_addr('12:34:56:78:9a:bc')

    sim_utils_exists = True
    is_hw_device = decor.is_hw_device()

except ModuleNotFoundError:
    sim_utils_exists = False
    is_hw_device = True

TEST_PACKET_NUM = 100


class snake_test_base(snake_base):
    @staticmethod
    def mac_str_to_num(mac_str):
        addr_bytes = mac_str.split(':')
        assert(len(addr_bytes) == 6)  # 6 bytes
        for b in addr_bytes:
            assert(len(b) == 2)  # 2 digits for each byte

        hex_str = mac_str.replace(':', '')
        n = int(hex_str, 16)

        return n

    @staticmethod
    def mac_num_to_str(mac_num):
        hex_str = format(mac_num, 'x')
        hex_str = ':'.join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2))
        return hex_str

    def create_packets(self, slice, ifg, flows=[]):
        if not flows:
            flow = {
                'entry_slice': 0,
                'entry_ifg': 0,
                'src_mac': 'de:ad:de:ad:de:ad',
                'dst_mac': 'ca:fe:ca:fe:ca:fe',
                'vlan_id': 0x100,
                'packet_size': 348,
                'protocol': 'none'}
            self.inject_packet = self.create_l2_packet(flow, slice, ifg)
        else:
            for flow in flows:
                if 'entry_slice' in flow:
                    slice = flow['entry_slice']
                if 'entry_ifg' in flow:
                    ifg = flow['entry_ifg']

                protocol = flow['protocol']
                if protocol == 'ipv6':
                    self.inject_packet = self.create_ipv6_packet(flow, slice, ifg)
                elif protocol == 'ipv4':
                    self.inject_packet = self.create_ipv4_packet(flow, slice, ifg)
                else:
                    self.inject_packet = self.create_l2_packet(flow, slice, ifg)
                flow['packet'] = self.inject_packet

    def create_inject_encap_header(self, flow, slice, ifg):
        inject_encap = Ether(dst=PUNT_INJECT_PORT_MAC_ADDR.addr_str, src=flow['src_mac'], type=TPID_Dot1Q) / \
            Dot1Q(prio=0, id=0, vlan=flow['vlan_id'], type=TPID_Inject) / \
            InjectUpStd(type=NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS, ifg_id=self.get_inject_actual_ifg(slice, ifg),
                        pif_id=0)
        return inject_encap

    def create_ipv6_packet(self, flow, slice, ifg):
        if sim_utils_exists:
            inject_encap = self.create_inject_encap_header(flow, slice, ifg)
            if flow['entry_slice'] == 2 and flow['entry_ifg'] == 0:
                dst_mac = self.mac_num_to_str(self.mac_str_to_num(flow['dst_mac']) + self.snake.dst_id_offset)
                vlan_id = flow['vlan_id'] + self.snake.dst_id_offset
            else:
                dst_mac = flow['dst_mac']
                vlan_id = flow['vlan_id']

            inject_data = Ether(dst=dst_mac, src=flow['src_mac'], type=TPID_Dot1Q) / \
                Dot1Q(prio=0, id=0, vlan=vlan_id) / IPv6(src=flow['src_ip'], dst=flow['dst_ip']) / TCP()
            inject_full = inject_encap / inject_data
        else:
            packet_str = '12 34 56 78 9a bc de ad de ad de ad 81 00 01 00 71 03 07 00 00 00 c8 00 00 00 00 00 00 00 00 00 00 00 00 ca fe ca fe ca fe de ad de ad de ad 81 00 01 00 86 dd 60 00 00 00 00 14 06 40 00 02 00 02 00 02 00 02 11 11 11 11 11 11 11 11 11 11 0d b8 0a 0b 12 f0 77 77 77 77 88 88 88 88 00 14 00 50 00 00 00 00 00 00 00 00 50 02 20 00 00 00 00 00 b4 9d 06 14 9d 62 8c 3a 07 54 db 20 54 8e bf 87 1f fe 22 57 4f 2b 00 0e 8e d4 cf 23 b0 c0 a5 6d 10 72 5d 80 6c 6c 83 b4 5e ac cf 57 62 f9 85 bb 4c e1 e7 d2 1b a9 75 7f c9 dc 33 24 5f aa f2 44 b4 b5 0e f4 34 9f c4 c3 57 39 e7 e2 41 5e f6 53 f7 ac c5 94 f6 1d 82 c2 0e 13 e5 2c 7a 18 76 d7 10 44 39 e5 2d ab 38 0d 58 14 79 8d bb 0b 0d 23 13 5c'
            packet_array = packet_str.split()
            inject_full = []
            for packet_word in packet_array:
                inject_full.append(int(packet_word, 16))
        return bytes(inject_full)

    def create_ipv4_packet(self, flow, slice, ifg):
        if sim_utils_exists:
            inject_encap = self.create_inject_encap_header(flow, slice, ifg)
            if flow['entry_slice'] == 2 and flow['entry_ifg'] == 0:
                dst_mac = self.mac_num_to_str(self.mac_str_to_num(flow['dst_mac']) + self.snake.dst_id_offset)
                vlan_id = flow['vlan_id'] + self.snake.dst_id_offset
            else:
                dst_mac = flow['dst_mac']
                vlan_id = flow['vlan_id']
            inject_data = Ether(dst=dst_mac, src=flow['src_mac'], type=TPID_Dot1Q) / \
                Dot1Q(prio=0, id=0, vlan=vlan_id) / IP(dst=flow['dst_ip']) / TCP()
            inject_full = inject_encap / inject_data
        else:
            packet_str = '12 34 56 78 9a bc de ad de ad de ad 81 00 01 00 71 03 07 00 00 00 c8 00 00 00 00 00 00 00 00 00 00 00 00 ca fe ca fe ca fe de ad de ad de ad 81 00 01 00 08 00 45 00 00 28 00 01 00 00 40 06 d8 6f ac 19 2b 9e c0 a8 0a 00 00 14 00 50 00 00 00 00 00 00 00 00 50 02 20 00 ed 1e 00 00 38 3a e0 c5 47 64 d7 fb d8 24 25 01 9b ce 5c 34 21 8f 18 a0 51 a9 0c ae 19 c8 fe 7d 88 33 5c 6d cb c0 84 48 66 c5 5a 1d 0c 22 ca 52 90 6e fd 07 eb e2 6d 8d 70 a2 5e bf 80 ac c4 04 54 93 cf 5b fd 9d bd 1a 20 e9 06 35 c5 45 cc a7 3c e6 ee 26 e7 b7 64 89 f8 ba da df 2f a8 cc 27 dd 6e 68 71 38 5d fe f4 1f 01 bd 3c 8f ad c0 2a 5d a8 cf fc bb 18 b4 03 46 a5 66 51 cb f9 2f 15 18 c1 d2 78 65 a3 47 26 fd 0d'
            packet_array = packet_str.split()
            inject_full = []
            for packet_word in packet_array:
                inject_full.append(int(packet_word, 16))
        return bytes(inject_full)

    def create_l2_packet(self, flow, slice, ifg):
        if sim_utils_exists:
            inject_encap = self.create_inject_encap_header(flow, slice, ifg)
            if flow['entry_slice'] == 2 and flow['entry_ifg'] == 0:
                dst_mac = self.mac_num_to_str(self.mac_str_to_num(flow['dst_mac']) + self.snake.dst_id_offset)
                vlan_id = flow['vlan_id'] + self.snake.dst_id_offset
            else:
                dst_mac = flow['dst_mac']
                vlan_id = flow['vlan_id']
            inject_data = Ether(dst=dst_mac, src=flow['src_mac'], type=TPID_Dot1Q) / \
                Dot1Q(prio=0, id=0, vlan=vlan_id) / IP() / TCP()
            inject_full = inject_encap / inject_data
        else:
            packet_str = '12 34 56 78 9a bc de ad de ad de ad 81 00 01 00 71 03 07 00 00 00 c8 00 00 00 00 00 00 00 00 00 00 00 00 ca fe ca fe ca fe de ad de ad de ad 81 00 01 00 08 00 45 00 00 28 00 01 00 00 40 06 7c cd 7f 00 00 01 7f 00 00 01 00 14 00 50 00 00 00 00 00 00 00 00 50 02 20 00 91 7c 00 00 32 8e ed d8 24 6b c8 26 37 6e 76 2c f1 1f 70 53 23 c9 95 08 60 01 fb 6a b5 1e 2e d2 25 99 ba ea 40 31 b9 1e 2b ca 17 6d f9 8c 8a b2 5f 24 8a c7 24 11 de 70 cb e4 58 8e 97 76 a2 01 9d dd 87 57 61 56 7e 52 b7 7d 08 1d ce e6 a6 c8 d0 96 ee 0d 1f d0 86 98 3a 4c 73 d8 7a d6 0b 44 fb d1 45 50 5a 2c 2c 3b 50 b6 05 c4 70 d4 09 22 57 c2 44 a9 fe 8c a3 b7 5a 47 19 94 51 3f d6 d3 89 06 1d d5 2d 1f 95 b3 f9 51'
            packet_array = packet_str.split()
            inject_full = []
            for packet_word in packet_array:
                inject_full.append(int(packet_word, 16))
        return bytes(inject_full)

    def base_loop_test_setup(self, slice=SLICE, ifg=IFG, flows=[]):
        self.snake.run_snake()
        self.create_packets(slice, ifg, flows)
        self.open_sockets()
        # Clean all pending notifications
        crit, norm = self.snake.mph.read_notifications(1)

        # If test requires HBM but there is no HBM, skip the test.
        self.has_hbm = self.snake.device.get_device_information().extension != 0
        if self.snake.args.hbm == snake_standalone.HBM_MODE_ENABLE and not self.has_hbm:
            self.skipTest("No HBM")

    def base_loop_test_run(
            self,
            test_packet_size,
            slice=SLICE,
            ifg=IFG,
            stop_after_dwell=True,
            duration_seconds=TRAFFIC_DWELL_TIME,
            inject_packets_count=TEST_PACKET_NUM,
            rate_check=False, flows=[]):

        if not flows:
            # Get inject sys port to inject to
            sp = self.snake.sys_ports[0]
            # Send traffic to the first port in the loop
            self.snake.send_traffic_to_port(
                sp.get_slice(),
                sp.get_ifg(),
                base_serdes=sp.get_base_serdes,
                base_pif=sp.get_base_pif(),
                packet_count=inject_packets_count,
                packet_size=test_packet_size)
        else:
            for flow in flows:
                self.inject(flow['packet'], flow['packet_size'], flow['entry_slice'], inject_packets_count)
        if (rate_check):
            for i in range(duration_seconds):
                self.snake.mph.print_mac_rate()  # internally, sleeps for 1 second
        else:
            # Wait for the traffic to flow
            time.sleep(duration_seconds)

            if stop_after_dwell:
                self.snake.mph.network_mac_ports[0].stop()
                self.snake.mph.network_mac_ports[0].set_loopback_mode(sdk.la_mac_port.loopback_mode_e_NONE)

                time.sleep(TRAFFIC_STOP_TIME)

                # Check MAC stats
                self.check_mac_stats(inject_packets_count, test_packet_size)
            else:
                # Can't check, just print
                time.sleep(TRAFFIC_STOP_TIME)
                self.snake.mph.print_mac_stats()

    def base_loop_test(
            self,
            test_packet_size,
            slice=SLICE,
            ifg=IFG,
            stop_after_dwell=True,
            duration_seconds=TRAFFIC_DWELL_TIME,
            inject_packets_count=TEST_PACKET_NUM,
            rate_check=False, flows=[]):

        self.base_loop_test_setup(slice, ifg, flows)
        self.base_loop_test_run(
            test_packet_size,
            slice,
            ifg,
            stop_after_dwell,
            duration_seconds,
            inject_packets_count,
            rate_check,
            flows)
