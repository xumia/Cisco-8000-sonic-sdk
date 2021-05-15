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

from ports_base import *
from spirent_connector import *
import decor

NUM_STREAMS = 1
GEN_TYPE = "FIXED"
RATE_PERCENTAGE = 2
TRAFFIC_DELAY = 1
DWELL_UP_TIME = 30


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_to_mib_counter(ports_base):
    loop_mode = 'none'
    p2p_ext = True

    # This is temp function
    # input: packet size .
    # output: the index for mac info filed dictionary - to where packet to be mapped
    def index_for_mac_info_field(self, packet_size):
        temp_array = [65, 128, 256, 512, 1024, 1519, 2501, 9001]
        for index, packet in enumerate(temp_array):
            if packet_size < packet:
                return index

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mib_counter(self):
        packet_sizes = [127, 128, 255, 256, 511, 512, 1023, 1024, 1518, 1519, 2500, 2501, 9000]
        mac_info_field = [{'tx': 'tx_64b_frames', 'rx': 'rx_64b_frames'},
                          {'tx': 'tx_65to127b_frames', 'rx': 'rx_65to127b_frames'},
                          {'tx': 'tx_128to255b_frames', 'rx': 'rx_128to255b_frames'},
                          {'tx': 'tx_256to511b_frames', 'rx': 'rx_256to511b_frames'},
                          {'tx': 'tx_512to1023b_frames', 'rx': 'rx_512to1023b_frames'},
                          {'tx': 'tx_1024to1518b_frames', 'rx': 'rx_1024to1518b_frames'},
                          {'tx': 'tx_1519to2500b_frames', 'rx': 'rx_1519to2500b_frames'},
                          {'tx': 'tx_2501to9000b_frames', 'rx': 'rx_2501to9000b_frames'}]

        self.fill_args_from_env_vars('traffic_gen_mix.json')
        self.snake.run_snake()
        self.open_spirent()
        self.snake.mph.wait_mac_ports_up(timeout=DWELL_UP_TIME)
        link_status = self.snake.mph.print_mac_up()
        self.assertTrue(link_status, 'one or more port links are down')

        for packet in packet_sizes:
            self.spirent.add_data_streams(fixed_frame_length=packet)
            stats = self.spirent.run_and_get_rx_tx(TRAFFIC_DELAY)
            tx_spirent_pck = stats['tx_packets']
            rx_spirent_pck = stats['rx_packets']
            self.assertEqual(
                tx_spirent_pck,
                rx_spirent_pck,
                'Packet_size={}: the tx spirent counter={} != rx spirent counter={}'.format(packet,
                                                                                            tx_spirent_pck,
                                                                                            rx_spirent_pck))
            map_info_field = self.index_for_mac_info_field(packet)
            for index in range(len(self.snake.mph.mac_ports)):
                mac_info = self.snake.mph.get_mac_stats(index)
                print(
                    'Link [{index}] name {name}, FC {fc_mode}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}), '
                    'Rx {rx_frames} {rx_bytes}, Tx {tx_frames} {tx_bytes}, Tx CRC {tx_crc_err}, Tx Underrun {tx_underrun_err}, '
                    'Uncorrectable {uncorrectable}, Correctable {correctable}'.format(
                        **mac_info))
                for info_index, info_field in enumerate(mac_info_field):
                    if map_info_field == info_index:
                        self.assertEqual(
                            mac_info[info_field['tx']],
                            rx_spirent_pck,
                            'In Packet size={} the tx_mib counter={} != rx spirent counter={} of (Slice {slice} / IFG {ifg} / SerDes {serdes}).'.format(
                                packet,
                                mac_info[info_field['tx']],
                                rx_spirent_pck,
                                **mac_info))
                        self.assertEqual(
                            mac_info[info_field['rx']],
                            tx_spirent_pck,
                            'In Packet size={} the rx_mib counter={} != tx spirent counter={} of (Slice {slice} / IFG {ifg} / SerDes {serdes}).'.format(
                                packet,
                                mac_info[info_field['rx']],
                                tx_spirent_pck,
                                **mac_info))
                    else:
                        self.assertEqual(
                            mac_info[info_field['tx']],
                            0,
                            'In Packet size={}  the tx mib_counter {} should be {} in port (Slice {slice} / IFG {ifg} / SerDes {serdes}).'.format(
                                packet,
                                info_field['tx'],
                                0,
                                **mac_info))
                        self.assertEqual(
                            mac_info[info_field['rx']],
                            0,
                            'In Packet size={}  the rx mib_counter {} should be {} in port (Slice {slice} / IFG {ifg} / SerDes {serdes}).'.format(
                                packet,
                                info_field['rx'],
                                0,
                                **mac_info))
            self.spirent.clear_stream()

    # methodology test_crc:
    # change tx_crc_en register of port2 to 0 - the packets will send to port3 with crc error
    # sending packets with traffic generator
    # checking rx_crc_err counter of port3 equal to number of packets sent by traffic generator
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_crc(self):
        self.fill_args_from_env_vars('traffic_gen_mix.json')

        self.snake.run_snake()
        self.open_spirent()
        self.snake.mph.wait_mac_ports_up(timeout=DWELL_UP_TIME)
        link_status = self.snake.mph.print_mac_up()
        self.assertTrue(link_status, 'one or more port links are down')

        is_pacific = self.snake.mph.ll_device.is_pacific()

        # disable crc append of second port
        second_port = self.snake.mph.mac_ports[1]
        second_port_slice = second_port.get_slice()
        second_port_ifg = second_port.get_ifg()
        second_port_serdes = second_port.get_first_serdes_id()
        second_port_serdes_count = second_port.get_num_of_serdes()
        mp_i = int(second_port_serdes / 8)
        base_serdes_of_port = (second_port_serdes % 8)
        for serdes in range(second_port_serdes_count):
            if is_pacific and second_port_serdes > 15:
                reg_tx_mac_cfg0 = self.snake.debug_device.read_register(
                    self.snake.debug_device.device_tree.slice[second_port_slice].ifg[second_port_ifg].mac_pool2[
                        mp_i].tx_mac_cfg0[base_serdes_of_port + serdes])
                reg_tx_mac_cfg0.tx_crc_en = 0
                self.snake.debug_device.write_register(
                    self.snake.debug_device.device_tree.slice[second_port_slice].ifg[second_port_ifg].mac_pool2[mp_i].tx_mac_cfg0[
                        base_serdes_of_port + serdes], reg_tx_mac_cfg0)
            else:
                reg_tx_mac_cfg0 = self.snake.debug_device.read_register(
                    self.snake.debug_device.device_tree.slice[second_port_slice].ifg[second_port_ifg].mac_pool8[mp_i].tx_mac_cfg0[base_serdes_of_port + serdes])
                reg_tx_mac_cfg0.tx_crc_en = 0
                self.snake.debug_device.write_register(
                    self.snake.debug_device.device_tree.slice[second_port_slice].ifg[second_port_ifg].mac_pool8[mp_i].tx_mac_cfg0[
                        base_serdes_of_port + serdes], reg_tx_mac_cfg0)

        self.spirent.add_data_streams()
        stats = self.spirent.run_and_get_rx_tx(TRAFFIC_DELAY)
        tx_spirent_pck = stats['tx_packets']

        # checking crc counter of third port
        mac_info = self.snake.mph.get_mac_stats(2)  # mac_stats of third port
        print(
            'Link [{index}] name {name}, FC {fc_mode}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}), '
            'Rx {rx_frames} {rx_bytes}, Tx {tx_frames} {tx_bytes}, Rx CRC {rx_crc_err}, Tx Underrun {tx_underrun_err}, '
            'Uncorrectable {uncorrectable}, Correctable {correctable}'.format(
                **mac_info))
        self.assertEqual(
            mac_info['rx_crc_err'],
            tx_spirent_pck,
            'The tx spirent counter={} != rx crc error counter={}'.format(tx_spirent_pck, mac_info['rx_crc_err']))


if __name__ == '__main__':
    unittest.main()
