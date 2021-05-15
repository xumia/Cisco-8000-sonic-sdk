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

import decor
from ports_base import *
import decor

TRAFFIC_DELAY = 1
PKT_SIZE = 370
ITERATION = 1


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_fabric_mac_port(ports_base):
    loop_mode = 'none'
    p2p_ext = True

    @unittest.skipIf(decor.is_gibraltar(), "Test is not stable in GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_fabric_mac_port(self):
        self.fill_args_from_env_vars('line_card_mix.json', self.DEVICE_MODE.LINECARD_2x50)
        self.snake.run_snake()
        self.open_spirent()
        self.snake.mph.wait_mac_ports_up(timeout=DWELL_UP_TIME)
        link_status = self.snake.mph.print_mac_up()
        self.assertTrue(link_status, 'one or more port links are down')
        self.snake.mph.clear_mac_stats()

        self.spirent.add_data_streams(fixed_frame_length=PKT_SIZE)
        stats = self.spirent.run_and_get_rx_tx(TRAFFIC_DELAY)
        tx_spirent_pck = stats['tx_packets']
        rx_spirent_pck = stats['rx_packets']
        self.assertEqual(
            tx_spirent_pck,
            rx_spirent_pck,
            'The tx spirent counter={} != rx spirent counter={}'.format(tx_spirent_pck, rx_spirent_pck))

        self.outfile = open("{}/fec_counters_{}.csv".format(self.reports_dir, self.id()), "w+", 1)
        self.outfile.write(
            "Iteration,Link,name,Slice,IFG,SerDes,BER,FLR,FLR_R,cw0,cw1,cw2,cw3,cw4,cw5,cw6,cw7,cw8,cw9,cw10,cw11,cw12,cw13,cw14,cw15,Uncorrectable,Symbol bursts\n")

        fec_counters = self.snake.mph.get_mac_fec_counters(clear_on_read=False)
        self.save_mac_fec_counters(fec_counters, ITERATION)
        self.check_mac_fec(fec_counters)
        self.outfile.close()

        # Checking Fabric Ports
        sum_fabric_tx_frames = 0
        sum_fabric_rx_frames = 0
        for fp in self.snake.mph.fabric_mac_ports:
            index_in_mac_port = self.snake.mph.get_mac_port_idx(fp.get_slice(), fp.get_ifg(), fp.get_first_serdes_id())
            mac_info = self.snake.mph.get_mac_stats(index_in_mac_port)
            print(
                'Link [{index}] name {name}, FC {fc_mode}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}), '
                'Rx {rx_frames} {rx_bytes}, Tx {tx_frames} {tx_bytes}, Tx CRC {tx_crc_err}, Tx Underrun {tx_underrun_err}, '
                'Uncorrectable {uncorrectable}, Correctable {correctable}'.format(**mac_info))
            sum_fabric_tx_frames += mac_info['tx_256to511b_frames']
            sum_fabric_rx_frames += mac_info['rx_256to511b_frames']

        self.assertEqual(
            sum_fabric_tx_frames,
            tx_spirent_pck,
            'The tx frames of all fabric ports ={} != tx spirent counter={}.'.format(
                sum_fabric_tx_frames,
                tx_spirent_pck))

        self.assertEqual(
            sum_fabric_rx_frames,
            tx_spirent_pck,
            'The rx frames of all fabric ports ={} != tx spirent counter={} .'.format(
                sum_fabric_rx_frames,
                tx_spirent_pck))

    @unittest.skipIf(not decor.is_gibraltar(), "Test is not  enabled on Pacific")
    def test_200g_fabric(self):
        self.fill_args_from_env_vars('line_card_mix_200g.json', self.DEVICE_MODE.LINECARD_4x50)
        self.snake.run_snake()
        self.snake.mph.wait_mac_ports_up(timeout=DWELL_UP_TIME)
        link_status = self.snake.mph.print_mac_up()
        self.assertTrue(link_status, 'one or more port links are down')


if __name__ == '__main__':
    unittest.main()
