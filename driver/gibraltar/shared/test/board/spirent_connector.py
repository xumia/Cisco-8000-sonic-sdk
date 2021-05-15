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

from types_and_enums import *
import spirent_defines
import time
import sanity
import network_objects
import os
from scapy.all import *
from binascii import hexlify, unhexlify
import pytest

DEFAULT_PKT = Ether(src="00:01:02:03:FF:FF", dst="10:01:02:03:04:05", type=0x8100) / \
    Dot1Q(vlan=256) / \
    IP(src="30.1.1.1", dst="10.1.1.1", ttl=255)


class spirent_connector():
    user = "Ports-Sanity"

    # ip address of Spirent Board e.g. '10.56.19.10'
    # Spirent port address e.g. '4/0'
    def __init__(self, ip, session_ip, port, board_str, an=True):
        pytest.WB_MODE = WarmBootMode.NONE
        pytest.IS_SIMULATOR = False
        self.ip = ip
        self.port = port
        self.session_ip = session_ip
        self.session_str = board_str
        self.pkt_gen = spirent_defines.SpirentPktGenerator(ip, session_ip, self.session_str, self.user)
        self.spirent_port = self.pkt_gen.add_port(port, AN=an)
        self.spirent_port.clear_statistic()
        self.spirent_port.reset()

    def teardown(self):
        self.spirent_port.reset()
        self.pkt_gen.__del__()

    def scapy_layer_name_to_spirent(self, name):
        return {
            'Ethernet': 'ethernet:EthernetII',
            'IP': 'ipv4:IPv4',
            '802.1Q': 'ethernet:EthernetII.Vlans.Vlan',
            'MPLS': 'mpls:Mpls',
            'IPv6': 'ipv6:IPv6',
            'TCP': 'tcp:Tcp',
            'UDP': 'udp:Udp',
        }.get(name, 'RAW')

    def scapy_packet_to_headers(self, pkt):
        counter = 0
        while True:
            layer = pkt.getlayer(counter)
            if (layer is None):
                break
            counter += 1

        headers = []
        last_len = 0
        for i in range(counter - 1, -1, -1):
            layer = pkt.getlayer(i)
            pay = hexlify(bytes(layer)).decode('ascii')

            fields = layer.fields
            if layer.name == '802.1Q':
                fields['type'] = layer.type
            headers.insert(0, (self.scapy_layer_name_to_spirent(layer.name), fields, int((len(pay) - last_len) / 2)))

            last_len += (len(pay) - last_len)

        return headers

    # num_streams = number of Spirent flows
    # gen_type = "FIXED" / "INCR" / "DECR" / "RANDOM" / "IMIX"
    # min_packet_size = minimum packet size to be sent (depends on the gen_type)
    # max_packet_size = maximum packet size to be sent (depends on the gen_type)
    # rate_percentage = percentage of traffic to be sent from Xena (between 1-100)
    # packet = Scapy packet to be sent - look for DEFAULT_PKT for an example
    def add_data_streams(self,
                         num_streams=1,
                         gen_type="FIXED",
                         min_packet_size=500,
                         max_packet_size=500,
                         rate_percentage=2,
                         pkt=DEFAULT_PKT,
                         fixed_frame_length=370):
        self.num_streams = num_streams
        self.gen_type = gen_type
        self.min_packet_size = min_packet_size
        self.max_packet_size = max_packet_size
        self.rate_percentage = rate_percentage
        self.pkt = pkt
        frame_length = fixed_frame_length

        headers = self.scapy_packet_to_headers(pkt)

        for i in range(self.num_streams):
            spirent_hdrs_name_list = []
            for hdr_type, hdr_data, hdr_len in headers:
                temp_hdr = hdr_type.replace(".", ":")
                spirent_hdrs_name_list.append(temp_hdr.split(":")[-1])
            stream = self.spirent_port.add_stream(i, self.gen_type, self.min_packet_size,
                                                  self.max_packet_size, spirent_hdrs_name_list, frame_length)
            for hdr_type, hdr_data, hdr_len in headers:
                stream.add_header(hdr_type, hdr_data, hdr_len)
            stream.set_rate_percentage(self.rate_percentage // self.num_streams)
            stream.stc.api.config(stream.hStreamBlock, **stream.kwargs)

    def clear_stream(self):
        self.spirent_port.reset()

    def run_traffic(self):
        self.spirent_port.clear_statistic()
        self.spirent_port.start_traffic()

    def stop_traffic(self):
        self.spirent_port.stop_traffic()

    def run_and_get_rx_tx(self, dwell_time=1):
        self.run_traffic()
        time.sleep(dwell_time)
        self.stop_traffic()
        time.sleep(1)
        res = self.spirent_port.get_statistic()
        return res
