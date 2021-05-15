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

import xena_defines
import time
import sanity
import network_objects
import os


class xena_connector():
    user = "xena_connector"

    # ip address of Xena Board e.g. '10.56.19.10'
    # Xena port address e.g. '4/0'
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        pkt_gen = xena_defines.xena_pkt_generator(ip, self.user)
        self.xena_port = pkt_gen.AddPort(port)
        self.xena_port.ClearStatistic()
        self.xena_port.EnableCapture(True)

    # num_streams = number of Xena flows
    # gen_type = "FIXED" / "INCREMENTING" / "BUTTERFLY" / "RANDOM" / "MIX" (with MIX need to also use SetPacketSizeMix)
    # min_packet_size = minimum packet size to be sent (depends on the gen_type)
    # max_packet_size = maximum packet size to be sent (depends on the gen_type)
    # rate_percentage = percentage of traffic to be sent from Xena (between 1-100)
    # packet = Raw data packet to be sent - must include at least the Headers, Xena will pad the rest
    def add_data_streams(self,
                         num_streams,
                         gen_type,
                         min_packet_size,
                         max_packet_size,
                         rate_percentage,
                         packet):
        self.num_streams = num_streams
        self.gen_type = gen_type
        self.min_packet_size = min_packet_size
        self.max_packet_size = max_packet_size
        self.rate_percentage = rate_percentage
        self.packet = packet
        for i in range(self.num_streams):
            stream = self.xena_port.AddStream(i)
            stream.SetPacketSize(self.gen_type, self.min_packet_size, self.max_packet_size)
            stream.AddHeader("RAW", self.packet)
            stream.SetRatePercentage(self.rate_percentage // self.num_streams)
            stream.EnableTraffic()

    def run_and_get_rx_tx(self, dwell_time):
        self.xena_port.ClearStatistic()
        self.xena_port.StartTraffic()
        time.sleep(dwell_time)
        self.xena_port.StopTraffic()
        time.sleep(1)
        res = self.xena_port.GetStatistic()
        return res
