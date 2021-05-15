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

from cem_insertions_base import *
import unittest


class test_cem_insertions(cem_insertions_base):

    def main(self):
        total_success_count = 0
        begin = time.time()
        print("starting populating")
        expected_key_payload_pairs = []
        for i in range(self.insertions_num):
            key = self.create_key(i)
            payload = etu.create_em_payload(i, PAYLOAD_WIDTH)
            try:
                self.insert(key=key, payload=payload)
                self.device.release_device_lock()
                total_success_count += 1
                expected_key_payload_pairs.append((key, payload))
            except BaseException:
                self.device.release_device_lock()
                raise
            if (total_success_count % 10000) == 0:
                length = time.time() - begin
                print("10000 inserted, total: {} in {}\t normailized: {}".format(i, length, length - 2.6))
                begin = time.time()
        if not self.all_entires_should_be_inserted:
            expected_key_payload_pairs = expected_key_payload_pairs[:total_success_count]
        if USE_LOOKUP:
            for (key, expected_payload) in expected_key_payload_pairs:
                self.assert_key_payload_in_cem(key, expected_payload)
        self.dump()
        if VERBOSE_DEBUG:
            self.assert_report_corresponds_to_insertions(expected_key_payload_pairs)

    @unittest.skipIf(not decor.is_hw_device(), "ARC can not be simulated")
    def test_seq_double(self):
        self.insertions_num = 10000
        self.seq_double()

    @unittest.skipIf(not decor.is_hw_device(), "ARC can not be simulated")
    def test_seq_single(self):
        self.insertions_num = 10000
        self.seq_single()

    @unittest.skipIf(not decor.is_hw_device(), "ARC can not be simulated")
    def test_rand_double(self):
        self.insertions_num = 10000
        self.rand_double()

    @unittest.skipIf(not decor.is_hw_device(), "ARC can not be simulated")
    def test_rand_single(self):
        self.insertions_num = 10000
        self.rand_single()

    @unittest.skipIf(not decor.is_hw_device(), "ARC can not be simulated")
    def test_oor(self):
        if self.ll_device.is_pacific():
            self.insertions_num = 262656
        else:
            self.insertions_num = 4 * 262656
        self.oor()

    @unittest.skipIf(not decor.is_hw_device(), "ARC can not be simulated")
    def test_setup_teardown(self):
        self.setup_teardown()


if __name__ == '__main__':
    unittest.main()
