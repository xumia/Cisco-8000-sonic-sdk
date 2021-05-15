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


DEBUG_TEST = True
VERBOSE_DEBUG = True
USE_LOOKUP = False
ASSERT_LOCATIONS_SIZE_IS_VALID = False
#from packet_test_utils import *
from leaba import sdk
import hw_tablescli
import lldcli
import test_hldcli as sdk_debug
import unittest
#import topology as T
import random
import time
import time
from csv import DictReader

#from scapy.all import *
from enum import Enum
import random
from os import path
can_exec_test = True
try:
    from leaba.debug_tools import debug_utils
    import sim_utils
    import decor
except BaseException:
    can_exec_test = False
if not can_exec_test:
    import sys
    sys.exit()


import em_test_utils as etu


PAYLOAD_WIDTH = 64


class KeyGenType(Enum):
    SEQ = 1
    RAND = 2


class KeyType(Enum):
    SINGLE = 1
    DOUBLE = 2


DEVICE_PATH = "/dev/testdev"
KEY_FIELD = ' key'
PAYLOAD_FIELD = ' payload'


def cems_are_eqaul(cem1, cem2):
    with open(cem1, 'r') as t1, open(cem2, 'r') as t2:
        lines1 = t1.readlines()
        lines2 = t2.readlines()
        fileone = lines1.__iter__()
        filetwo = lines2.__iter__()
        the_len = len(lines1)
        if not the_len == len(lines2):
            return False

    for i in range(the_len):
        l1 = fileone.__next__()
        l2 = filetwo.__next__()
        if not l1 == l2:
            return False

    return True


class cem_insertions_base(unittest.TestCase):

    def setUp(self):
        if DEBUG_TEST:
            sdk.la_set_logging_level(288, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(288, sdk.la_logger_component_e_TABLES, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(288, sdk.la_logger_component_e_LLD, sdk.la_logger_level_e_DEBUG)
        self.device = sim_utils.create_device(1)
        assert self.device is not None, "create_device failed"
        self.ll_device = self.device.get_ll_device()
        self.rm = sdk_debug.la_device_get_resource_manager(self.device)
        self.cem = self.rm.get_cem()
        assert self.cem is not None, "get_cem failed"
        random_values = []
        self.insertions_num = 40000
        self.num_of_entries_in_bulk = 10000
        self.all_entires_should_be_inserted = True
        random.seed(2938723)

    def tearDown(self):
        self.device.tearDown()
        print("finished tear down")

    def create_key_seed(self, i):
        if self.key_gen_type == KeyGenType.SEQ:
            return i
        elif self.key_gen_type == KeyGenType.RAND:
            width = 46 if self.key_type == KeyType.SINGLE else 142
            shifting = 4
            width -= shifting
            return random.randint(0, pow(2, width))
        else:
            raise RuntimeException("shouldnt be here")

    def dump(self):
        if DEBUG_TEST:
            arc_counters = debug_utils.arc_counters(self.device)
            arc_counters.dump_debug_counters()
            if VERBOSE_DEBUG:
                cem_db = debug_utils.cem_db(self.device)
                cem_db.report(range(16))
        return ""

    def action_type(self):
        if self.key_type == KeyType.SINGLE:
            return hw_tablescli.cem_action_e_INSERT_SINGLE
        elif self.key_type == KeyType.DOUBLE:
            return hw_tablescli.cem_action_e_INSERT_DOUBLE
        else:
            raise RuntimeException("shouldnt be here")

    def gen_key(self, i):
        seed = self.create_key_seed(i)
        seed = seed * 16
        if self.key_type == KeyType.SINGLE:
            return seed
        elif self.key_type == KeyType.DOUBLE:
            seed += 3
            return seed
        else:
            raise RuntimeException("shouldnt be here")

    def create_key(self, i):
        width = 46 if self.key_type == KeyType.SINGLE else 142
        return etu.create_em_key(self.gen_key(i), width)

    def insert(self, key, payload):
        if self.key_type == KeyType.DOUBLE:
            self.device.acquire_device_lock(True)
            self.cem.insert_table_double_entry(key, payload)
        elif self.key_type == KeyType.SINGLE:
            self.device.acquire_device_lock(True)
            self.cem.insert_table_single_entry(key, payload)
        else:
            raise RuntimeException("shouldnt be here")

    def bulk_insert(self, actions):
        self.device.acquire_device_lock(True)
        return self.cem.update(actions)

    def create_action_desc(self, action, key, payload):
        action_desc = hw_tablescli.cem_action_desc()
        action_desc.m_action = action

        action_desc.m_key = key
        action_desc.m_payload = payload

        return action_desc

    def assert_key_payload_in_cem(self, key, expected_payload):
        actual_payload = hw_tablescli.em_payload()
        actual_key = self.create_key(0)
        tries = 5000
        looked_up_succesfully = False
        location = None
        while not looked_up_succesfully:
            try:
                status, location = self.cem.lookup(key, actual_payload)
                looked_up_succesfully = actual_payload.get_value() == expected_payload.get_value()
                self.assertTrue(looked_up_succesfully)
            except BaseException:
                tries -= 1
                if DEBUG_TEST:
                    print("missed key:{}".format(key.to_string()))
                if tries == 0:
                    self.assertTrue(looked_up_succesfully, "failed: key:{}, dump:{}".format(key.to_string(), self.dump()))
        return location

    def assert_report_corresponds_to_insertions(self, expected_key_payload_pairs):
        with open("./cem_db.csv", "r") as f:
            reader  = DictReader(f)
            populated_lines = filter(lambda x: '0x' in x[KEY_FIELD], reader)
            populated_lines = map(lambda x: (int(x[KEY_FIELD], 16), int(x[PAYLOAD_FIELD], 16)), populated_lines)
            populated_lines_set = set(list(populated_lines))
            expected_key_payload_pairs_set = set(map(lambda x: (x[0].get_value(), x[1].get_value()), expected_key_payload_pairs))
            if expected_key_payload_pairs_set == populated_lines_set:
                return  # TEST PASS

            print("expected_key_payload_pairs_set.difference(populated_lines_set):{}".format(
                expected_key_payload_pairs_set.difference(populated_lines_set)))
            print("populated_lines_set.difference(expected_key_payload_pairs_set):{}".format(
                populated_lines_set.difference(expected_key_payload_pairs_set)))
            self.assertTrue(False)
#           self.assertTrue(len(populated_lines) == len(expected_key_payload_pairs),"len(populated_lines):{}, len(expected_key_payload_pairs):{}".format(len(populated_lines), len(expected_key_payload_pairs)))
#           print("start")
#           expected_key_payload_pairs.sort(key= lambda x: (x[0].get_value(), x[1].get_value()))
#           populated_lines.sort(key = lambda x: (int(x[KEY_FIELD], 16),int(x[PAYLOAD_FIELD], 16)))
#           print("done")
#           for (key, payload),row in zip(expected_key_payload_pairs,populated_lines) :
#               self.assertTrue(key.get_value() == int(row[KEY_FIELD], 16), "key.get_value():{}, row:{}".format(key.get_value(), row))
#               self.assertTrue(payload.get_value() == int(row[PAYLOAD_FIELD], 16), "payload.get_value():{}, row:{}".format(payload.get_value(),row))

    def seq_double(self):
        print("###SEQ_DOUBLE###")
        self.key_gen_type = KeyGenType.SEQ
        self.key_type = KeyType.DOUBLE
        self.main()

    def seq_single(self):
        print("###SEQ_SINGLE###")
        self.key_gen_type = KeyGenType.SEQ
        self.key_type = KeyType.SINGLE
        self.main()

    def rand_double(self):
        print("###RAND_DOUBLE###")
        self.key_gen_type = KeyGenType.RAND
        self.key_type = KeyType.DOUBLE
        self.main()

    def rand_single(self):
        print("###RAND_SINGLE###")
        self.key_gen_type = KeyGenType.RAND
        self.key_type = KeyType.SINGLE
        self.main()

    def oor(self):
        print("###OOR###")
        self.key_gen_type = KeyGenType.SEQ
        self.key_type = KeyType.SINGLE
        self.insertions_num = 262656
        self.num_of_entries_in_bulk = 300000
        self.all_entires_should_be_inserted = False
        self.main()

    def setup_teardown(self):
        pass
