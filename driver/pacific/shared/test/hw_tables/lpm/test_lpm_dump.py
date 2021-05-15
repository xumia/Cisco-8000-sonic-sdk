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

import os

import ipaddress

import gzip
import json
from logical_lpm_base import logical_lpm_base
import unittest
import lpm_test_utils
import hw_tablescli

from parser_formats import lpm_instruction

LPM_DUMP_FILENAME = "lpm_dump.json.gz"

FILE_PATH = "shared/test/hw_tables/lpm/inputs/ip_mix_big.txt.gz"
FILE_FORMAT = "OLD_FORMAT"

VRF_LENGTH = 11

L1 = 0
L2 = 1


class test_lpm_dump(logical_lpm_base):

    def test_dump_entries_from_file(self):
        print(" * Inserting entries from file \"{}\"".format(FILE_PATH))
        lpm_input = lpm_test_utils.generate_instructions_from_file(FILE_PATH, FILE_FORMAT, 100000)
        lpm_test_utils.execute_bulk(self.logical_lpm, lpm_input, 100000)
        self.perform_test_actions(lpm_input)
        print(" * Dumping the LPM")
        self.logical_lpm.save_state(LPM_DUMP_FILENAME)
        print(" * Checking sanity")
        self.check_sanity()
        print(" * Deleting the dump file (by calling save_state)")
        os.remove(LPM_DUMP_FILENAME)

    def check_sanity(self):
        with gzip.open(LPM_DUMP_FILENAME) as lpm_dump_file:
            lpm_dump = json.loads(lpm_dump_file.read())
            lpm_dump_file.close()
            self.check_lpm_dump_result(lpm_dump)

    def check_lpm_dump_result(self, lpm_dump):
        print("     - Checking the node structure of the LPM dump")
        self.check_nodes_structure(lpm_dump)
        print("     - Checking the buckets inside the LPM dump")
        self.check_buckets(lpm_dump)

    def check_nodes_structure(self, lpm_dump):
        """
        Checks that the structure of the nodes in the LPM dump is valid
        (i.e. that each node can actually be a parent of its children,
        and that the valid keys are exactly the inserted keys).
        :param lpm_dump: The dict made from the JSON of the LPM dump
        :return: None
        """
        keys_in_tree = set()
        subtrees = [lpm_dump[hw_tablescli.bucketing_tree.TREE_KEY][hw_tablescli.bucketing_tree.ROOT_KEY]]
        while len(subtrees) > 0:
            new_subtrees = []
            for subtree in subtrees:
                if subtree[hw_tablescli.bucketing_tree.IS_VALID_KEY]:
                    keys_in_tree.add(
                        (subtree[hw_tablescli.bucketing_tree.KEY_VALUE_KEY], subtree[hw_tablescli.bucketing_tree.KEY_WIDTH_KEY]))
                if hw_tablescli.bucketing_tree.LEFT_KEY in subtree:
                    self.assertTrue(self.is_parent(subtree, subtree[hw_tablescli.bucketing_tree.LEFT_KEY]))
                    new_subtrees.append(subtree[hw_tablescli.bucketing_tree.LEFT_KEY])
                if hw_tablescli.bucketing_tree.RIGHT_KEY in subtree:
                    self.assertTrue(self.is_parent(subtree, subtree[hw_tablescli.bucketing_tree.RIGHT_KEY]))
                    new_subtrees.append(subtree[hw_tablescli.bucketing_tree.RIGHT_KEY])
            subtrees = new_subtrees

        # Makes sure that the valid keys == the inserted keys.
        self.assertEqual(self.insertions, keys_in_tree, "The keys that were inserted should be exactly the valid keys in the tree")

    def compare_buckets(self, json_buckets, buckets):
        """
        Checks that the list of json_buckets actually represents the buckets
        :param json_buckets:
        :param buckets:
        :return:
        """
        buckets_dict = {str(bucket.get_sw_index()): self.bucket_to_dict(bucket) for bucket in buckets}
        self.assertEqual(json_buckets, buckets_dict)

    def check_buckets(self, lpm_dump):
        """
        Checks that the buckets in the LPM dump are the same buckets in the logical LPM.
        :param lpm_dump:
        :return:
        """
        buckets_lpm_dump = lpm_dump[hw_tablescli.bucketing_tree.TREE_KEY][hw_tablescli.bucketing_tree.BUCKETS_KEY]
        json_bucket_L1 = buckets_lpm_dump[hw_tablescli.bucketing_tree.L1_BUCKETS_KEY]
        json_bucket_L2 = buckets_lpm_dump[hw_tablescli.bucketing_tree.L2_BUCKETS_KEY]
        tree = self.logical_lpm.get_tree()

        # Compares the buckets
        self.compare_buckets(json_bucket_L1, tree.get_buckets(L1))
        self.compare_buckets(json_bucket_L2, tree.get_buckets(L2))

    def perform_test_actions(self, instructions):
        """
        Gets a list of LpmInstruction and performs each instruction
        :param instructions: The list of LpmInstructions
        :return: None
        """
        self.insertions = set()
        # Keeps and encodes all the keys that were inserted in order to compare them later.
        for instruction in instructions:
            k, w = instruction.get_key_and_width()
            # Encode key
            encoded_key_value, encoded_key_width = lpm_test_utils.encode_lpm_prefix(k, w)
            encoded_key = lpm_test_utils.generate_lpm_key(encoded_key_value, encoded_key_width)
            if instruction.action == lpm_instruction.INSERT:
                self.insertions.add((encoded_key.to_string(), encoded_key.get_width()))

            if instruction.action == lpm_instruction.REMOVE:
                self.insertions.remove((encoded_key.to_string(), encoded_key.get_width()))

    # Helper Methods
    @staticmethod
    def key_to_binary_string(key, key_width):
        """
        Converts a key to a binary string (with proper zero padding)
        :param key: A string in hex representing the value of the key
        :param key_width: The width of the key
        :return:
        """
        b = bin(int(key, 16))[2:]
        return (key_width - len(b)) * '0' + b

    @staticmethod
    def is_suffix(key1, key_width1, key2, key_width2):
        """
        Checks if key1 is a suffix of key2
        :param key1:
        :param key_width1:
        :param key2:
        :param key_width2:
        :return:
        """
        if key_width1 > key_width2:
            return False

        if key_width1 == 0:
            return True

        b1 = test_lpm_dump.key_to_binary_string(key1, key_width1)
        b2 = test_lpm_dump.key_to_binary_string(key2, key_width2)

        return b1 == b2[:key_width1]

    @staticmethod
    def is_parent(node1, node2):
        """
        Checks if node1 can be a parent of node2
        :param node1:
        :param node2:
        :return:
        """
        return test_lpm_dump.is_suffix(node1[hw_tablescli.bucketing_tree.KEY_VALUE_KEY],
                                       node1[hw_tablescli.bucketing_tree.KEY_WIDTH_KEY],
                                       node2[hw_tablescli.bucketing_tree.KEY_VALUE_KEY],
                                       node2[hw_tablescli.bucketing_tree.KEY_WIDTH_KEY])

    @staticmethod
    def bucket_to_dict(bucket):
        """
        Converts a bucket to a dict with all the necessary data
        :param bucket:
        :return:
        """
        root = {hw_tablescli.bucketing_tree.KEY_VALUE_KEY: bucket.get_root().to_string(),
                hw_tablescli.bucketing_tree.KEY_WIDTH_KEY: bucket.get_root().get_width()}
        return {hw_tablescli.bucketing_tree.ROOT_KEY: root,
                hw_tablescli.bucketing_tree.SW_INDEX_KEY: bucket.get_sw_index(),
                hw_tablescli.bucketing_tree.HW_INDEX_KEY: bucket.get_hw_index(),
                hw_tablescli.bucketing_tree.DEFAULT_PAYLOAD_KEY: bucket.get_default_entry().payload,
                hw_tablescli.bucketing_tree.CORE_KEY: bucket.get_core()}


if __name__ == "__main__":
    unittest.main()
