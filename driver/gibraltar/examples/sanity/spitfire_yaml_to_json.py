#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

# Converting yaml file to serdes parameter json dictionary.

import os
import argparse
import yaml
import json
import pdb


class si_yaml_parser():
    """
       The spitfire_yaml_to_json.py converts the yaml file format to serdes parameter json file format.

       The script takes two paraemeters, yaml input filename and json output filename.
            ie: python3 parse_yaml.py --yaml_file <yaml file> --json_file <output json filename>

       Note: Version python3 and up is required to run the script.

       Example:
          python3 spitfire_yaml_to_json.py --yaml_file sf_F_serdes_all_chill_p3_gib_1.yaml --json_file p3_serdes_param.json
    """

    # String mapping between YAML type to serdes_parameter JSON type
    mode_type_map = {'SI_MODE_MOD_50G_COPPER': '50,COPPER',
                     'SI_MODE_MOD_25G_COPPER': '25,COPPER',
                     'SI_MODE_MOD_10G_COPPER': '10,COPPER',
                     'SI_MODE_MOD_50G_LOOPBACK': '50,CHIP2CHIP',
                     'SI_MODE_MOD_25G_LOOPBACK': '25,CHIP2CHIP',
                     'SI_MODE_MOD_10G_LOOPBACK': '10,CHIP2CHIP',
                     'SI_MODE_MOD_50G_OPTICS': '50,OPTIC',
                     'SI_MODE_MOD_25G_OPTICS': '25,OPTIC',
                     'SI_MODE_MOD_10G_OPTICS': '10,OPTIC'}

    # For different ASIC, just modify these mappings.
    # Fields string mapping between YAML TX_SI_NAME to serdes_parameter TX_SI_NAME type
    tx_si_name_map = {'TX inner eye1': 'TX_INNER_EYE1', 'TX inner eye2': 'TX_INNER_EYE2',
                      'TX LUTE mode': 'TX_LUT_MODE',
                      'TX main': 'TX_MAIN',
                      'TX post': 'TX_POST',
                      'TX pre': 'TX_PRE1',
                      'TX Precode': 'DATAPATH_TX_PRECODE'}
    # Fields string mapping between YAML RX_SI_NAME to serdes_parameter RX_SI_NAME type
    rx_si_name_map = {'RX AC Coupling Bypass': 'RX_AC_COUPLING_BYPASS',
                      'RX AFE trim': 'RX_AFE_TRIM',
                      'RX CTLE': 'RX_CTLE_CODE',
                      'RX DSP mode': 'RX_DSP_MODE',
                      'RX Precode': 'DATAPATH_RX_PRECODE',
                      'RX VGA tracking enable': 'RX_VGA_TRACKING'}

    def load_yaml_file(self, fn):
        stream = open(fn, 'r')
        try:
            self.dictionary = yaml.load_all(stream)
            self.yaml_fn = fn
            stat = True
        except BaseException:
            stat = False
        return stat

    def parse_si_data(self, si_data):

        keys = si_data.keys()
        modes_max = si_data['mode_max']
        #
        # Loop through all 9 modes
        #
        self.mode_list_dict = {}
        self.mode_list_dict["VERSION"] = self.version
        self.mode_list_dict["YAML_INFO"] = "AUTO-GEN from YAML file: {}".format(self.yaml_fn)
        for mode_idx in range(modes_max):
            mode = si_data['mode'][mode_idx]
            mode_type = mode['mode_type']
            mode_si_value = mode['mode_si_value']
            link_max = mode_si_value['link_max']
            tmp_mode_type = "no_mode_type"
            self.ifg_list = []
            self.ifg_dict = {}
            for link_idx in range(link_max):
                link = mode_si_value['link'][link_idx]
                link_si_value = link['link_si_value']
                if (link_si_value is not None):
                    link_desc = link_si_value['desc']
                    ifg_si_data = {}
                    if link_desc not in self.ifg_list:
                        key_words = link_desc.split()
                        gb_ifg = int(key_words[-1])
                        slice_id = gb_ifg // 2
                        ifg_id = gb_ifg % 2
                        ifg_si_data['slice_id'] = slice_id
                        ifg_si_data['ifg_id'] = ifg_id
                        key_words = self.mode_type_map[mode_type].split(',')
                        ifg_si_data['speed'] = int(key_words[-2])
                        ifg_si_data['module_type'] = key_words[-1]
                        link_key = "{},{},{},{}" .format(slice_id, ifg_id, ifg_si_data['speed'], ifg_si_data['module_type'])
                        self.ifg_list.append(link_desc)
                        lane_max = link_si_value['lane_max']
                        for lane_idx in range(lane_max):
                            lane_si_value = link_si_value['lane'][lane_idx]['lane_si_value']
                            #
                            # Adding RX serdes parameters
                            #
                            tx_reg_count = lane_si_value['tx_reg_count']
                            tx_si_value = lane_si_value['tx_si_value']
                            for tx_si_idx in range(tx_reg_count):
                                try:
                                    tx_name = self.tx_si_name_map[tx_si_value[tx_si_idx]['desc']]
                                    val = tx_si_value[tx_si_idx]['val']
                                    #
                                    # Change to signed integer
                                    #
                                    if (val > 0x7FFFFFFF):
                                        val = int(val - 0x100000000)
                                    ifg_si_data[tx_name] = val
                                except BaseException:
                                    print("{} is not found in tx_si_name_map table.".format(tx_si_value[tx_si_idx]['desc']))
                            #
                            # Adding RX serdes parameters
                            #
                            rx_reg_count = lane_si_value['rx_reg_count']
                            rx_si_value = lane_si_value['rx_si_value']
                            for rx_si_idx in range(rx_reg_count):
                                try:
                                    rx_name = self.rx_si_name_map[rx_si_value[rx_si_idx]['desc']]
                                    rx_val = int(rx_si_value[rx_si_idx]['val'])
                                    #
                                    # Change to signed integer
                                    #
                                    if (rx_val > 0x7FFFFFFF):
                                        rx_val = int(rx_val - 0x100000000)
                                    ifg_si_data[rx_name] = rx_val
                                except BaseException:
                                    print("{} is not found in rx_si_name_map table." % (rx_si_value[rx_si_idx]['desc']))
                        self.mode_list_dict[link_key] = ifg_si_data
        return True

    def save_to_file(self, fn):
        print("\n\nParsed data.  Save to filename: {}\n\n".format(fn))
        self.json = json.dumps(self.mode_list_dict, indent=4)
        f = open(fn, "w")
        f.write(self.json)
        f.close()

    def parse_slot(self, slot_max, slot_list):
        # Start searching from the list
        found = False
        idx = 0
        idx_max = slot_max
        slist = slot_list
        srch_data = slist[idx]
        while not found and (idx < idx_max):
            if isinstance(srch_data, dict):
                keys = srch_data.keys()
                for key2 in keys:
                    # Search the key and stop at "inst_si_value" then start parsing from there.
                    if (key2 == "inst_si_value"):
                        found = True
                        new_dict = srch_data[key2]
                    elif (isinstance(srch_data[key2], list) or isinstance(srch_data[key2], dict)):
                        # look through the list and find a new list with dictionary
                        not_found = True
                        srch_data = srch_data[key2]
                        for kk, value in srch_data.items():
                            if (isinstance(value, list)):
                                srch_data = value[0]
                                not_found = False
                        if not_found:
                            idx = idx + 1
            else:
                idx = idx + 1
        if (found):
            self.parse_si_data(new_dict)
        else:
            print("No dictionary is found with keys={}".format(keys))

    def parse_yaml_data(self, json_fn):
        #
        for doc in self.dictionary:
            for key, value in doc.items():
                if key == "struct_ver":
                    doc_start = True
                elif key == "card_type":
                    card_type = value
                elif key == "asic_type":
                    asic_type = value
                elif key == "si_ver":
                    si_param_ver = value
                elif key == "board_ver_min":
                    board_ver_min = value
                elif key == "slot_max":
                    slot_max = int(value)
                elif key == "slot":
                    self.version = "{} {} version: {} Board: P{}".format(card_type, asic_type, si_param_ver, board_ver_min)
                    self.parse_slot(slot_max, value)
                    self.save_to_file(json_fn)
        if not doc_start:
            print("ERROR: Unable to locate the beginning of SI information")
            return False

        return True

    #
    # Need to reload yaml file because self.dictionary type is generator
    #
    def dump_dict_json(self, infile, json_name='json_dict.json'):
        stream = open(infile, 'r')
        list_data = list(yaml.load_all(stream))
        json_format_str = json.dumps(list_data, indent=2)
        original_stdout = sys.stdout
        with open(json_name, 'w') as f:
            print('Saving json dictionary to {}'.format(json_name))
            sys.stdout = f
            print(json_format_str)
            sys.stdout = original_stdout

    def gen_si_json(self, json_fn):
        print("Parse and save JSON to {}".format(json_fn))
        stat = self.parse_yaml_data(json_fn)
        return stat

    def convert_yaml_to_json(self, infile, outfile):
        self.load_yaml_file(infile)
        stat = self.gen_si_json(outfile)
        if not stat:
            print("Error - Could not generate serdes parameter from YAML file")
        return stat

    def init_parser(self):
        self.parser = argparse.ArgumentParser(description='SI YAML file to JSON file parser.')
        self.parser.add_argument('--yaml_file', default=None,
                                 help='Input SI YAML filename.  %(default)s')
        self.parser.add_argument('--json_file', default=None,
                                 help='Output SI JSON filename.  %(default)s')

    def parse_args(self):
        self.init_parser()
        self.args = self.parser.parse_args()


#
# Convert YAML to JSON and print in indent format
#
if __name__ == '__main__':
    import sys
    yaml_parser = si_yaml_parser()
    yaml_parser.parse_args()
    if (yaml_parser.args.yaml_file is not None) and (yaml_parser.args.json_file is not None):
        stat = yaml_parser.convert_yaml_to_json(yaml_parser.args.yaml_file, yaml_parser.args.json_file)
        # Uncomment for debugging.  Dump for debugging
        ## yaml_parser.dump_dict_json(yaml_parser.args.yaml_file, "y2j_format.json")
    else:
        print("No input and/or output file.")
        yaml_parser.parser.print_help()
