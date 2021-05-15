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

# Converting Sherman SI parameters CSV file to json dictionary

import argparse
import json
import re


def csv_to_json(input_file, output_file):
    """
    printing the data parsed from the input file to output json printed nicely

    :param input_file:
    :param output_file:
    :return:
    """

    data_dict = parse_csv(input_file)
    with open(output_file, "w") as outfile:
        json.dump(data_dict, outfile, indent=4)
    print("json file writen to {}".format(output_file))
    return


def parse_csv(input_file):
    output_data = {}
    csv_file = open(input_file, 'r')
    start_parse = False
    header = True
    for line in csv_file:
        line = line.replace('\n', '')
        if 'ver' in line:
            output_data['VERSION'] = line.replace('#', '').replace(',', '').replace('ver', '')
        if 'BEGIN_PARAM' in line:
            start_parse = True
            continue
        if 'END_PARAM' in line:
            break
        if start_parse:
            # skip header
            if header:
                header = False
                continue
            try:
                parsed_data = get_data_from_line(line)
            except Exception as e:
                print(e)
                print('faild to parse line \n{}'.format(line))
                exit()
            serdes_data = {}
            for serdes_id in range(parsed_data['lane_start'], parsed_data['lane_end'] + 1):
                serdes_data = parsed_data.copy()
                serdes_data.pop('lane_start')
                serdes_data.pop('lane_end')
                serdes_data['serdes_id'] = serdes_id

                # Key is: Slice,IFG,SerDes,speed,module_type
                # Module type is: optics=0; Loopback=1; copper=2 (10G only), C2C=3'
                entry_key = '{},{},{},{},{}'.format(
                    serdes_data['slice_id'],
                    serdes_data['ifg_id'],
                    serdes_data['serdes_id'],
                    serdes_data['speed'],
                    serdes_data['module_type'])
                output_data[entry_key] = serdes_data
    csv_file.close()
    return output_data


def get_data_from_line(line):
    import re
    import math
    # *IFG instance,*lane,*RT instance,*line/system,*port,*Serdes speed (G),*module,TX_PRE1,TX_ATTN,TX_POST,RX_GS1,RX_GS2,rx_gain_lf.min,rx_gain_lf.max,rx_gain_hf.min,rx_gain_hf.max,RX_TERM,rx_ffe_bfglf,rx_ffe_bfghf,rx_eid,rx_hyst_post_neg,rx_hyst_post_pos

    # line = "5,[0-3],direct,line,2_17,10.3125,1,0,4,6,0,0,0,15,0,15,AVDD,1,8,2,-750,750"

    line_values = line.split(',')
    lanes = re.match('\[(\d+)\-(\d+)\]', line_values[1])

    serdes_speed = int(float(line_values[5]))
    if serdes_speed == 53:
        serdes_speed = 50

    module_type = ['OPTIC', 'LOOPBACK', 'COPPER', 'CHIP2CHIP'][int(line_values[6])]

    termination_string = line_values[16]
    termination_value = -1
    if termination_string == 'AGND':
        termination_value = 0
    elif termination_string == 'AVDD':
        termination_value = 1
    elif termination_string == 'floating':
        termination_value = 2
    else:
        raise BaseException('Failed to parse termination ({})'.format(termination_string))

    data = {
        'slice_id': int(int(line_values[0]) / 2),
        'ifg_id': int(line_values[0]) % 2,
        'lane_start': int(lanes.group(1)),
        'lane_end': int(lanes.group(2)),
        'retimer': line_values[2],  # 'direct' or number
        'line_host': line_values[3],
        'port': line_values[4],
        'speed': serdes_speed,
        'module_type': module_type,
        'TX_PRE1': int(line_values[7]),
        'TX_ATTN': int(line_values[8]),
        'TX_POST': int(line_values[9]),
        'RX_GS1': int(line_values[10]),
        'RX_GS2': int(line_values[11]),
        'RX_GAIN_LF_MIN': int(line_values[12]),
        'RX_GAIN_LF_MAX': int(line_values[13]),
        'RX_GAIN_HF_MIN': int(line_values[14]),
        'RX_GAIN_HF_MAX': int(line_values[15]),
        'RX_TERM': termination_value,
        'RX_FFE_BFGLF': int(line_values[17]),
        'RX_FFE_BFGHF': int(line_values[18]),
        'EID_THRESHOLD': int(line_values[19]),
        'HYSTERESIS_POST1_NEGATIVE': int(line_values[20]),
        'HYSTERESIS_POST1_POSITIVE': int(line_values[21]),
    }

    return data


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SI CSV to JSON converter.')

    parser.add_argument('--csv', help='Input CSV file path')
    parser.add_argument('--json', help='Output JSON file')
    args = parser.parse_args()

    if args.csv is None or args.json is None:
        print('Missing argument\n')
        exit(1)

    csv_to_json(args.csv, args.json)
