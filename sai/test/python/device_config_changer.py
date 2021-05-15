#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import json
from sai_test_utils import is_asic_env_gibraltar


class DeviceConfigChanger():
    '''
    Dynamically creates and updates device JSON configuration for testing.
    '''

    def __init__(self, input_config_file=""):
        '''
        Construct a DeviceConfigChanger. If input_config_file is not
        specified, it will be automatically selected based on device type.
        '''
        if input_config_file == "":
            sdk_root = os.getenv('SDK_ROOT', os.getcwd() + "/../")
            board = "blacktip" if is_asic_env_gibraltar() else "sherman"
            input_config_file = "{0}/sai/res/config/{1}.json".format(sdk_root, board)

        with open(input_config_file, 'r') as in_fp:
            self._json_dict = json.load(in_fp)

    def update_device_config(self, dev_json_dict, dev_index=0):
        '''
        Add fields of the dev_index'th object in the JSON file's "devices"
        array. If configuration already exists, overwrites with
        provided configuration.
        '''
        self._json_dict["devices"][dev_index].update(dev_json_dict)

    def write_config_file(self, to_config_file, json_indent=4):
        '''
        Write out the current stored configuration to the given filename,
        with a default pretty-print indent of 4.
        '''
        with open(to_config_file, 'w') as out_fp:
            json.dump(self._json_dict, out_fp, indent=json_indent)
