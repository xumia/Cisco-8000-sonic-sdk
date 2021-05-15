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

from leaba import sdk
import sim_utils
import uut_provider
import time
import argparse

args = None


def do_init_profile():
    device = sim_utils.create_device(0, initialize=False)

    device.device.set_bool_property(sdk.la_device_property_e_EMULATED_DEVICE, True)

    ldev = device.get_ll_device()
    ldev.set_shadow_read_enabled(False)

    if args.debug_hld_on:
        print("Enabling SDK HLD debug logs.")
        sdk.la_set_logging_level(0, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)

    slice_modes = sim_utils.STANDALONE_DEV
    device_config_func = None

    start = time.time()
    print('Starting the device init')
    uut_provider.initialize_device(device, slice_modes, device_config_func)
    end = time.time()

    total_time = int(end - start)

    print('Total init time: {:02d}:{:02d}:{:02d}'.format(total_time // 3600, (total_time % 3600 // 60), total_time % 60))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Initialization profiler')
    parser.add_argument('--debug_hld_on', action='store_true', help='Turn on/off HLD debug messages during initialization.')
    args = parser.parse_args()
    do_init_profile()
