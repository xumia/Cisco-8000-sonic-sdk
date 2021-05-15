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
import uut_provider
import lldcli
import decor
import os
from distutils.util import strtobool
import topology as T

# Create production or RTL device.
#   Example of RTL device path: /dev/rtl/socket:localhost:7474,7475
if decor.is_asic5():
    STANDALONE_DEV = [sdk.la_slice_mode_e_NETWORK] * 1
elif decor.is_asic3():
    STANDALONE_DEV = [sdk.la_slice_mode_e_NETWORK] * 8
else:
    STANDALONE_DEV = [sdk.la_slice_mode_e_NETWORK] * 6

LINECARD_4N_2F_DEV = [sdk.la_slice_mode_e_NETWORK] * 4 + [sdk.la_slice_mode_e_CARRIER_FABRIC] * 2
LINECARD_3N_3F_DEV = [sdk.la_slice_mode_e_NETWORK] * 3 + [sdk.la_slice_mode_e_CARRIER_FABRIC] * 3
FABRIC_ELEMENT_DEV = [sdk.la_slice_mode_e_CARRIER_FABRIC] * 6


# Main helper function to create single host simulation flow.


#
# enable_logging_from_env explicitly indicates we should look at the
# "ENABLE_NSIM_LOG" environment variable for logging. This is more granular
# that enable_logging.
#
def create_test_device(
        device_path,
        dev_id,
        initialize=True,
        slice_modes=None,
        device_config_func=None,
        nsim_accurate_scale_model=False,
        enable_logging=False,
        test_mode_punt_egress_packets_to_host=False,
        matilda_model=(-1, False),
        enable_logging_from_env=True):

    if (slice_modes is None):
        slice_modes = STANDALONE_DEV

    uut = uut_provider.nsim_device()
    uut.matilda_model = matilda_model
    uut.init(
        device_path,
        dev_id,
        initialize,
        slice_modes,
        nsim_accurate_scale_model,
        enable_logging,
        device_config_func,
        test_mode_punt_egress_packets_to_host,
        enable_logging_from_env)
    return uut


def create_hw_device(
        device_path,
        dev_id,
        initialize=True,
        slice_modes=None,
        device_config_func=None,
        matilda_model=(-1, False)):
    uut = uut_provider.hw_device()
    uut.matilda_model = matilda_model
    uut.init(device_path, dev_id, initialize, slice_modes, device_config_func)
    return uut


def create_device(
        dev_id,
        initialize=True,
        slice_modes=None,
        device_config_func=None,
        should_read_matilda_model=True):

    if (decor.is_asic5()):
        if (slice_modes is None):
            slice_modes = [sdk.la_slice_mode_e_NETWORK] * 1
    elif (decor.is_asic3()):
        if (slice_modes is None):
            slice_modes = [sdk.la_slice_mode_e_NETWORK] * 8
    else:
        if (slice_modes is None):
            slice_modes = [sdk.la_slice_mode_e_NETWORK] * 6

    matilda_model = read_matilda_model(should_read_matilda_model)

    if decor.is_hw_device():
        return create_hw_device(os.getenv('SDK_DEVICE_NAME'), dev_id, initialize,
                                slice_modes, device_config_func,
                                matilda_model=matilda_model)
    else:
        return create_test_device('/dev/testdev', dev_id, initialize, slice_modes,
                                  device_config_func,
                                  enable_logging_from_env=True,
                                  matilda_model=matilda_model)


def get_device_tree(ll_device):
    if ll_device.is_pacific():
        return ll_device.get_pacific_tree()
    if ll_device.is_gibraltar():
        return ll_device.get_gibraltar_tree()
    if ll_device.is_asic4():
        return ll_device.get_asic4_tree()
    if ll_device.is_asic5():
        return ll_device.get_asic5_tree()
    if ll_device.is_asic3():
        return ll_device.get_asic3_tree()
    return None


def read_matilda_model(should_read_matilda_model):
    if (not should_read_matilda_model or not decor.is_gibraltar()):
        return 0, False
    mat_str, mat_hw_type = decor.get_matilda_model_from_env()
    return decor.matilda_str_to_int(mat_str), mat_hw_type
