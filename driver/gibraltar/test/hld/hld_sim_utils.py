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

import lldcli
import test_lldcli
from leaba import sdk
import test_nsim_providercli as nsim
import test_racli as ra
import rtl_test_utils
import hld_uut_provider

# Create production or RTL device.
#   Example of RTL device path: /dev/rtl/socket:localhost:7474,7475

STANDALONE_DEV = [sdk.la_slice_mode_e_NETWORK] * 6
LINECARD_4N_2F_DEV = [sdk.la_slice_mode_e_NETWORK] * 4 + [sdk.la_slice_mode_e_CARRIER_FABRIC] * 2
LINECARD_3N_3F_DEV = [sdk.la_slice_mode_e_NETWORK] * 3 + [sdk.la_slice_mode_e_CARRIER_FABRIC] * 3
FABRIC_ELEMENT_DEV = [sdk.la_slice_mode_e_CARRIER_FABRIC] * 6


def create_rtl_device(device_path, dev_id, slice_modes=STANDALONE_DEV, initialize=False,
                      simulation_mode=lldcli.ll_device.simulation_mode_e_LBR, device_config_func=None):
    uut = hld_uut_provider.rtl_device()
    uut.init(device_path, dev_id, slice_modes, initialize, simulation_mode, device_config_func)
    return uut


def create_ra_device(
        device_path,
        dev_id,
        use_socket,
        port,
        initialize=True,
        slice_modes=STANDALONE_DEV,
        block_filter_getter=lambda _: [],
        create_sim=False,
        enable_hbm_lpm=False,
        device_config_func=None,
        inject_from_npu_host=False,
        restore_full_init=False,
        restore_mems_init=False,
        skip_arc_microcode=False,
        add_inject_up_header_if_inject_from_npuh=True):
    sim_options = ra.simulator_options()
    sim_options.use_socket = use_socket
    sim_options.use_socket_in_mems_init = not (restore_full_init or restore_mems_init)
    sim_options.use_socket_in_rest_of_init = not restore_full_init
    sim_options.use_socket_in_load_arc_microcode = not skip_arc_microcode
    sim_options.port = port
    uut = hld_uut_provider.ra_device()
    uut.init(
        device_path,
        dev_id,
        initialize,
        slice_modes,
        block_filter_getter,
        create_sim,
        enable_hbm_lpm,
        device_config_func,
        inject_from_npu_host,
        sim_options,
        add_inject_up_header_if_inject_from_npuh)
    return uut
