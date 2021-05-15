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

from leaba import sdk
import test_racli as ra
import hld_sim_utils
import lldcli

import argparse

ll_device = None
device_tree = None


def setup(port):
    global ll_device
    global device_tree

    ll_device = lldcli.ll_device_create(0, '/dev/testdev/rtl')

    block_filter = []
    sim_options = ra.simulator_options()
    sim_options.use_socket = True
    sim_options.use_socket_in_mems_init = True
    sim_options.use_socket_in_rest_of_init = True
    sim_options.use_socket_in_load_arc_microcode = False
    sim_options.port = port

    simulator = ra.create_ra_simulator(block_filter, 0, sim_options)
    ll_device.set_device_simulator(simulator, lldcli.ll_device.simulation_mode_e_SBIF)
    ll_device.set_shadow_read_enabled(False)
    ll_device.reset()
    ll_device.reset_access_engines()
    device_tree = ll_device.get_asic3_tree()


def test_acm_access():
    print("Testing ACM access...")
    reg = device_tree.acm.reset_reg
    rval = ll_device.read_register(reg)
    print("device_tree.acm.reset_reg = {}".format(rval))
    assert (rval == 1), "Error: ACM access error! Value should be 1"


def test_acm_top_access():
    print("Testing ACM top access...")
    reg = device_tree.asic7_top.core_obs_clk
    rval = ll_device.read_register(reg)
    print("device_tree.asic7_top.core_obs_clk = {}".format(rval))
    assert (rval == 40), "Error: ACM top access error! Value should be 40"

    ll_device.write_register(reg, 38)
    print("device_tree.asic7_top.core_obs_clk new value set!")
    rval = ll_device.read_register(reg)
    assert (rval == 38), "Error: ACM top access error! Value should be 38"


def test_acm_acc_eng_access():
    print("Testing ACM access engine access...")
    reg = device_tree.slice[0].ifg[0].serdes_pool16.broadcast_config_reg
    rval = ll_device.read_register(reg)
    print("device_tree.slice[0].ifg[0].serdes_pool16.broadcast_config_reg = {}".format(rval))
    assert (rval == 4095), "Error: ACM top access error! Value should be 4095"
    ll_device.write_register(reg, 45)
    print("device_tree.slice[0].ifg[0].serdes_pool16.broadcast_config_reg new value set!")
    rval = ll_device.read_register(reg)
    print("device_tree.slice[0].ifg[0].serdes_pool16.broadcast_config_reg = {}".format(rval))
    assert (rval == 45), "Error: ACM access error! Value should be 45"


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RTL Test Asic7 standalone')
    parser.add_argument('--port', default=5674, type=int, help='TCP port')

    args = parser.parse_args()

    setup(args.port)
    test_acm_access()
    test_acm_top_access()
    test_acm_acc_eng_access()

    print("Asic7 standalone test finished!")
