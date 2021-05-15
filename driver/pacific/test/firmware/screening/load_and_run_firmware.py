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


import unittest
import lldcli
import test_lldcli
import argparse
import sys
import struct
import array
import time

ll_device = None

# Layout of ARC instructions and data memories:
#   leaba_trunk/Moriah/ASIC/verification/dmc/tests/dmc_arc_multi_core_test.sv
#
# make test-firmware-css
# out/noopt-debug/bin/test_firmware_css_iccm.bin
#
# make firmware-css
# out/noopt-debug/res/firmware_css_sys.bin
#


def load_firmware_to_device(ll_device, fw_path, fw_base):
    pt = ll_device.get_pacific_tree()
    is_sim = (ll_device.get_device_simulator() is not None)
    memory_step = 4 if not is_sim else 1  # byte addressable in silicon, dword addressable in RTL

    fw = array.array('I')
    with open(fw_path, 'rb') as f:
        fw.frombytes(f.read())

    print('Firmware path: {0}, size bytes {1}, size dwords {2}, memory_step {3}'.format(fw_path, len(fw) * 4, len(fw), memory_step))
    for i in range(0, len(fw)):
        ll_device.write_memory(pt.sbif.css_mem_even, fw_base + i * memory_step, fw[i])

    # TODO:
    # # core reset
    # ll_device.write_register(pt.sbif.reset_reg, 0x1e)
    # # take core out of reset
    # ll_device.write_register(pt.sbif.reset_reg, 0x1f)
    # time.sleep(10)
    # # take arc0 out of reset
    # ll_device.write_register(pt.sbif.reset_reg, 0x1d)
    # # ARC0 go
    # ll_device.write_register(pt.sbif.arc_run_halt_reg[0], 0x1)


def debug_on(device_id):
    from leaba import sdk as sdk
    lld_components = [
        sdk.la_logger_component_e_AE,
        sdk.la_logger_component_e_LLD,
        sdk.la_logger_component_e_ACCESS,
        sdk.la_logger_component_e_SBIF]
    for dev_id in [device_id, 288]:
        for component in lld_components:
            sdk.la_set_logging_level(dev_id, component, sdk.la_logger_level_e_DEBUG)


def main():
    # Parse command line args
    parser = argparse.ArgumentParser()
    parser.add_argument('--devpath', default=None, help='device path, e.g. /dev/uio0')
    parser.add_argument('--host', default=None, help='server hostname')
    parser.add_argument('--port_rw', type=int, default=None, help='TCP port for read/write')
    parser.add_argument('--port_int', type=int, default=None, help='TCP port for interrupt')
    parser.add_argument('--fwpath', required=True, help='Path to firmware binary')

    args, unknown_args = parser.parse_known_args()

    uri = (args.devpath) and (not args.host and not args.port_rw and not args.port_int)
    socket = (not args.devpath) and (args.host and args.port_rw and args.port_int)
    if uri:
        devpath = args.devpath
    elif socket:
        devpath = '/dev/testdev/socket?host={0}&port_rw={1}&port_int={2}'.format(args.host, args.port_rw, args.port_int)
    else:
        print('ERROR: bad arguments, use either --devpath or a combination of --host,--port_rw,--port_int')
        parser.print_help()
        return 1

    # Init device
    device_id = 0
    debug_on(device_id)

    print('Creating device', devpath)
    global ll_device
    ll_device = lldcli.ll_device_create(device_id, devpath)
    assert ll_device is not None, "ll_device_create failed"

    if ('testdev' in devpath):
        simulator = test_lldcli.create_socket_simulator(devpath)
        assert simulator is not None, "create_socket_simulator failed"
        ll_device.set_device_simulator(simulator, lldcli.ll_device.simulation_mode_e_SBIF)

    # Load firmware from file and write to device's CSS memory
    #load_firmware_to_device(ll_device, args.fwpath, int(0x604/4))
    return 0


if __name__ == '__main__':
    main()
