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
SBIF_SPI_CTRL_CFG_REG = None
SBIF_SPI_CTRL_EXEC_REG = None
SBIF_SPI_CTRL_ADDR_REG = None
SBIF_SPI_CTRL_DATA_REG_0 = None


def sbif_write_dword(reg, val):
    ll_device.write_register(reg, val)


def sbif_read_dword(reg):
    (rc, val) = ll_device.read_register(reg)
    return val


def spi_cmd_read_encode(addr, ndwords):
    nbytes = ndwords << 2
    if nbytes > 64:
        print('ERROR - nbytes={0}, spi_read can only read from 0 to 64 bytes'.format(nbytes))
        return

    # Write the address to SBIF addr control reg
    sbif_write_dword(SBIF_SPI_CTRL_ADDR_REG, addr)

    # Encode SPI READ command
    spi_instr = 0x03
    spi_sck_half_period = 0x30  # 0x0f
    spi_data_dir = 0x0
    spi_data_len = nbytes
    spi_add_len = 0x1

    val = (spi_instr & 0xff) | ((spi_sck_half_period & 0x3f) << 22) | ((spi_add_len & 0x3) << 8) | \
          ((spi_data_len & 0x7f) << 10) | ((spi_data_dir & 0x1) << 17)

    sbif_write_dword(SBIF_SPI_CTRL_CFG_REG, val)


def spi_cmd_exec_poll():
    sbif_write_dword(SBIF_SPI_CTRL_EXEC_REG, 1)

    # poll for completion
    val = 1
    while (val):
        time.sleep(0.1)
        val = sbif_read_dword(SBIF_SPI_CTRL_EXEC_REG)


def spi_read_from_flash(addr, ndwords):
    print("spi_read_from_flash: addr 0x%x, ndword %d" % (addr, ndwords))

    dwords = []
    for i in range(0, ndwords):
        spi_cmd_read_encode(addr, ndwords)
        spi_cmd_exec_poll()
        dword = sbif_read_dword(SBIF_SPI_CTRL_DATA_REG_0)
        dwords.append(dword)

    return dwords


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

    global ll_device, pt
    global SBIF_SPI_CTRL_CFG_REG, SBIF_SPI_CTRL_EXEC_REG, SBIF_SPI_CTRL_ADDR_REG, SBIF_SPI_CTRL_DATA_REG_0

    # Init device
    device_id = 0
    # debug_on(device_id)

    print('Creating device', devpath)
    ll_device = lldcli.ll_device_create(device_id, devpath)
    assert ll_device is not None, "ll_device_create failed"

    if ('testdev' in devpath):
        simulator = test_lldcli.create_socket_simulator(devpath)
        assert simulator is not None, "create_socket_simulator failed"
        ll_device.set_device_simulator(simulator, lldcli.ll_device.simulation_mode_e_SBIF)

    pt = ll_device.get_pacific_tree()
    SBIF_SPI_CTRL_CFG_REG = pt.sbif.spi_ctrl_cfg_reg
    SBIF_SPI_CTRL_EXEC_REG = pt.sbif.spi_ctrl_exec_reg
    SBIF_SPI_CTRL_ADDR_REG = pt.sbif.spi_ctrl_addr_reg
    SBIF_SPI_CTRL_DATA_REG_0 = pt.sbif.spi_ctrl_data_reg[0]

    ll_device.set_shadow_read_enabled(False)

    return 0
    print('Reading from flash')

    flash_base_addr = 0
    dwords = spi_read_from_flash(flash_base_addr, int(320 / 4))
    for i in range(0, len(dwords)):
        print('%04x: %08x' % (i * 4, dwords[i]))

    print('Done')

    return 0


if __name__ == '__main__':
    main()
