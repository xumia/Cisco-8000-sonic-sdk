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

from leaba import sdk
import lldcli
import cpu2jtagcli
import time
import os

verbose = 1


def set_bit(val, bit, is_high):
    if is_high:
        return val | (1 << bit)
    return val & ~(1 << bit)


def get_bits(val, msb, lsb):
    mask = (1 << (msb - lsb + 1)) - 1
    return (val >> lsb) & mask


class fuse():
    default_test_reg_value = 0x83e06c0c5fffffffffffffffffffffffffffffffffffffffffffffffffe0000000000000000000000001ffffffffffffffffffffffffe047fffffffffffe0000000000000000005b689281fffffffffffffffffffffffffffffffe0000000000001e7ffffffffffffffffffffffff9401c0000b82000000000000000000000001

    def __init__(self, ll_dev=None):
        dev_id = 0
        if verbose >= 2:
            sdk.la_set_logging_level(dev_id, sdk.la_logger_component_e_CPU2JTAG, sdk.la_logger_level_e_XDEBUG)
        elif verbose == 1:
            sdk.la_set_logging_level(dev_id, sdk.la_logger_component_e_CPU2JTAG, sdk.la_logger_level_e_DEBUG)

        dev_path = os.getenv('SDK_DEVICE_NAME')
        if dev_path is None:
            dev_path = '/dev/testdev'
        if ll_dev is None:
            self.ll_device = lldcli.ll_device_create(dev_id, dev_path)
        else:
            self.ll_device = ll_dev
        self.tap = cpu2jtagcli.cpu2jtag_create(self.ll_device)

        self.reset_tap()

    def reset_tap(self):
        # disable TAP override
        self.tap.disable()

        # enable TAP override, then deassert -> assert -> deassert JTAG
        core_freq_khz, tck_freq_mhz = 1200 * 1000, 5
        self.tap.enable(core_freq_khz, tck_freq_mhz)

    def setup_tap_for_fuse_access(self, test_reg_value_init):
        test_reg_value = test_reg_value_init
        print("configuring TR_FUSE_CTRL_SEL_AS_0 = 1, REG_TEST__FUSE_CTRL_TAP_CTRL = 1, REG_TEST__FUSE_CTRL_DISABLE_RESET = 1, REG_TEST__FUSE_CTRL_CORE_REQ_EN = 0, REG_TEST__FUSE_CTRL_RESET_L = 0, REG_TEST__FUSE_CTRL_SPEED_2 = 1...")
        test_reg_value = set_bit(test_reg_value, 439, 1)
        test_reg_value = set_bit(test_reg_value, 444, 1)
        test_reg_value = set_bit(test_reg_value, 446, 1)
        test_reg_value = set_bit(test_reg_value, 443, 0)
        test_reg_value = set_bit(test_reg_value, 445, 0)
        test_reg_value = set_bit(test_reg_value, 482, 1)
        self.tap.load_ir_dr_no_tdo(0x2b4, 1028, test_reg_value)
        print("configuring REG_TEST__FUSE_CTRL_RESET_L = 1...")
        test_reg_value = set_bit(test_reg_value, 445, 1)
        self.tap.load_ir_dr_no_tdo(0x2b4, 1028, test_reg_value)
        return test_reg_value

    def write_fuse_4k_bit_buffer(self, write_data):
        print("writing " + hex(write_data) + " to the 4k-bit-buffer of the fuse...")
        read_data = self.tap.load_ir_dr(0x200, 4096, write_data)
        return read_data

    def read_fuse_into_4k_bit_buffer(self):
        print("reading the fuse into its 4k-bit-buffer...")
        self.tap.load_ir(0x2d2)
        time.sleep(1)

    def configure_tck_on_fuse_read(self, test_reg_value, enable_tck):
        disable_tck = 1 - enable_tck
        print("configuring TR_DFT_CLK_IS_DFT_CLK_IN = " + str(disable_tck) + "...")
        test_reg_value = set_bit(test_reg_value, 1001, disable_tck)
        self.tap.load_ir_dr_no_tdo(0x2b4, 1028, test_reg_value)
        return test_reg_value

    def read_fuse_4k_bit_buffer(self, write_data=0):
        print("reading the 4k-bit-buffer of the fuse while writing " + hex(write_data) + "...")
        fuse_data = self.tap.load_ir_dr(0x200, 4096, write_data)
        print('read_fuse_4k_bit_buffer: fuse_data={}'.format(hex(fuse_data)))
        return fuse_data

    def get_device_id_from_fuse_data(self, fuse_data):
        device_id = get_bits(fuse_data, 62, 0)
        return device_id

    def bit_reversal(self, x_in, size):
        x_out = 0
        for i in range(0, size):
            x_out = set_bit(x_out, size - 1 - i, get_bit(x_in, i))
        return x_out

    # Read fuse value, don't reload the 4bit buffer afterwords
    def read_fuse_fast(self):
        test_reg_value = self.setup_tap_for_fuse_access(self.default_test_reg_value)
        # self.write_fuse_4k_bit_buffer(0x0)
        test_reg_value = self.configure_tck_on_fuse_read(test_reg_value, 0)
        self.read_fuse_into_4k_bit_buffer()
        test_reg_value = self.configure_tck_on_fuse_read(test_reg_value, 1)
        fuse_data = self.read_fuse_4k_bit_buffer()
        print("configuring the TAP's TESTREG to its default value...")
        self.tap.load_ir_dr_no_tdo(0x2b4, 1028, self.default_test_reg_value)
        print("===========================================")
        device_id = self.get_device_id_from_fuse_data(fuse_data)
        print("fuse_data =", hex(fuse_data))
        print("device_id =", hex(device_id))

    # Read fuse value, and also reload the 4bit buffer afterwords so that
    # sbif.efuse_userbits_reg0,1,2,3 will read meaningful values afterwords.
    def read_fuse(self):
        test_reg_value = self.setup_tap_for_fuse_access(self.default_test_reg_value)
        # self.write_fuse_4k_bit_buffer(0x0)
        test_reg_value = self.configure_tck_on_fuse_read(test_reg_value, 0)
        self.read_fuse_into_4k_bit_buffer()
        test_reg_value = self.configure_tck_on_fuse_read(test_reg_value, 1)
        # Read the fuse value from 4k-bit buffer to CPU, the 4k-bit buffer is invalidated.
        fuse_data = self.read_fuse_4k_bit_buffer()
        # Read the fuse value into the 4k-bit buffer again.
        # This enables fetching the lower 4 dwords of fuse value from sbif.efuse_userbits_reg0,1,2,3.
        self.read_fuse_into_4k_bit_buffer()
        print("configuring REG_TEST__FUSE_CTRL_TAP_CTRL = 0")
        test_reg_value = set_bit(test_reg_value, 444, 0)
        self.tap.load_ir_dr_no_tdo(0x2b4, 1028, test_reg_value)
        print("configuring the TAP's TESTREG to its default value...")
        self.tap.load_ir_dr_no_tdo(0x2b4, 1028, self.default_test_reg_value)
        print("===========================================")
        device_id = self.get_device_id_from_fuse_data(fuse_data)
        fuse_userbits = self.read_fuse_userbits()
        print("fuse_data =", hex(fuse_data))
        print("device_id =", hex(device_id))
        print("fuse_userbits =", hex(fuse_userbits))
        return device_id

    def reload_fuse_userbits(self):
        # efuse_userbits registers fetch the first 128bits from fuse 4kb buffer.
        # To enable those registers, we read fuse value into that buffer.
        test_reg_value = self.setup_tap_for_fuse_access(self.default_test_reg_value)
        test_reg_value = self.configure_tck_on_fuse_read(test_reg_value, 0)
        self.read_fuse_into_4k_bit_buffer()
        test_reg_value = self.configure_tck_on_fuse_read(test_reg_value, 1)

        print("configuring REG_TEST__FUSE_CTRL_TAP_CTRL = 0")
        test_reg_value = set_bit(test_reg_value, 444, 0)
        self.tap.load_ir_dr_no_tdo(0x2b4, 1028, test_reg_value)

        print("configuring the TAP's TESTREG to its default value...")
        self.tap.load_ir_dr_no_tdo(0x2b4, 1028, self.default_test_reg_value)

        # NOTE: if tap.disable() is called, a "read" from fuse_userbits will fetch 0.
        return self.read_fuse_userbits()

    def read_fuse_userbits(self):
        sbif = self.ll_device.get_pacific_tree().sbif
        dword0 = self.ll_device.read_register(sbif.efuse_userbits_reg0)
        dword1 = self.ll_device.read_register(sbif.efuse_userbits_reg1)
        dword2 = self.ll_device.read_register(sbif.efuse_userbits_reg2)
        dword3 = self.ll_device.read_register(sbif.efuse_userbits_reg3)

        return (dword3 << 96) | (dword2 << 64) | (dword1 << 32) | dword0

    def burn_fuse(self, write_data):
        test_reg_value = self.setup_tap_for_fuse_access(self.default_test_reg_value)
        self.write_fuse_4k_bit_buffer(0x0)
        test_reg_value = self.configure_tck_on_fuse_read(test_reg_value, 0)
        self.read_fuse_into_4k_bit_buffer()
        test_reg_value = self.configure_tck_on_fuse_read(test_reg_value, 1)
        fuse_data_before_burn = self.read_fuse_4k_bit_buffer(write_data)
        test_reg_value = self.configure_tck_on_fuse_read(test_reg_value, 0)
        self.tap.load_ir(0x2d1)
        time.sleep(1)
        self.read_fuse_into_4k_bit_buffer()
        test_reg_value = self.configure_tck_on_fuse_read(test_reg_value, 1)
        fuse_data_after_burn = self.read_fuse_4k_bit_buffer()
        print("configuring the TAP's TESTREG to its default value...")
        self.tap.load_ir_dr_no_tdo(0x2b4, 1028, self.default_test_reg_value)
        print("===========================================")
        print("fuse_data before burn =", hex(fuse_data_before_burn))
        print("fuse_data after  burn =", hex(fuse_data_after_burn))
        print("data to burn   =", hex(write_data))
        print("fuse_data diff =", hex(fuse_data_before_burn ^ fuse_data_after_burn))


if __name__ == '__main__':
    f = fuse()
    f.read_fuse()
