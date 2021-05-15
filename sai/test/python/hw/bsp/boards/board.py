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

"""
#!/usr/bin/env python3

file for defining board class
"""


class BaseBoard:
    def __init__(self, base_clock):
        self.port_mix = {}
        self.fpga_version = None
        self.device_core_freq = base_clock
        self.voltage = -1.0

    def get_device_ip(self):
        pass

    def enable_optical_trx(self):
        raise NotImplementedError

    def get_serdes_cfg_file_path(self):
        raise NotImplementedError

    def enable_device_clocks(self, enable):
        raise NotImplementedError

    def device_power_up(self, load_pcie_fw= True):
        raise NotImplementedError

    def device_power_down(self):
        raise NotImplementedError

    def device_reset(self):
        raise NotImplementedError

    def device_non_graceful_reset(self, init_device_and_ports):
        raise NotImplementedError

    def device_out_of_reset(self):
        raise NotImplementedError

    def to_string(self):
        return ""

    def get_temp(self):
        pass

    def get_power(self):
        pass

    def get_fpga_version(self):
        pass

    def set_voltage(self, ps_name, voltage):
        pass

    def set_core_freq(self, freq):
        return self.device_core_freq

    def destroy(self):
        pass
