#!/usr/bin/env python3
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

from lpm_hw_source_pacific import lpm_hw_csv_parser as lpm_hw_csv_parser_pacific
from lpm_hw_source_pacific import lpm_hw_device as lpm_hw_device_pacific
from lpm_hw_source_gb import lpm_hw_device as lpm_hw_device_gb
from lpm_hw_source_gb import lpm_hw_csv_parser as lpm_hw_csv_parser_gb
import lpm_hw_to_logic_converter_pacific
import lpm_logical_model
import lpm_hw_to_logic_converter_gb
from lpm_logs_converter import lpm_logs_converter


# @brief Create LPM debug device
# param[in]  lpm_source         lpm_source: la_device or lpm memory dumped to csv.
# param[in]  device_type        lpm_helper.PACIFIC / lpm_helper.GB.
class lpm_helper:
    PACIFIC = "PACIFIC"
    GB = "GB"

    def __init__(self):
        self.device = None

    # @brief Return LPM debug object with LPM's logs as source.
    # param[in] filename LPM's logs.
    # param[in] device type lpm_helper.GB/lpm_helper.PACIFIC
    # param[out] lpm_helper object
    @staticmethod
    def load_from_logs(filename, device_type):
        ret_helper = lpm_helper()
        if device_type not in [lpm_helper.PACIFIC, lpm_helper.GB]:
            raise Exception("Device type must be lpm_helper.PACIFIC or lpm_helper.GB")
        ret_helper.hw_src = None
        ret_helper.converter = lpm_logs_converter(filename)
        return ret_helper

    # @brief Return LPM debug object with csv memory dump as source.
    # param[in] filename LPM's memory as csv.
    # param[in] device type lpm_helper.GB/lpm_helper.PACIFIC
    # param[out] lpm_helper object
    @staticmethod
    def load_from_csv(filename, device_type, extended_tcam=True):
        ret_helper = lpm_helper()
        if device_type not in [lpm_helper.PACIFIC, lpm_helper.GB]:
            raise Exception("Device type must be lpm_helper.PACIFIC or lpm_helper.GB")
        if device_type == lpm_helper.PACIFIC:
            ret_helper.hw_src = lpm_hw_csv_parser_pacific(filename)
            ret_helper.converter = lpm_hw_to_logic_converter_pacific.lpm_hw_to_logic_converter_pacific(
                ret_helper.hw_src, extended_tcam)
        if device_type == lpm_helper.GB:
            ret_helper.hw_src = lpm_hw_csv_parser_gb(filename)
            ret_helper.converter = lpm_hw_to_logic_converter_gb.lpm_hw_to_logic_converter_gb(ret_helper.hw_src, extended_tcam)
        return ret_helper

    # @brief Return LPM debug object with device as source.
    # param[in] device la_device object
    # param[in] device type lpm_helper.GB/lpm_helper.PACIFIC
    # param[out] lpm_helper object
    @staticmethod
    def load_from_live_device(device, device_type, extended_tcam=True):
        if device_type not in [lpm_helper.PACIFIC, lpm_helper.GB]:
            raise Exception("Device type must be lpm_helper.PACIFIC or lpm_helper.GB")

        ret_helper = lpm_helper()

        ret_helper.device = device

        if device_type == lpm_helper.PACIFIC:
            ret_helper.hw_src = lpm_hw_device_pacific(device)
            ret_helper.converter = lpm_hw_to_logic_converter_pacific.lpm_hw_to_logic_converter_pacific(
                ret_helper.hw_src, extended_tcam)
        if device_type == lpm_helper.GB:
            ret_helper.hw_src = lpm_hw_device_gb(device)
            ret_helper.converter = lpm_hw_to_logic_converter_gb.lpm_hw_to_logic_converter_gb(ret_helper.hw_src, extended_tcam)
        return ret_helper

    # @brief Return a logical lpm model created from the HW source.
    # param[out] lpm_logical_model
    # Usage examples:
    # print(model.distributor[0].key)
    # print(model.cores[0].l2_buckets[0].entries)
    # model.lookup(44,"192.168.2.1",verbosity=3) (vrf,ip_str,verbosity)
    def get_lpm_model(self):
        ret_model = lpm_logical_model.lpm_logical_model(self.converter)
        return ret_model

    # @brief Dump the LPM's memory into csv file.
    # param[in]  output_file                  CSV filename.
    # param[in]  print_hbm                    True/False whether to print the HBM data or not.
    # param[in]  print_hbm_replicas           True/False whether to print the HBM replicas or not, if False the equalty of the replicas will be asserted.
    # Supports only GB la_device as HW source.
    def read_lpm_memory(self, output_file="lpm_data.csv", print_hbm=True, print_hbm_replicas=False):
        if self.device is None:
            print("lpm_helper wasn't initiated with HW device, can't print memory.")
            return
        self.hw_src.read_lpm_memory(output_file, print_hbm=print_hbm, print_hbm_replicas=print_hbm_replicas)
