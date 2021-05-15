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

from abc import abstractmethod, ABC


class lpm_model_base(ABC):

    # @brief Lookup ip as hardware.
    #
    # param[in]  vrf                VRF number.
    # param[in]  ip_str             IPv6 or IPv4 as string.
    # param[in]  verbosity          Verbosity level (0,1,2)
    # param[out] distributor_row
    # param[out] group_number
    # param[out] core_number
    # param[out] tcam_row
    # param[out] l1_bucket_idx
    # param[out] l1_is_default
    # param[out] l2_bucket_idx
    # param[out] l2_is_default
    # param[out] payload
    @abstractmethod
    def lookup(self, vrf, ip_str, verbosity=1):
        pass

    # @brief Lookup in the lpm distributor
    #
    # @param[in]     key                    key to lookup.
    # @param[out]    distributor_key        The key matches the lookup.
    # @param[out]    distributor_hit_width  Width that matches the key.
    # @param[out]    ret_distributor_row    Row number that matched.
    # @param[out]    ret_group              Group number that matches the hit.
    # @param[out]    distributor_entry      Distributor entry containing key,group,core
    # @param[out]    ret_core               Core number that matches the hit.
    @abstractmethod
    def lookup_distributor(self, key):
        pass

    # @brief Lookup in core's tcam
    #
    # @param[in]     core_idx               Core index.
    # @param[in]     key                    key to lookup.
    # @param[out]    tcam_entry             TCAM entry containing key,payload,hit_width.
    # @param[out]    hit_row_idx            Index of the row that matched.
    @abstractmethod
    def lookup_tcam(self, core_idx, key):
        pass

    # @brief Lookup in L1\L2 given bucket
    #
    # @param[in]     bucket                 L1 \ L2 bucket to look in
    # @param[in]     key                    key to lookup.
    # @param[out]    lpm_entry              LPM entry containing key,valid,payload or None in case of no matching entry
    # In case of no matching entry this function DOES NOT return default value
    @abstractmethod
    def lookup_in_bucket(self, bucket, key):
        pass
