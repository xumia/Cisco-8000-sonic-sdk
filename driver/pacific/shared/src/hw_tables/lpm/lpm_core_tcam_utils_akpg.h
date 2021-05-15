// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
//
// This file and all technical concepts, proprietary knowledge, algorithms and
// intellectual property rights it contains (collectively the "Confidential Information"),
// are the sole propriety information of Cisco and shall remain at Cisco's ownership.
// You shall not disclose the Confidential Information to any third party and you
// shall use it solely in connection with operating and/or maintaining of Cisco's
// products and pursuant to the terms and conditions of the license agreement you
// entered into with Cisco.
//
// THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
// IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// END_LEGAL

#ifndef __LEABA_LPM_CORE_TCAM_UTILS_AKPG_H__
#define __LEABA_LPM_CORE_TCAM_UTILS_AKPG_H__

#include "lpm_core_tcam_utils_base.h"

namespace silicon_one
{

class lpm_core_tcam_utils_akpg : public lpm_core_tcam_utils_base
{
public:
    ///@brief Default constructor.
    lpm_core_tcam_utils_akpg() = default;

    // lpm_core_tcam_utils_base API
    logical_tcam_type_e get_logical_tcam_type_of_key(const lpm_key_t& key) const override;

}; // namespace lpm_core_tcam_utils_akpg

} // namespace silicon_one

#endif // __LEABA_LPM_CORE_TCAM_UTILS_AKPG_H__
