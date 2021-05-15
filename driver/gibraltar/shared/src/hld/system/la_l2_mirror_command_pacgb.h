// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_L2_MIRROR_COMMAND_PACGB_H__
#define __LA_L2_MIRROR_COMMAND_PACGB_H__

#include "la_l2_mirror_command_base.h"

namespace silicon_one
{

class la_l2_mirror_command_pacgb : public la_l2_mirror_command_base
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    //////////////////////////////
public:
    explicit la_l2_mirror_command_pacgb(const la_device_impl_wptr& device);
    ~la_l2_mirror_command_pacgb() override;

protected:
    la_l2_mirror_command_pacgb() = default; // Needed for cereal
    la_status configure_rx_obm_punt_src_and_code(uint64_t punt_source, la_voq_gid_t voq_id) const override;
    void populate_rx_obm_code_table_key(la_uint_t mirror_gid, npl_rx_obm_code_table_key_t& out_key) const override;
    la_status configure_mirror_to_dsp_in_npu_soft_header_table(uint8_t value) override;
    la_status teardown_mirror_to_dsp_in_npu_soft_header_table() override;
};

} // namespace silicon_one

#endif // __LA_L2_MIRROR_COMMAND_PACGB_H__
