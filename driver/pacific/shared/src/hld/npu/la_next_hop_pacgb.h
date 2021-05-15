// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_NEXT_HOP_PACGB_H__
#define __LA_NEXT_HOP_PACGB_H__

#include "la_next_hop_base.h"

namespace silicon_one
{

class la_next_hop_pacgb : public la_next_hop_base
{
    friend class la_next_hop_impl_common;
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_next_hop_pacgb(const la_device_impl_wptr& device);
    ~la_next_hop_pacgb() override;

protected:
    la_next_hop_pacgb() = default;
    // Resolution API helpers
    // General functions

    /// Next-hop table entry
    npl_egress_nh_and_svi_direct0_table_entry_wptr_t m_nh_direct0_entry[NUM_SLICE_PAIRS_PER_DEVICE];
    npl_egress_nh_and_svi_direct1_table_entry_wptr_t m_nh_direct1_entry[NUM_SLICE_PAIRS_PER_DEVICE];

    // Manage the TX table
    la_status configure_global_tx_tables() override;
    la_status do_configure_global_tx_tables(la_slice_pair_id_t slice_pair) override;
    la_status update_global_tx_tables() override;
    la_status do_update_global_tx_tables(la_slice_pair_id_t slice_pair) override;
    la_status teardown_global_tx_tables() override;
    la_status do_teardown_global_tx_tables(la_slice_pair_id_t slice_pair) override;
};

} // namesapce leaba

#endif // __LA_NEXT_HOP_PACGB_H__
