// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

//
// Implementation of common parts of multicast-group configurations. Mainly managing the EM MC DB.
//

#ifndef __LA_MULTICAST_GROUP_PLGR_H__
#define __LA_MULTICAST_GROUP_PLGR_H__

#include "hld_types.h"
#include "hld_types_fwd.h"
#include "la_multicast_group_common_akpg.h"
#include "nplapi/npl_constants.h"
#include "nplapi/npl_types.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

class la_multicast_group_common_plgr : public la_multicast_group_common_akpg
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    explicit la_multicast_group_common_plgr(la_device_impl_wptr device);
    la_multicast_group_common_plgr() = default; // needed for cereal
    ~la_multicast_group_common_plgr() override;

protected:
    void populate_mc_em_db_tx_format_0_value(bool is_0,
                                             uint64_t tc_map_profile,
                                             uint64_t oq_group,
                                             uint64_t mc_copy_id,
                                             npl_mc_em_db_value_t& out_value);

private:
    la_status remove_entry_from_mc_em_db_tx_format_0(size_t member_index, npl_mc_em_db_key_t key) override;
    la_status update_entry_in_mc_em_db_tx_format_0(npl_mc_em_db_entry_wptr_t entry,
                                                   size_t member_index_in_entry,
                                                   const npl_mc_em_db_value_t& value,
                                                   size_t member_index_in_value) override;

    // Ingress replication helper functions
    la_status insert_entry_to_mc_em_db_rx_result(uint64_t member_index,
                                                 uint64_t slice,
                                                 uint64_t tc_map_profile,
                                                 uint64_t base_voq_nr,
                                                 uint64_t member_mcid,
                                                 npl_mc_em_db_entry_wptr_t& out_entry) override;
    void populate_mc_em_db_rx_result_value(bool is_0,
                                           uint64_t tc_map_profile,
                                           uint64_t base_voq_nr,
                                           uint64_t member_mcid,
                                           npl_mc_em_db_value_t& out_value) override;
    la_status update_entry_in_mc_em_db_rx_result(la_slice_id_t slice,
                                                 size_t dst_index,
                                                 npl_mc_em_db_entry_wptr_t& dst_entry,
                                                 size_t src_index,
                                                 npl_mc_em_db_entry_wptr_t& src_entry) override;
    la_status remove_entry_from_mc_em_db_rx_result(la_slice_id_t slice,
                                                   size_t member_index,
                                                   npl_mc_em_db_entry_wptr_t& entry) override;
};

} // namespace silicon_one

#endif // __LA_MULTICAST_GROUP_PLGR_H__
