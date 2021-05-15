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

#ifndef __LA_SLICE_MAPPER_BASE_H__
#define __LA_SLICE_MAPPER_BASE_H__

#include "api/types/la_common_types.h"
#include "common/cereal_utils.h"
#include "device_context/la_slice_mapper.h"
#include "slice_mapping_types.h"
#include <memory>
#include <vector>

struct json_t;

namespace silicon_one
{

class la_slice_mapper_base : public la_slice_mapper
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    la_slice_mapper_base(const la_slice_id_vec_t& active_slices, size_t num_slices_per_device, size_t num_ifgs_per_slice);
    virtual ~la_slice_mapper_base();

    virtual la_status initialize(std::string map_file_path, bool use_mapping);

    /// mapping functions

    /// @brief
    la_slice_pair_id_t map_slice_pair(la_slice_pair_id_t id) const override;
    la_slice_pair_id_t map_back_slice_pair(la_slice_pair_id_t id) const override;

    la_slice_id_t map_slice(la_slice_id_t id) const override;
    la_slice_id_t map_back_slice(la_slice_id_t id) const override;

    la_status map_slice_ifg(la_slice_ifg& ifg) const override;
    la_status map_back_slice_ifg(la_slice_ifg& ifg) const override;

    la_status map_serdices(la_slice_serdices& map_this) const override;
    la_status map_back_serdices(la_slice_serdices& map_this) const override;

    la_status map_pif(la_slice_pif& map_this) const override;
    la_status map_back_pif(la_slice_pif& map_this) const override;

    virtual la_slice_serdices map_pif_to_serdes(const la_slice_pif& pif_dat) const;
    virtual la_slice_pif map_serdes_to_pif(const la_slice_serdices& serdes_dat) const;

    /// @brief a vector of indices of all the slices that are not diabled.
    /// each index is <num_slices_per_device()
    virtual const la_slice_id_vec_t& get_used_slices_internal() const;

    /// @brief a vector of indices of all the slices that are not diabled.
    /// bascily, each index is <num_enabled_slices()/2
    virtual const la_slice_id_vec_t& get_used_slices() const;

    bool is_mapping_active() const override;

    size_t max_num_slices_per_device() const override;

protected:
    la_slice_mapper_base() = default;
    size_t m_num_mappable_ifgs;
    size_t m_num_mappable_slices;
    size_t m_num_mappable_pairs;
    la_slice_id_vec_t m_enabled_slices;
    la_slice_id_vec_t m_enabled_slices_logical;

    la_status read_slice_pairs_mapping(json_t* j_root);
    la_status read_ifg_mapping(json_t* j_root, slice_mapping& back_map, slice_mapping& s_map);
    la_status read_slice_mapping(json_t* j_root);
    la_status read_mapping_from_file(std::string file_name);

    bool m_use_mapping;
    std::vector<slice_mapping> m_slice_mappings;
    std::vector<slice_mapping> m_back_slice_mappings;
    std::vector<single_idx_mapping> m_slice_pair_map;
    std::vector<single_idx_mapping> m_slice_pair_map_back;
};

} // namespace silicon_one

#endif // __LA_SLICE_MAPPER_BASE_H__
