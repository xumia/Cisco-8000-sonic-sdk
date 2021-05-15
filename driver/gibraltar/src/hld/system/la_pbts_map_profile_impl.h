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

#ifndef __LA_PBTS_MAP_PROFILE_IMPL_H__
#define __LA_PBTS_MAP_PROFILE_IMPL_H__

/// @file
/// @brief Leaba PBTS Map Profile
#include <memory>

#include "api/system/la_pbts_map_profile.h"
#include "api/types/la_common_types.h"
#include "common/cereal_utils.h"
#include "hld_types.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_device_impl;

class la_pbts_map_profile_impl : public la_pbts_map_profile
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_pbts_map_profile_impl() = default;
    //////////////////////////////

public:
    explicit la_pbts_map_profile_impl(const la_device_impl_wptr& device);
    ~la_pbts_map_profile_impl() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, la_pbts_map_profile::level_e level, la_pbts_destination_offset max_offset);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Inherited API-s
    la_status set_mapping(la_fwd_class_id fcid, la_pbts_destination_offset offset) override;
    la_status get_mapping(la_fwd_class_id fcid, la_pbts_destination_offset& out_pbts_offset) const override;
    la_status get_size(la_pbts_destination_offset& out_max_offset) const override;
    la_status get_level(la_pbts_map_profile::level_e& out_level) const override;
    la_status get_profile_id(uint64_t& out_profile_id) const override;
    enum {
        FCID_MAX_ID = 8,
    };

private:
    la_status program_mapping_table(la_fwd_class_id fcid, la_pbts_destination_offset offset);
    bool valid_user_destinations(la_pbts_destination_offset offset);
    la_status clear_profile();
    // Device this object is created on.
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // Resolution level
    la_pbts_map_profile::level_e m_level;

    // Maximum offset supported in destinations
    la_pbts_destination_offset m_max_offset = {.value = FCID_MAX_ID - 1};

    // Mappings FCID -> offset
    la_pbts_destination_offset m_mapping[FCID_MAX_ID] = {{.value = 0}};

    // Profile ID.
    uint64_t m_profile_id;
};
}

/// @}

#endif // __LA_PBTS_MAP_PROFILE_IMPL_H__
