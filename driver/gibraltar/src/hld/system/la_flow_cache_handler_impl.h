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

#ifndef __LA_FLOW_CACHE_HANDLER_IMPL_H__
#define __LA_FLOW_CACHE_HANDLER_IMPL_H__

#include "api/system/la_flow_cache_handler.h"
#include "api/types/la_common_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"

/// @file @brief La_device_impl's handler for flow cache configuration.
///
/// Handle la_device's API-s for managing a flow cache configurations.

namespace silicon_one
{

class la_flow_cache_handler_impl : public la_flow_cache_handler
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_flow_cache_handler_impl(const la_device_impl_wptr& device);
    ~la_flow_cache_handler_impl();

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_flow_cache_handler API-s
    la_status get_flow_cache_enabled(bool& out_enabled) const override;
    la_status set_flow_cache_enabled(bool enabled) override;
    la_status get_flow_cache_counters(la_flow_cache_handler::flow_cache_counters& out_flow_cache_counters) const override;

private:
    la_flow_cache_handler_impl() = default; // For serialization purposes

    la_status configure_flc_db();
    la_status configure_flc_db_header_types(la_slice_id_t slice_num);
    la_status configure_header_types_to_mask_id(la_slice_id_t slice_num);
    la_status configure_flc_db_masks(la_slice_id_t slice_num);

    la_status clear_all_flc_tables();
    la_status clear_header_types_array_table();
    la_status clear_header_type_mask_id_table();
    la_status clear_header_type_large_mask_table();
    la_status clear_header_type_medium_mask_table();
    la_status clear_header_type_small_mask_table();

    std::vector<std::vector<npl_protocol_type_e> > get_cached_protocol_sequences() const;

    // Device this handler belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    bool m_flow_cache_enabled;
};

} // namespace silicon_one

#endif // __LA_FLOW_CACHE_HANDLER_IMPL_H__
