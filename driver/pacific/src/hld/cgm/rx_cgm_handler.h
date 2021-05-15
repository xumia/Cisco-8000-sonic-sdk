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

#ifndef __RX_CGM_HANDLER_H__
#define __RX_CGM_HANDLER_H__

#include "api/types/la_cgm_types.h"
#include "api/types/la_common_types.h"
#include "api/types/la_qos_types.h"
#include "common/ranged_index_generator.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "lld/pacific_mem_structs.h"
#include "system/slice_manager_smart_ptr_base.h"

/// @file
///
/// @brief La_device_impl's handler for RX CGM configuration.
///
/// Handle la_device's API-s for managing RX CGM device configurations.
/// All threshold API-s operate in bytes, and convert to buffers internally.

namespace silicon_one
{

class rx_cgm_handler
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    enum { LA_RX_CGM_SQ_PROFILE_MAX_ID = 15 };
    enum { LA_RX_CGM_SQ_PROFILE_DEFAULT_ID = LA_RX_CGM_SQ_PROFILE_MAX_ID };

    enum { LA_RX_CGM_MAX_NUM_DROP_COUNTERS = 8 };
    enum { LA_RX_CGM_MAX_NUM_SQ_GROUPS = 4 };

    explicit rx_cgm_handler(const la_device_impl_wptr& device);
    ~rx_cgm_handler();

    // Counter A management
    la_status set_rx_cgm_sms_bytes_quantization(const la_rx_cgm_sms_bytes_quantization_thresholds& thresholds);
    la_status get_rx_cgm_sms_bytes_quantization(la_rx_cgm_sms_bytes_quantization_thresholds& out_thresholds);

    // SQG management
    la_status set_rx_cgm_sqg_thresholds(la_uint_t sqg_index, const la_rx_cgm_sqg_thresholds& thresholds);
    la_status get_rx_cgm_sqg_thresholds(la_uint_t sqg_index, la_rx_cgm_sqg_thresholds& out_thresholds);

    // SQ Profile management
    la_status allocate_rx_cgm_sq_profile_id(la_slice_id_t slice, la_uint_t& out_profile_id);
    la_status release_rx_cgm_sq_profile_id(la_slice_id_t slice, la_uint_t profile_id);
    la_status set_rx_cgm_sq_profile_thresholds(la_slice_id_t slice,
                                               la_uint_t profile_id,
                                               const la_rx_cgm_sq_profile_thresholds& thresholds);
    la_status set_rx_cgm_sq_profile_policy(la_slice_id_t slice,
                                           la_uint_t profile_id,
                                           const la_rx_cgm_policy_status& rx_cgm_status,
                                           bool flow_control,
                                           bool drop_yellow,
                                           bool drop_green,
                                           bool fc_trig);

    // SQ management
    la_status set_rx_cgm_sq_profile_mapping(la_slice_id_t slice,
                                            la_ifg_id_t ifg,
                                            la_uint_t serdes,
                                            la_traffic_class_t tc,
                                            la_uint_t profile_id);
    la_status set_rx_cgm_sq_group_mapping(la_slice_id_t slice,
                                          la_ifg_id_t ifg,
                                          la_uint_t serdes,
                                          la_traffic_class_t tc,
                                          la_uint_t group_index);
    la_status set_rx_cgm_sq_mapping(la_slice_id_t slice,
                                    la_ifg_id_t ifg,
                                    la_uint_t serdes,
                                    la_traffic_class_t tc,
                                    la_uint_t profile_id,
                                    la_uint_t group_index,
                                    la_uint_t counter_index);

    // Counters
    la_status set_rx_cgm_sq_drop_counter_mapping(la_slice_id_t slice,
                                                 la_ifg_id_t ifg,
                                                 la_uint_t serdes,
                                                 la_traffic_class_t tc,
                                                 la_uint_t counter_index);
    la_status read_rx_cgm_drop_counter(la_slice_id_t slice, la_uint_t counter_index, la_uint_t& out_packet_count);

    // Headroom manaagement
    la_status set_rx_cgm_hr_management_mode(la_rx_cgm_headroom_mode_e mode);
    la_status get_rx_cgm_hr_management_mode(la_rx_cgm_headroom_mode_e& out_mode) const;
    la_status set_rx_cgm_hr_timer_or_threshold_value(la_slice_id_t slice, la_uint_t profile_id, la_uint_t hr_value);

    // SQ state
    la_status get_rx_cgm_sq_buffer_count(la_slice_id_t slice,
                                         la_ifg_id_t ifg,
                                         la_uint_t serdes,
                                         la_traffic_class_t tc,
                                         size_t& out_buffers);

private:
    // Device this handler belongs to
    la_device_impl_wptr m_device;

    // The slice id manager of the device
    slice_manager_smart_ptr m_slice_id_manager;

    // Device HR management mode
    la_rx_cgm_headroom_mode_e m_hr_management_mode;

    // Profile ID-s per slice
    std::array<ranged_index_generator, ASIC_MAX_SLICES_PER_DEVICE_NUM> m_profile_id_generator;

    la_status read_profile_map_table_line(la_slice_id_t slice, la_uint_t line, rx_cgm_profile_map_table_memory& out_mem);
    la_status write_profile_map_table_line(la_slice_id_t slice, la_uint_t line, rx_cgm_profile_map_table_memory& mem);

    la_status validate_thresholds(const la_rx_cgm_sq_profile_thresholds& thresholds) const;
    la_status validate_thresholds(const la_rx_cgm_sqg_thresholds& thresholds) const;
    la_status validate_thresholds(const la_rx_cgm_sms_bytes_quantization_thresholds& thresholds) const;

    rx_cgm_handler() = default; // For serialization only.

}; // class rx_cgm_handler

} // namespace silicon_one

#endif // __RX_CGM_HANDLER_H__
