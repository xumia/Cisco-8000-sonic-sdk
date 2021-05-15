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

#ifndef __LA_METER_SET_IMPL_H__
#define __LA_METER_SET_IMPL_H__

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"
#include "api/types/la_system_types.h"
#include "common/defines.h"
#include "hld_types_fwd.h"
#include "la_meter_action_profile_impl.h"
#include "la_meter_profile_impl.h"
#include "lld/pacific_mem_structs.h"
#include "nplapi/nplapi_tables.h"
#include "qos/la_meter_set_base.h"
#include "system/counter_manager.h"
#include "system/slice_manager_smart_ptr_base.h"

#include <map>
#include <memory>

namespace silicon_one
{

class la_meter_set_impl : public la_meter_set_base
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_meter_set_impl(const la_device_impl_wptr& device);
    ~la_meter_set_impl() override;
    virtual la_status initialize(la_object_id_t oid, type_e meter_type, size_t size);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Dependency management
    virtual la_status notify_change(dependency_management_op op) = 0;

    // la_meter_set API-s
    size_t get_set_size() const override;
    type_e get_type() const override;
    la_status set_meter_profile(size_t meter_index, const la_meter_profile* meter_profile) override;
    la_status get_meter_profile(size_t meter_index, const la_meter_profile*& out_meter_profile) const override;
    la_status set_meter_action_profile(size_t meter_index, const la_meter_action_profile* meter_action_profile) override;
    la_status get_meter_action_profile(size_t meter_index, const la_meter_action_profile*& out_meter_action_profile) const override;
    la_status set_committed_bucket_coupling_mode(size_t meter_index, coupling_mode_e coupling_mode) override;
    la_status get_committed_bucket_coupling_mode(size_t meter_index, coupling_mode_e& out_coupling_mode) const override;
    la_status set_cir(size_t meter_index, la_rate_t cir) override;
    la_status get_cir(size_t meter_index, la_rate_t& out_cir) const override;
    la_status set_eir(size_t meter_index, la_rate_t eir) override;
    la_status get_eir(size_t meter_index, la_rate_t& out_eir) const override;
    la_status attach_user(const la_object_wcptr& user, bool is_aggregate, bool is_lpts_entry_meter = false);
    la_status detach_user(const la_object_wcptr& user);

    // Get allocation index in bank
    virtual la_status get_allocation(la_slice_ifg slice_ifg, counter_allocation& out_allocation) const = 0;

    enum {
        TRAFFIC_ALLOWED = 1,
        NUM_SHAPER_PER_EXACT_METERS_BLOCK = 3,
        FIRST_EXACT_METER_BANK_INDEX = 96,
        METER_SET_SIZE_GROUPING = 2, // Meter allocations are done in multiples of this value
        NUM_STATISTICAL_METERS_PER_BANK = 2 * 1024,
        FIRST_STATISTICAL_METER_BANK_INDEX = FIRST_EXACT_METER_BANK_INDEX + 12,
        BUCKET_WIDTH = 22,
    };

    virtual float get_shaper_max_rate(size_t meter_index, bool is_cir) const;

protected:
    la_slice_ifg SINGLE_ALLOCATION_SLICE_IFG;
    static constexpr size_t SINGLE_ALLOCATION_IFG = 0;
    static constexpr la_rate_t FAST_REFILL_RATE = 1000000000;

    // Meter properties, for type::EXACT only cir/eir[SINGLE_ALLOCATION_IFG] will be configured and will describe all ifgs.
    struct meter_properties {
        la_meter_profile_impl_wptr meter_profile = nullptr;
        la_meter_action_profile_impl_wptr meter_action_profile = nullptr;
        coupling_mode_e coupling_mode = coupling_mode_e::NOT_COUPLED;
        npl_meter_weight_t cir_weight[NUM_IFGS_PER_DEVICE] = {};
        npl_meter_weight_t eir_weight[NUM_IFGS_PER_DEVICE] = {};
        la_rate_t user_cir[NUM_IFGS_PER_DEVICE] = {};
        la_rate_t user_eir[NUM_IFGS_PER_DEVICE] = {};
        size_t meter_offset_index;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(meter_properties)

    // Abstract do_API_functions
    virtual la_status do_set_cir(size_t meter_index) = 0;
    virtual la_status do_set_eir(size_t meter_index) = 0;
    virtual la_status do_set_meter_profile(size_t meter_index, const la_meter_profile_impl_wptr& meter_profile_impl) = 0;
    virtual la_status do_set_meter_action_profile(size_t meter_index,
                                                  const la_meter_action_profile_impl_wptr& meter_action_profile_impl)
        = 0;
    virtual la_status do_set_committed_bucket_coupling_mode(size_t meter_index, coupling_mode_e coupling_mode) = 0;
    virtual la_status do_attach_user(const la_object_wcptr& user, bool is_aggregate) = 0;
    virtual la_status do_detach_user(const la_object_wcptr& user) = 0;

    // Meter_state_table, meters_attribute_table, meter_shaper_configuration_table
    virtual la_status configure_meter_state_entry(la_slice_ifg ifg, size_t meter_index) = 0;
    virtual la_status erase_meter_state_entry(la_slice_ifg ifg, size_t meter_index);
    virtual la_status configure_meters_attribute_entry(la_slice_ifg ifg, size_t meter_index) = 0;
    virtual la_status erase_meters_attribute_entry(la_slice_ifg ifg, size_t meter_index) = 0;
    virtual la_status configure_meter_shaper_configuration_entry(la_slice_ifg ifg, size_t meter_index) = 0;
    virtual la_status erase_meter_shaper_configuration_entry(la_slice_ifg ifg, size_t meter_index) = 0;
    virtual la_status configure_meters_table_entry(la_slice_ifg ifg, size_t meter_index) = 0;
    virtual la_status erase_meters_table_entry(la_slice_ifg ifg, size_t meter_index);

    virtual void get_bank_and_base_index(la_slice_ifg ifg, size_t& bank_index, size_t& set_base_index) const = 0;
    virtual la_status get_meter_profile_allocation(la_slice_ifg ifg, size_t meter_index, size_t& out_index) const = 0;
    virtual la_status get_meter_action_profile_allocation(la_slice_ifg ifg, size_t meter_index, size_t& out_index) const = 0;

    la_status populate_weight_from_cir_or_eir(size_t meter_index,
                                              la_rate_t rate,
                                              bool is_cir,
                                              npl_meter_weight_t& out_weight) const;
    la_status populate_cir_or_eir_from_weight(size_t meter_index,
                                              npl_meter_weight_t weight,
                                              bool is_cir,
                                              la_rate_t& out_rate) const;

    // Template function to populate tables structs
    template <typename _Key>
    void populate_general_key(la_slice_ifg ifg, size_t meter_index, _Key& key) const;

    template <typename _Payload>
    la_status populate_meters_attribute_payload(la_slice_ifg ifg, size_t meter_index, _Payload& payload) const;

    template <typename _EntryType>
    la_status populate_meter_state_entry(la_slice_ifg ifg, size_t meter_index, _EntryType& entry) const;

    template <typename _Payload>
    la_status populate_meter_shaper_configuration_payload(la_slice_ifg ifg, size_t meter_index, _Payload& payload) const;

    template <typename _EntryType>
    la_status do_configure_meters_table_entry(la_slice_ifg ifg,
                                              size_t meter_index,
                                              lld_memory_scptr meters_table,
                                              size_t line_index);

    bool is_supported_user(const la_object_wcptr& user, bool is_lpts_entry_meter) const;
    bool is_lpts_entry_meter() const;

    npl_meter_weight_t la_rate_2_npl_meter_weight(la_rate_t rate, float shaper_max_rate) const;
    la_rate_t npl_meter_weight_2_la_rate(npl_meter_weight_t weight, float shaper_max_rate) const;

    virtual la_status configure_metering(la_slice_ifg ifg);
    virtual la_status erase_metering(la_slice_ifg ifg);

    virtual la_status detach_meter_profile(size_t meter_index);
    virtual la_status detach_meter_action_profile(size_t meter_index);
    virtual la_status do_detach_meter_profile(size_t meter_index) = 0;
    virtual la_status do_detach_meter_action_profile(size_t meter_index) = 0;

    // Check whether a port meter's set-size is adequate
    bool is_valid_set_size(const la_object_wcptr& user, bool is_lpts_entry_meter) const;

    bool is_initialized() const;

    la_rate_t user_rate_to_meter_rate(size_t meter_index, la_rate_t rate) const;
    la_rate_t meter_rate_to_user_rate(size_t meter_index, la_rate_t rate) const;

    la_status validate_meter_profile(size_t meter_index, const la_meter_profile_impl_wcptr& meter_profile);
    la_status validate_coupling_mode(const la_meter_profile_impl_wcptr& meter_profile, coupling_mode_e coupling_mode);

    // Containing device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Meter type
    type_e m_meter_type;

    size_t m_set_size;

    // meter properties vector
    std::vector<meter_properties> m_meters_properties;

    // The meter's users, the value of the map indicates if the user is aggregated.
    std::map<la_object_wcptr, bool> m_user_to_aggregation;

    // Physical meter descriptors, mapped by slice-pair-id
    std::vector<std::unique_ptr<counter_allocation> > m_allocations;

    bool m_lpts_entry_meter;

    la_meter_set_impl() = default; // For serialization purposes only.

}; // class la_meter_set

} // namespace silicon_one

#endif // __LA_METER_SET_IMPL_H__
