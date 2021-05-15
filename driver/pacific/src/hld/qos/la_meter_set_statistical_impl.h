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

#ifndef __LA_METER_SET_STATISTICAL_IMPL_H__
#define __LA_METER_SET_STATISTICAL_IMPL_H__

#include "api/qos/la_meter_set.h"
#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"
#include "api/types/la_system_types.h"
#include "hld_types_fwd.h"
#include "la_meter_action_profile_impl.h"
#include "la_meter_profile_impl.h"
#include "la_meter_set_exact_impl.h"
#include "la_meter_set_impl.h"
#include "lld/pacific_mem_structs.h"
#include "nplapi/nplapi_tables.h"
#include "system/counter_allocation.h"
#include "system/counter_manager.h"

#include <map>
#include <memory>

namespace silicon_one
{

class la_meter_set_statistical_impl : public la_meter_set_impl
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_meter_set_statistical_impl(const la_device_impl_wptr& device);
    ~la_meter_set_statistical_impl() override;
    la_status initialize(la_object_id_t oid, type_e meter_type, size_t size) override;

    // la_meter_set API-s
    using la_meter_set_impl::set_cir;
    la_status set_cir(size_t meter_index, la_slice_ifg ifg, la_rate_t cir) override;
    using la_meter_set_impl::get_cir;
    la_status get_cir(size_t meter_index, la_slice_ifg ifg, la_rate_t& out_cir) const override;
    using la_meter_set_impl::set_eir;
    la_status set_eir(size_t meter_index, la_slice_ifg ifg, la_rate_t eir) override;
    using la_meter_set_impl::get_eir;
    la_status get_eir(size_t meter_index, la_slice_ifg ifg, la_rate_t& out_eir) const override;

    // la_meter_set_impl API-s
    la_status get_counter(la_counter_set*& out_counter) const override;
    la_status read(size_t counter_index,
                   bool force_update,
                   bool clear_on_read,
                   la_qos_color_e color,
                   size_t& out_packets,
                   size_t& out_bytes) override;
    la_status read(la_slice_ifg ifg, size_t counter_index, la_qos_color_e color, size_t& out_packets, size_t& out_bytes) override;
    la_status get_allocation(la_slice_ifg slice_ifg, counter_allocation& out_allocation) const override;

    la_status notify_change(dependency_management_op op) override;
    const la_meter_set_exact_impl_wptr& get_exact_meter_set_as_counter() const;
    float get_shaper_max_rate(size_t meter_index, bool is_cir) const override;

protected:
    // do_API_functions
    la_status do_set_cir(size_t meter_index) override;
    la_status do_set_eir(size_t meter_index) override;
    la_status do_set_meter_profile(size_t meter_index, const la_meter_profile_impl_wptr& meter_profile_impl) override;
    la_status do_set_meter_action_profile(size_t meter_index,
                                          const la_meter_action_profile_impl_wptr& meter_action_profile_impl) override;
    la_status do_set_committed_bucket_coupling_mode(size_t meter_index, coupling_mode_e coupling_mode) override;
    la_status do_attach_user(const la_object_wcptr& user, bool is_aggregate) override;
    la_status do_detach_user(const la_object_wcptr& user) override;
    la_status do_detach_meter_profile(size_t meter_index) override;
    la_status do_detach_meter_action_profile(size_t meter_index) override;

    // Configuring tables functions.
    la_status configure_meter_state_entry(la_slice_ifg ifg, size_t meter_index) override;
    la_status configure_meters_attribute_entry(la_slice_ifg ifg, size_t meter_index) override;
    la_status erase_meters_attribute_entry(la_slice_ifg ifg, size_t meter_index) override;
    la_status configure_meter_shaper_configuration_entry(la_slice_ifg ifg, size_t meter_index) override;
    la_status erase_meter_shaper_configuration_entry(la_slice_ifg ifg, size_t meter_index) override;
    la_status configure_meters_table_entry(la_slice_ifg ifg, size_t meter_index) override;

    void get_bank_and_base_index(la_slice_ifg ifg, size_t& bank_index, size_t& set_base_index) const override;
    la_status get_meter_profile_allocation(la_slice_ifg ifg, size_t meter_index, size_t& out_index) const override;
    la_status get_meter_action_profile_allocation(la_slice_ifg ifg, size_t meter_index, size_t& out_index) const override;

private:
    enum {
        INVALID_INDEX = (size_t)-1,
        DEFAULT_TOKEN_SIZE = 1,
        TOKEN_SIZE_RESOLUTION = 64,
    };

    static constexpr float SHAPER_DISTRIBUTION_RATE_PER_CLOCK = 1.0 / 8.0;

    struct meters_token_entry_details_t {
        size_t line_index;
        size_t entry_index;
        size_t cir_msb;
        size_t cir_lsb;
        size_t eir_msb;
        size_t eir_lsb;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(meters_token_entry_details_t)

    struct meter_token_size_data {
        size_t cir_token_size = DEFAULT_TOKEN_SIZE;
        size_t eir_token_size = DEFAULT_TOKEN_SIZE;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(meter_token_size_data)

    la_status configure_meters_token_table(size_t meter_index);
    meters_token_entry_details_t get_meters_token_table_entry_details(size_t meter_index) const;
    la_status do_allocation();
    la_status release_allocation();
    bool is_allocated() const;
    la_status alloc_exact_meter_set_as_counter(la_meter_set_exact_impl_wptr& out_exact_meter_set_impl);

    la_status wait_until_meter_is_full();

    // The bank index of this meter set
    size_t m_bank_index;

    // The base index of this set in the bank.
    size_t m_set_base_index;

    std::vector<meter_token_size_data> m_token_sizes;

    float m_shaper_tokens_per_sec;

    // Exact meter_set for statistical counter purpose
    la_meter_set_exact_impl_wptr m_exact_meter_set_impl;

    la_meter_set_statistical_impl() = default; // For serialization purposes only.
};                                             // class la_meter_set_statistical

} // namespace silicon_one

#endif // __LA_METER_SET_STATISTICAL_IMPL_H__
