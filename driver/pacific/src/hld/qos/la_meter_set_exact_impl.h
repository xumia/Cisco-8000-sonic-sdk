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

#ifndef __LA_METER_SET_EXACT_IMPL_H__
#define __LA_METER_SET_EXACT_IMPL_H__

#include "api/qos/la_meter_set.h"
#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"
#include "api/types/la_system_types.h"
#include "hld_types_fwd.h"
#include "la_meter_action_profile_impl.h"
#include "la_meter_profile_impl.h"
#include "la_meter_set_impl.h"
#include "lld/pacific_mem_structs.h"
#include "nplapi/nplapi_tables.h"
#include "system/counter_manager.h"

#include <map>
#include <memory>

namespace silicon_one
{

class la_meter_set_exact_impl : public la_meter_set_impl, public dependency_listener
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_meter_set_exact_impl(const la_device_impl_wptr& device);
    ~la_meter_set_exact_impl() override;
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
    void set_counter_user_type(counter_user_type_e type);

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
    la_status wait_until_meter_is_full(la_slice_ifg ifg);
    la_status validate_new_user(const la_object_wcptr& user, bool is_aggregate);
    la_status get_ethernet_port_from_logical_port(const la_object_wcptr& logical_port, la_ethernet_port_wcptr& out_eth_port);
    la_status do_allocation_on_add_ifg(la_slice_ifg ifg, bool slice_pair_added, bool is_aggregate);
    la_status release_allocation_on_remove_ifg(la_slice_ifg ifg, bool slice_pair_removed);
    la_status do_release_allocation(counter_allocation& allocation, la_slice_ifg ifg, bool slice_pair_removed);
    la_status add_ifg(la_slice_ifg ifg, bool is_aggregate);
    la_status remove_ifg(la_slice_ifg ifg);

    la_status get_mem_line_params(la_slice_ifg& ifg,
                                  size_t meter_index,
                                  size_t entries_in_line,
                                  size_t& bank_index,
                                  size_t& table_index,
                                  size_t& mem_line,
                                  size_t& entry_index);

    la_status configure_meter_shaper_configuration_for_used_ifgs(size_t meter_index);

    counter_user_type_e m_counter_user_type = COUNTER_USER_TYPE_METER;
    // Every meter set is associated with a parallel counter set
    la_counter_set_wptr m_counter = nullptr;
    // Cached counters
    typedef std::array<size_t, (size_t)la_qos_color_e::RED + 1> colored_counter_values_t;
    std::vector<colored_counter_values_t> m_cached_packets;
    std::vector<colored_counter_values_t> m_cached_bytes;

    la_meter_set_exact_impl() = default; // For serialization purposes only.
};                                       // class la_meter_set_exact_impl

} // namespace silicon_one

#endif // __LA_METER_SET_EXACT_IMPL_H__
