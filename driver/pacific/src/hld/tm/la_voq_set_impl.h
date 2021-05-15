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

#ifndef __LA_VOQ_SET_IMPL_H__
#define __LA_VOQ_SET_IMPL_H__

#include <vector>

#include "api/types/la_tm_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"
#include "system/la_device_impl.h"
#include "tm/la_voq_set_base.h"

#include "lld/lld_memory.h"

namespace silicon_one
{

class la_device_impl;
class la_voq_cgm_profile;
class la_voq_cgm_profile_impl;
class la_counter_set_impl;

class la_voq_set_impl : public la_voq_set_base
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_voq_set_impl(const la_device_impl_wptr& device);
    ~la_voq_set_impl() override;

    // Lifecycle
    la_status initialize(la_object_id_t oid,
                         la_voq_gid_t base_voq_id,
                         size_t set_size,
                         la_vsc_gid_vec_t base_vsc_vec,
                         la_device_id_t dest_device,
                         la_slice_id_t dest_slice,
                         la_ifg_id_t dest_ifg);
    la_status destroy(bool ignore_active_not_empty);

    // la_voq_set API-s

    la_vsc_gid_vec_t get_base_vsc_vec() const override;
    la_status get_base_vsc(la_slice_id_t slice, la_vsc_gid_t& out_base_vsc) const override;
    la_status set_cgm_profile(size_t voq_index, la_voq_cgm_profile* cgm_profile) override;
    la_status get_cgm_profile(size_t voq_index, la_voq_cgm_profile*& out_cgm_profile) const override;
    la_status flush(bool block) override;
    la_status flush(size_t voq_index, bool block) override;
    la_status read_flush_counter(bool clear_on_read, la_uint64_t& out_packets, la_uint64_t& out_bytes) override;
    la_status read_flush_counter(size_t voq_index, bool clear_on_read, la_uint64_t& out_packets, la_uint64_t& out_bytes) override;
    la_status restore(size_t voq_index) override;
    la_status is_empty(bool& out_empty) const override;
    la_status is_empty(size_t voq_index, bool& out_empty) const override;
    la_status get_voq_size(size_t voq_index, la_slice_id_t slice, voq_size& out_size) const override;
    la_status get_voq_age(size_t voq_index, la_slice_id_t slice, size_t& out_age) const override;
    la_status set_fabric_priority(size_t voq_index, bool is_high_priority) override;
    la_status get_fabric_priority(size_t voq_index, bool& out_is_high_priority) const override;
    la_status set_state(state_e state) override;
    la_status set_state(size_t voq_index, state_e state) override;
    la_status get_state(state_e& out_state) const override;
    la_status get_state(size_t voq_index, state_e& out_state) const override;
    la_status set_counter(la_voq_set::voq_counter_type_e type, size_t group_size, la_counter_set* counter) override;
    la_status get_counter(la_voq_set::voq_counter_type_e& out_voq_counter_type,
                          size_t& out_group_size,
                          la_counter_set*& out_counter) const override;

    // la_object API-s
    la_object::object_type_e type() const override;
    std::string to_string() const override;

    // la_voq_set_impl API-s
    la_status force_local_voq_enable(bool enable);

    /// @brief Check if all VOQ-s have VOQ CGM profile
    ///
    /// @return True if all VOQ-s have profiles, false otherwise.
    bool all_cgm_profiles_assigned() const;

    /// @brief Check if VOQ_SET is during flush process.
    ///
    /// @return True if VOQ_SET is during flush process, false otherwise.
    bool is_during_flush() const;

private:
    // HW properties of context ID
    struct context_hw_id {
        size_t id;   //< Context ID
        size_t line; //< Line in memory that context data will be presented at.
        size_t bit;  //< Index in memory that context data will be presented at.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(context_hw_id);

    enum {
        // Invalid device ID - used for flushing on LC systems
        INVALID_DEST_DEV = la_device_impl::MAX_DEVICES,

        // Disabled OQ used for flushing on standalone systems
        DISABLED_PORT = RECYCLE_PIF_ID,
        DISABLED_PORT_SLICE_ID = 0,

        // OQ counter used for flush accounting
        FLUSH_OQ_CTR_INDEX = 1,
    };

    // Helper functions
    void get_voq_map_info(la_voq_gid_t voq, la_slice_id_t slice, lld_memory_scptr& out_voq_mem, size_t& out_line) const;
    void get_dev_dest_map_info(la_voq_gid_t voq, la_slice_id_t slice, lld_memory_scptr& out_dev_mem, size_t& out_line) const;

    la_status set_dynamic_cgm_profile(size_t voq_index, uint64_t cgm_profile_id);
    la_status set_dynamic_cgm_profile_per_slice(size_t voq_index,
                                                uint64_t cgm_profile_id,
                                                la_slice_id_t slice_id,
                                                uint64_t& out_orig_pool_ret_th,
                                                bool& out_orig_pool_ret_th_valid,
                                                uint64_t& out_original_fullness,
                                                bool& out_is_original_fullness_valid);
    la_status set_context_pool_ret_th(la_slice_id_t slice, uint64_t new_val, uint64_t& out_old_val, bool& out_old_val_valid);
    la_status establish_voq2context_mapping(size_t voq_index,
                                            la_slice_id_t slice,
                                            bool& out_is_voq_mapped,
                                            uint64_t& out_voq2context,
                                            uint64_t& orig_pool_ret_th,
                                            bool& orig_pool_ret_th_valid);
    la_status update_ics_queue_profile(uint64_t cgm_profile_num, la_slice_id_t slice, uint64_t voq_context);
    la_status update_pdvoq_voqcgm_profile(uint64_t cgm_profile_num, la_slice_id_t slice, uint64_t voq_context);
    la_status establish_context2dram_context_mapping(la_slice_id_t slice,
                                                     uint64_t voq_context,
                                                     uint64_t& out_original_fullness,
                                                     bool& out_original_fullness_valid,
                                                     uint64_t& out_dram_context,
                                                     bool& out_dram_context_valid);
    la_status update_dram_contextinfo_table(uint64_t dram_context, uint64_t profile_num, uint64_t voq_context);
    la_status update_pdvoq_slice_almost_full_conf_register(la_slice_id_t slice, uint64_t new_fullness, uint64_t& out_old_fullness);

    la_status do_set_state(state_e state);
    la_status do_flush(bool block);
    la_status do_flush();
    la_status do_flush(size_t voq_index);
    la_status get_flushed_packet_count(size_t& out_packets);
    la_status read_disabled_oq_drop_counter(size_t& out_packets);
    la_status initialize_flush_counters();
    la_status read_txpdr_debug_pd_counter(size_t& out_packets);

    la_status configure_voq_properties_table(size_t voq_index);
    la_status erase_voq_properties_table(size_t voq_index);
    la_status get_pdvoq_voq_scheduling_type(size_t voq_index, uint64_t& out_voq_scheduling_type);
    la_status redirect_voq_to_disabled_dest(size_t start, size_t end);
    la_status return_from_flush(size_t start, size_t end);
    la_status do_get_voq_size(size_t voq_index, la_slice_id_t slice, bool& out_is_in_hbm, voq_size& out_size) const;
    la_status do_get_voq_age(size_t voq_index, la_slice_id_t slice, size_t& out_age) const;
    la_status get_candidate_context_id(size_t voq_index, la_slice_id_t slice, context_hw_id& out_context_id) const;
    la_status verify_context_to_voq(size_t context, size_t voq_index, la_slice_id_t slice, bool& out_match) const;
    la_status get_context_size_in_sms(const context_hw_id& context, la_slice_id_t slice, size_t& out_size) const;
    la_status get_context_size_in_hbm(const context_hw_id& context,
                                      la_slice_id_t slice,
                                      size_t& out_size_blocks,
                                      size_t& out_size_bytes) const;
    la_status is_smscontext_in_hbm(const context_hw_id& context, la_slice_id_t slice, bool& out_is_in_hbm) const;

    la_status attach_voq_flush_vsc(size_t start, size_t end);
    la_status map_voq_to_vsc(la_voq_gid_t base_voq_id,
                             la_vsc_gid_vec_t base_vsc_vec,
                             la_device_id_t dest_device,
                             la_slice_id_t dest_slice,
                             la_ifg_id_t dest_ifg);

    bool is_lc_network_mc_voq_set(size_t voq) const;
    bool is_lc_fabric_mc_voq_set(size_t voq) const;

    bool is_send_to_fabric() const;

    uint64_t get_voq_cgm_profile_id(size_t voq_index) const;

    // Return a string representing the VSC vector
    std::string vsc_vec_to_string();

    // Private members

    // VSC
    la_vsc_gid_vec_t m_base_vsc_vec;

    // State of the VOQ
    state_e m_voq_state;

    // CGM profile
    std::vector<la_voq_cgm_profile_impl_wptr> m_cgm_profiles;

    // Fabric priority
    std::vector<bool> m_is_fabric_high_priority;

    // Force local VOQ - used force a VOQ to be forwarded locally.
    bool m_force_local_voq;

    // Counter
    la_counter_set_impl_wptr m_counter;

    // Set while inside a flush operation
    bool m_is_during_flush_process;
    std::vector<bool> m_indx_is_during_flush_process;

    // Flush operation redirected VOQs
    std::vector<bool> m_voq_redirected;

    // Original VOQ destinations before they were redirected for the flush operation
    std::vector<npl_filb_voq_mapping_t::value_type> m_voq_flush_orig_mappings;

    // Flush counters - vector of (packets, bytes)
    std::vector<std::pair<la_uint64_t, la_uint64_t> > m_flush_counters;

    la_voq_set_impl() = default; // For serialization purposes only.
    // State of the VOQ
    std::vector<state_e> m_per_voq_index_state;

}; // class la_voq_set_impl

} // namespace silicon_one

#endif // __LA_VOQ_SET_IMPL_H__
