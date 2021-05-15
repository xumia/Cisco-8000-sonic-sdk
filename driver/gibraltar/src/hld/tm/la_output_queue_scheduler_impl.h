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

#ifndef __LA_OUTPUT_QUEUE_SCHEDULER_IMPL_H__
#define __LA_OUTPUT_QUEUE_SCHEDULER_IMPL_H__

#include "api/tm/la_output_queue_scheduler.h"
#include "common/bit_vector.h"
#include "common/ranged_index_generator.h"

#include "hld_types.h"
#include "hld_types_fwd.h"
#include "lld/lld_memory.h"
#include "lld/lld_register.h"

namespace silicon_one
{

class la_device_impl;

namespace gibraltar
{
union sch_oqse_cfg_memory;
}

class la_output_queue_scheduler_impl : public la_output_queue_scheduler
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_output_queue_scheduler_impl(const la_device_impl_wptr& device,
                                            la_slice_id_t slice_id,
                                            la_ifg_id_t ifg_id,
                                            index_handle index);
    ~la_output_queue_scheduler_impl() = default;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, scheduling_mode_e mode);
    la_status destroy();

    // la_output_queue_scheduler API-s
    la_status get_scheduling_mode(scheduling_mode_e& out_mode) const override;
    la_status set_scheduling_mode(scheduling_mode_e mode) override;
    la_status get_group_weight(la_oqcs_group_id_t group_id, la_wfq_weight_t& out_weight) const override;
    la_status set_group_weight(la_oqcs_group_id_t group_id, la_wfq_weight_t weight) override;
    la_status get_group_actual_weight(la_oqcs_group_id_t group_id, la_wfq_weight_t& out_weight) const override;
    la_status get_attached_vscs(la_vsc_oq_vec_t& out_vsc_vector) const override;
    la_status attach_vsc(la_vsc_gid_t vsc,
                         la_oq_vsc_mapping_e mapping,
                         la_device_id_t ingress_device,
                         la_slice_id_t ingress_slice,
                         la_voq_gid_t ingress_voq_id) override;
    la_status do_attach_vsc(la_vsc_gid_t vsc,
                            la_oq_vsc_mapping_e mapping,
                            la_device_id_t ingress_device,
                            la_slice_id_t ingress_slice,
                            la_voq_gid_t ingress_voq_id);
    la_status detach_vsc(la_vsc_gid_t vsc) override;
    la_status do_detach_vsc(la_vsc_gid_t vsc);
    la_status get_vsc_pir(la_vsc_gid_t vsc, la_rate_t& out_rate) const override;
    la_status set_vsc_pir(la_vsc_gid_t vsc, la_rate_t rate) override;
    la_status do_set_vsc_pir(la_vsc_gid_t vsc, la_rate_t rate);
    la_status get_vsc_burst_size(la_vsc_gid_t vsc, size_t& out_burst) const override;
    la_status set_vsc_burst_size(la_vsc_gid_t vsc, size_t burst) override;
    la_status do_set_vsc_burst_size(la_vsc_gid_t vsc, size_t burst);
    void cache_credit_cir_burst_size(size_t burst);
    size_t get_cached_credit_cir_burst_size() const;
    void cache_credit_eir_or_pir_burst_size(size_t burst);
    size_t get_cached_credit_eir_or_pir_burst_size() const;
    void cache_credit_oq_pir_burst_size(size_t burst);
    size_t get_cached_credit_oq_pir_burst_size() const;
    void cache_transmit_oq_pir_burst_size(size_t burst);
    size_t get_cached_transmit_oq_pir_burst_size() const;
    la_slice_id_t get_slice() const override;
    la_ifg_id_t get_ifg() const override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    int get_oqse_id() const;

    /// @brief Set static-go on all attached VSCs to a reachable remote device, i.e. - grant credits without being asked
    la_status set_static_go(bit_vector& reachable_devices_bv);

    /// @brief Set the scheduler to static-go on a specific VSC, i.e. - grant credits without being asked
    la_status set_static_go(la_vsc_gid_t vsc);

    // Stop static-go: Stop pushing credits from requested VSC
    la_status stop_static_go(la_vsc_gid_t vsc_id);

private:
    // Helper function - attach vcs in CSMS
    la_status attach_vsc_csms(la_vsc_gid_t vsc,
                              la_device_id_t ingress_device,
                              la_slice_id_t ingress_slice,
                              la_voq_gid_t ingress_voq_id);
    // Helper function - attach vcs in SCH
    la_status attach_vsc_sch(la_vsc_gid_t vsc, la_oq_vsc_mapping_e mapping);

    // Helper function - detach vcs in SCH
    la_status detach_vsc_sch(la_vsc_gid_t vsc);

    // Helper function - get attached information from the CSMS
    la_status get_attached_csms(la_vsc_oq& attached_vsc) const;

    // Helper function - write scheduling mode to register
    la_status write_scheduling_mode();

    // @brief Get VOQ memory, device mapping memory and exact line for given VSC.
    void get_dev_voq_map_info(la_vsc_gid_t vsc, lld_memory_sptr& out_dev_mem, lld_memory_sptr& out_voq_mem, size_t& out_line) const;
    // @brief Helper function for populating the VSC->VOQ table value.
    bit_vector populate_vsc_voq_mapping_value(la_voq_gid_t ingress_voq, la_slice_id_t ingress_slice);

    // @brief Helper function for populating sch_oqse_cfg_memory for HW write.
    la_status populate_oqse_cfg(scheduling_mode_e mode, gibraltar::sch_oqse_cfg_memory& out_oqse_cfg);

    // @brief Helper function to get HW encoding of la_oq_vsc_mapping_e.
    size_t get_ll_bitmap(la_oq_vsc_mapping_e mapping) const;

    /// @brief Return whether this OQSE is used for LP-queuing.
    ///
    /// @return True if it requests credits from TPSE, false if it requests from LPSE.
    bool is_system_port_queueing() const;

    // Device this transmit scheduler belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid{LA_OBJECT_ID_INVALID};

    // Transmit scheduler slice ID
    la_slice_id_t m_slice_id;

    // Transmit scheduler interface group ID
    la_ifg_id_t m_ifg_id;

    // SCH or SCH_FAB registers and memories
    lld_memory_sptr m_sch_oqse_cfg;
    lld_memory_sptr m_sch_vsc_map_cfg;
    lld_memory_sptr m_sch_vsc_token_bucket;
    lld_memory_sptr m_sch_vsc_token_bucket_cfg;
    lld_memory_sptr m_sch_vsc_token_bucket_empty;
    lld_register_sptr m_oqse_shaper_configuration;

    template <class _sch>
    void initialize_sch_references(_sch& sch)
    {
        m_sch_oqse_cfg = sch->oqse_cfg;
        m_sch_vsc_map_cfg = sch->vsc_map_cfg;
        m_sch_vsc_token_bucket = sch->vsc_token_bucket;
        m_sch_vsc_token_bucket_cfg = sch->vsc_token_bucket_cfg;
        m_sch_vsc_token_bucket_empty = sch->vsc_token_bucket_empty;
        m_oqse_shaper_configuration = sch->oqse_shaper_configuration;
    }

    // OQSE ID
    index_handle m_oqse_id;

    // Scheduling mode
    scheduling_mode_e m_scheduling_mode;

    // Weights of all groups as set by the user.
    std::vector<la_wfq_weight_t> m_groups_weights;

    // Scheduler requested burst sizes (max_bucket)
    size_t m_requested_credit_cir_burst_size;
    size_t m_requested_credit_eir_or_pir_burst_size;
    size_t m_requested_credit_oq_pir_burst_size;
    size_t m_requested_transmit_oq_pir_burst_size;

    // List of attached VSCs
    la_vsc_voq_map_t m_attached_vscs;

    la_output_queue_scheduler_impl() = default; // For serialization purposes only.

}; // class la_output_queue_scheduler

} // namespace silicon_one

/// @}

#endif // __LA_OUTPUT_QUEUE_SCHEDULER_IMPL_H__
