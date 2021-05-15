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

#ifndef __LA_SYSTEM_PORT_SCHEDULER_IMPL_H__
#define __LA_SYSTEM_PORT_SCHEDULER_IMPL_H__

#include "common/defines.h"
#include <memory>
#include <vector>

#include "api/tm/la_system_port_scheduler.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_device_impl;
class la_output_queue_scheduler_impl;
class la_logical_port_scheduler_impl;
class la_interface_scheduler_impl;
class lld_register;
class lld_memory;

class la_system_port_scheduler_impl : public la_system_port_scheduler
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_system_port_scheduler_impl(const la_device_impl_wptr& device,
                                           la_slice_id_t slice_id,
                                           la_ifg_id_t ifg_id,
                                           la_system_port_scheduler_id_t sp_sch_id);
    ~la_system_port_scheduler_impl() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, const la_interface_scheduler_wptr& intf_sch);
    la_status destroy();

    // la_tm_port_transmit_scheduler API-s
    la_status get_priority_propagation(bool& out_enabled) const override;
    la_status set_priority_propagation(bool enabled) override;
    la_status get_logical_port_enabled(bool& out_enabled) const override;
    la_status set_logical_port_enabled(bool enabled) override;
    la_status get_oq_priority_group(la_oq_id_t oid, priority_group_e& out_pg) const override;
    la_status set_oq_priority_group(la_oq_id_t oid, priority_group_e pg) override;
    la_status get_credit_pir(la_oq_id_t oid, la_rate_t& out_rate) const override;
    la_status set_credit_pir(la_oq_id_t oid, la_rate_t rate) override;
    la_status get_credit_pir_burst_size(la_oq_id_t oid, size_t& out_burst) const override;
    la_status set_credit_pir_burst_size(la_oq_id_t oid, size_t burst) override;
    la_status do_set_credit_pir_burst_size(la_oq_id_t oid, size_t burst);
    la_status get_transmit_pir(la_oq_id_t oid, la_rate_t& out_rate) const override;
    la_status set_transmit_pir(la_oq_id_t oid, la_rate_t rate) override;
    la_status get_transmit_pir_burst_size(la_oq_id_t oid, size_t& out_burst) const override;
    la_status set_transmit_pir_burst_size(la_oq_id_t oid, size_t burst) override;
    la_status do_set_transmit_pir_burst_size(la_oq_id_t oid, size_t burst);
    la_status get_transmit_uc_mc_weight(la_oq_id_t oid, la_wfq_weight_t& out_ucw, la_wfq_weight_t& out_mcw) const override;
    la_status set_transmit_uc_mc_weight(la_oq_id_t oid, la_wfq_weight_t ucw, la_wfq_weight_t mcw) override;
    la_status get_priority_group_credit_cir(priority_group_e pg, la_rate_t& out_rate) const override;
    la_status set_priority_group_credit_cir(priority_group_e pg, la_rate_t rate) override;
    la_status get_priority_group_credit_burst_size(priority_group_e pg, size_t& out_burst) const override;
    la_status set_priority_group_credit_burst_size(priority_group_e pg, size_t burst) override;
    la_status do_set_priority_group_credit_burst_size(size_t pg, size_t burst);
    la_status get_priority_group_transmit_cir(priority_group_e pg, la_rate_t& out_rate) const override;
    la_status set_priority_group_transmit_cir(priority_group_e pg, la_rate_t rate) override;
    la_status get_priority_group_transmit_burst_size(priority_group_e pg, size_t& out_burst) const override;
    la_status set_priority_group_transmit_burst_size(priority_group_e pg, size_t burst) override;
    la_status do_set_priority_group_transmit_burst_size(size_t pg, size_t burst);
    la_status get_priority_group_eir_weight(priority_group_e pg, la_wfq_weight_t& out_weight) const override;
    la_status set_priority_group_eir_weight(priority_group_e pg, la_wfq_weight_t weight) override;
    la_status get_priority_group_eir_actual_weight(priority_group_e pg, la_wfq_weight_t& out_weight) const override;
    la_status get_output_queue_scheduler(la_oq_id_t oqid, la_output_queue_scheduler*& out_oq_sch) const override;
    la_status get_logical_port_scheduler(la_logical_port_scheduler*& out_lp_sch) const override;
    la_status update_port_speed(la_mac_port::port_speed_e mac_port_speed);

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

private:
    la_status pacific_oqcs_eir_cir_workaround();

    la_status do_set_transmit_uc_mc_weight(la_oq_id_t oid, la_wfq_weight_t ucw, la_wfq_weight_t mcw);

    // Information for TpseOqpgMappingConfigutration register
    enum {
        OQ_COUNT = 8,       ///< Number of Output Queue per TM port CS
        BITS_PER_PORT = 17, ///< Number of bits for each port.
    };

    // LSB bit of the value for the specific OQ
    static const size_t s_oq_lsb_bit[OQ_COUNT];

    // MSB bit of the value for the specific OQ
    static const size_t s_oq_msb_bit[OQ_COUNT];

    // Mapping between OQ, PG to value. -1 means invalid combination
    static const int s_oq_oqpg_value[OQ_COUNT][(size_t)priority_group_e::NONE];

    // The base priority group value for the specific OQ
    static const uint32_t s_oq_base_pq[OQ_COUNT];

    // Device this transmit scheduler belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid{LA_OBJECT_ID_INVALID};

    // Transmit scheduler slice ID
    la_slice_id_t m_slice_id;

    // Transmit scheduler interface group ID
    la_ifg_id_t m_ifg_id;

    // SCH or SCH_FAB registers and memories
    lld_register_sptr m_sch_tpse_general_configuration;
    lld_register_sptr m_sch_tpse_oqpg_mapping_configuration;
    lld_register_sptr m_sch_tpse_cir_shaper_update_cfg;
    lld_register_sptr m_sch_tpse_pir_shaper_update_cfg;
    lld_memory_sptr m_sch_oqpg_cir_token_bucket;
    lld_memory_sptr m_sch_oqpg_cir_token_bucket_cfg;
    lld_memory_sptr m_sch_oq_pir_token_bucket;
    lld_memory_sptr m_sch_oq_pir_token_bucket_cfg;
    lld_memory_sptr m_sch_tpse_wfq_cfg;

    template <class _sch>
    void initialize_sch_references(_sch& sch)
    {
        m_sch_tpse_general_configuration = sch->tpse_general_configuration;
        m_sch_tpse_oqpg_mapping_configuration = sch->tpse_oqpg_mapping_configuration;
        m_sch_tpse_cir_shaper_update_cfg = sch->tpse_cir_shaper_update;
        m_sch_tpse_pir_shaper_update_cfg = sch->tpse_pir_shaper_update;
        m_sch_oqpg_cir_token_bucket = sch->oqpg_cir_token_bucket;
        m_sch_oqpg_cir_token_bucket_cfg = sch->oqpg_cir_token_bucket_cfg;
        m_sch_oq_pir_token_bucket = sch->oq_pir_token_bucket;
        m_sch_oq_pir_token_bucket_cfg = sch->oq_pir_token_bucket_cfg;
        m_sch_tpse_wfq_cfg = sch->tpse_wfq_cfg;
    }

    // Interface scheduler
    la_interface_scheduler_impl_wptr m_intf_sch;

    // System port scheduler ID
    la_system_port_scheduler_id_t m_sp_sch_id;

    // Vector of output queue scheduler objects
    std::vector<la_output_queue_scheduler_impl_wptr> m_oq_sch_vec;

    // Logical port scheduler associated with this system port scheduler
    la_logical_port_scheduler_impl_wptr m_lp_sch;

    // Using logical port scheduler
    bool m_logical_port_enabled;

    // The underlying mac port speed
    la_rate_t m_port_speed;

    // Scheduler requested burst sizes (max_bucket)
    std::vector<size_t> m_requested_credit_oqpg_cir_burst_size;
    std::vector<size_t> m_requested_transmit_oqpg_cir_burst_size;

    // Weights of all priority groups as set by the user.
    std::vector<la_wfq_weight_t> m_pg_weights;

    // Weights for UC/MC traffic
    std::vector<std::vector<la_wfq_weight_t> > m_uc_mc_weights;
    // UC/MC Index in m_uc_mc_weights
    enum class uc_mc_weights_e : size_t { UC_IDX = 0, MC_IDX, LAST };

    la_system_port_scheduler_impl() = default; // For serialization purposes only.

}; // class la_tm_port_credit_scheduler

} // namespace silicon_one

/// @}

#endif // __LA_SYSTEM_PORT_SCHEDULER_IMPL_H__
