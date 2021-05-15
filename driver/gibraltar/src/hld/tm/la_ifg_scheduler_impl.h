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

#ifndef __LA_IFG_SCHEDULER_IMPL_H__
#define __LA_IFG_SCHEDULER_IMPL_H__

#include "api/system/la_mac_port.h"
#include "api/tm/la_ifg_scheduler.h"
#include "api/types/la_tm_types.h"
#include "tm/la_output_queue_scheduler_impl.h"
#include <memory>
#include <string>
#include <vector>

#include "hld_types.h"
#include "hld_types_fwd.h"
#include "lld/lld_memory.h"
#include "lld/lld_register.h"

namespace silicon_one
{

class la_device_impl;

class la_ifg_scheduler_impl : public la_ifg_scheduler
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_ifg_scheduler_impl(const la_device_impl_wptr& device, la_slice_id_t slice_id, la_ifg_id_t ifg_id);
    ~la_ifg_scheduler_impl() override;

    // la_credit_scheduler API-s
    la_status get_credit_rate(la_rate_t& out_rate) const override;
    la_status set_credit_rate(la_rate_t rate) override;
    la_status get_transmit_rate(la_rate_t& out_rate) const override;
    la_status set_transmit_rate(la_rate_t rate) override;
    la_status get_credit_burst_size(size_t& out_burst) const override;
    la_status set_credit_burst_size(size_t burst) override;
    la_status get_transmit_burst_size(size_t& out_burst) const override;
    la_status set_transmit_burst_size(size_t burst) override;
    la_status set_max_transmit_rate_utilization(la_float_t max_rate_percent) override;
    la_status get_max_transmit_rate_utilization(la_float_t& out_max_rate_percent) const override;
    la_status set_max_rx_rate_utilization(la_float_t max_rate_percent) override;
    la_status get_max_rx_rate_utilization(la_float_t& out_max_rate_percent) const override;
    la_status get_txpdr_cir(la_rate_t& out_rate) const override;
    la_status set_txpdr_cir(la_rate_t rate) override;
    la_status get_txpdr_eir_or_pir(la_rate_t& out_rate, bool& out_is_eir) const override;
    la_status set_txpdr_eir_or_pir(la_rate_t rate, bool is_eir) override;
    la_status get_txpdr_cir_weight(la_wfq_weight_t& out_weight) const override;
    la_status set_txpdr_cir_weight(la_wfq_weight_t weight) override;
    la_status get_txpdr_eir_weight(la_wfq_weight_t& out_weight) const override;
    la_status set_txpdr_eir_weight(la_wfq_weight_t weight) override;
    la_status get_txpdr_hp_oqcs(la_output_queue_scheduler*& out_oq_sch) const override;
    la_status get_txpdr_lp_oqcs(la_output_queue_scheduler*& out_oq_sch) const override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Helper function - Retrieve credit scheduler's Committed Information Rate.
    la_status get_cir(la_rate_t& out_rate);

    // Helper function - Retrieve credit scheduler's Excess information rate.
    la_status get_eir(la_rate_t& out_rate);

    // Helper function - Retrieve transmit scheduler's Committed Information Rate.
    la_status get_transmit_cir(la_rate_t& out_rate);

    // Helper function - Retrieve transmit scheduler's Peak Information Rate.
    la_status get_transmit_pir(la_rate_t& out_rate);

    // Helper function - Retrieve OQSE credit rate - device value.
    la_status get_oqse_shaper(uint32_t& out_device_rate);

    // Initialize the IFG scheduler with all the proper defaults
    la_status initialize(la_object_id_t oid);

    // Destroy the IFG scheduler
    la_status destroy();

    // Initialize an interface inside the IFG scheduler
    la_status initialize_interface(size_t pif_base, size_t pif_count);

    // Initialize an fabric port interface inside the IFG scheduler
    la_status initialize_fabric_interface(size_t pif_base, size_t pif_count);

    // The profile ID for each speed
    // The profiles are for the following speeds: 800, 400, 100, 50, 40, 25, 10, not used
    static const std::map<la_mac_port::port_speed_e, la_uint_t> s_pdif_fifo_threshold_profile_id;

    la_status reset_fdoq_calendar(size_t pif_base, size_t pif_count);

protected:
    la_status initialize_lld_memories();
    la_status initialize_scheduler_shapers_and_ifg_total_rate();
    la_status initialize_general_credit_shapers();
    la_status initialize_slow_rate();
    la_status initialize_credit_tpse_shaper(uint32_t device_rate);
    la_status initialize_oqse_shaper(uint32_t device_rate);
    la_status initialize_lpse_shaper(uint32_t device_rate);

    la_status initialize_general_transmit_shapers();
    la_status initialize_transmit_tpse_shaper(uint32_t device_rate);

    la_status initialize_fdoq_calendar();
    la_status configure_fdoq_calendar(size_t pif_base, size_t pif_count);
    la_status initialize_pdif_fifo();

    la_status initialize_oqcs();

    la_status read_max_transmit_rate();
    la_status read_max_rx_shaper_burst();

    la_status allocate_pdif_fifo(size_t pif_base, size_t pif_count, bool is_fabric);
    la_status reset_pdif_fifo(size_t pif_base, size_t pif_count);

    la_status set_tpse_to_interface_map(la_uint_t intf_id, la_uint_t intf_count);

    la_status do_set_credit_rate(la_uint32_t device_rate);
    la_status do_set_credit_burst_size(size_t burst);
    la_status do_set_transmit_burst_size(size_t burst);
    la_status do_set_transmit_rate(la_uint32_t device_rate);

    // Device this transmit scheduler belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // Transmit scheduler slice ID
    la_slice_id_t m_slice_id;

    // Transmit scheduler interface group ID
    la_ifg_id_t m_ifg_id;

    // Max transmit and rx rate values
    la_uint32_t m_max_transmit_rate;
    la_uint64_t m_max_rx_shaper_burst;

    // SCH or SCH_FAB registers and memories
    lld_register_scptr m_sch_soft_reset_configuration;
    lld_register_scptr m_sch_ifse_general_configuration;
    lld_register_scptr m_sch_slow_rate_configuration;
    lld_register_scptr m_sch_lpse_shaper_configuration;
    lld_register_scptr m_sch_oqse_shaper_configuration;
    lld_register_scptr m_sch_tpse_shaper_configuration;
    lld_register_scptr m_sch_spare_reg;
    lld_register_array_sptr m_sch_ifse_cir_shaper_rate_configuration;
    lld_register_array_sptr m_sch_ifse_cir_shaper_max_bucket_configuration;
    lld_register_array_sptr m_sch_ifse_pir_shaper_configuration;
    lld_register_array_sptr m_sch_ifse_pir_shaper_max_bucket_configuration;
    lld_register_array_sptr m_sch_ifse_wfq_cir_weights;
    lld_register_array_sptr m_sch_ifse_wfq_eir_weights;
    lld_memory_scptr m_sch_vsc_token_bucket_cfg;
    lld_memory_scptr m_sch_oq_pir_token_bucket_cfg;
    lld_memory_scptr m_sch_oqpg_cir_token_bucket_cfg;
    lld_memory_scptr m_sch_oqse_cir_token_bucket_cfg;
    lld_memory_scptr m_sch_oqse_eir_token_bucket_cfg;
    lld_memory_scptr m_sch_lpse_wfq_weight_map;

    template <class _sch>
    void initialize_sch_references(_sch& sch)
    {
        m_sch_soft_reset_configuration = sch->soft_reset_configuration;
        m_sch_ifse_general_configuration = sch->ifse_general_configuration;
        m_sch_slow_rate_configuration = sch->slow_rate_configuration;
        m_sch_lpse_shaper_configuration = sch->lpse_shaper_configuration;
        m_sch_oqse_shaper_configuration = sch->oqse_shaper_configuration;
        m_sch_tpse_shaper_configuration = sch->tpse_shaper_configuration;
        m_sch_spare_reg = sch->spare_reg;
        m_sch_ifse_cir_shaper_rate_configuration = sch->ifse_cir_shaper_rate_configuration;
        m_sch_ifse_cir_shaper_max_bucket_configuration = sch->ifse_cir_shaper_max_bucket_configuration;
        m_sch_ifse_pir_shaper_configuration = sch->ifse_pir_shaper_configuration;
        m_sch_ifse_pir_shaper_max_bucket_configuration = sch->ifse_pir_shaper_max_bucket_configuration;
        m_sch_ifse_wfq_cir_weights = sch->ifse_wfq_cir_weights;
        m_sch_ifse_wfq_eir_weights = sch->ifse_wfq_eir_weights;
        m_sch_vsc_token_bucket_cfg = sch->vsc_token_bucket_cfg;
        m_sch_oq_pir_token_bucket_cfg = sch->oq_pir_token_bucket_cfg;
        m_sch_oqpg_cir_token_bucket_cfg = sch->oqpg_cir_token_bucket_cfg;
        m_sch_oqse_cir_token_bucket_cfg = sch->oqse_cir_token_bucket_cfg;
        m_sch_oqse_eir_token_bucket_cfg = sch->oqse_eir_token_bucket_cfg;
        m_sch_lpse_wfq_weight_map = sch->lpse_wfq_weight_map;
    }

    // TXPDR High priority OQ, this is actually output quoue 0 on port 20
    la_output_queue_scheduler_impl_wptr m_txpdr_hp;

    // TXPDR Low priority OQ, this is actually output queue 1 on port 20
    la_output_queue_scheduler_impl_wptr m_txpdr_lp;

    la_ifg_scheduler_impl() = default; // For serialization purposes only.
};                                     // class la_credit_scheduler_impl

} // namespace silicon_one

#endif // __LA_IFG_SCHEDULER_IMPL_H__
