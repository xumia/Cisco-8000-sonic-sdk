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

#ifndef __LA_MAC_PORT_GIBRALTAR_H__
#define __LA_MAC_PORT_GIBRALTAR_H__

#include "system/la_mac_port_pacgb.h"

namespace silicon_one
{

class la_mac_port_gibraltar : public la_mac_port_pacgb
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_mac_port_gibraltar() = default; // Needed for cereal

public:
    explicit la_mac_port_gibraltar(const la_device_impl_wptr& device);
    ~la_mac_port_gibraltar() override;

    la_status do_reset() override;

    // PFC
    la_status set_pfc_enable(la_uint8_t tc_bitmap) override;
    la_status get_pfc_enabled(bool& out_enabled, la_uint8_t& tc_bitmap) const override;
    la_status set_pfc_counter(la_counter_set* rx_counter) override;
    la_status set_pfc_meter(la_meter_set* tx_meter) override;
    la_status get_pfc_counter(const la_counter_set*& out_counter) const override;
    la_status get_pfc_meter(const la_meter_set*& out_meter) const override;
    la_status get_pfc_quanta(std::chrono::nanoseconds& out_xoff_time) const override;
    la_status set_pfc_quanta(std::chrono::nanoseconds xoff_time) override;
    la_status set_pfc_disable() override;

private:
    la_status mlp_init(fc_mode_e rx_fc_mode, fc_mode_e tx_fc_mode, fec_mode_e fec_mode) override;

    la_status update_pdoq_oq_ifc_mapping() override;
    la_status set_oqueue_state(la_pfc_priority_t pfc_priority, pfc_config_queue_state_e state) override;
    la_status get_oqueue_ptr(la_pfc_priority_t pfc_priority, la_uint_t& out_q_rd_ptr, la_uint_t& out_q_wr_ptr) override;
    la_status set_oq_counter_set(la_pfc_priority_t pfc_priority, la_uint_t counter_set) override;
    bool is_oq_drop_counter_set_valid(size_t counter_set) override;
    la_status read_oq_uc_counters(size_t counter_set_idx, output_queue_counters& oq_uc_counter) override;
    la_status read_oq_mc_counters(size_t counter_set_idx, output_queue_counters& oq_mc_counter) override;
    la_status set_reset_state_fabric_port(mac_reset_state_e state) override;
    la_status configure_fabric_scheduler() override;

    la_status set_sq_map_table_priority(la_uint_t map_mode) override;
    la_status set_ssp_sub_port_map() override;
    la_status set_source_if_to_port_map_fc_enable(bool fc_enable) override;
    la_status set_fcm_prio_map_bitmap(la_uint8_t tc_bitmap) override;
    la_status set_pfc_tc_xoff_rx_enable(la_uint8_t tc_bitmap) override;
    la_status init_rxcgm() override;
    la_status reset_rx_cgm_mapping() override;

    // PFC
    la_status init_pfc() override;
    bool is_sw_based_pfc_enabled() const override;
    la_status get_pfc_status(la_pfc_priority_t pfc_priority, bool& out_state) override;
};
}

#endif // __LA_MAC_PORT_GIBRALTAR_H__
