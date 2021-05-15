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

#ifndef __IFG_HANDLER_BASE_H__
#define __IFG_HANDLER_BASE_H__

#include "api/system/la_mac_port.h"
#include "hld_types.h"
#include "hw_tables/memory_tcam.h"
#include "lld/lld_fwd.h"
#include "system/ifg_handler.h"
#include "system/la_mac_port_base.h"
#include <memory>
#include <set>

namespace silicon_one
{

class la_device_impl;

class ifg_handler_base : public ifg_handler
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    ifg_handler_base(const la_device_impl_wptr& device, la_slice_id_t slice_id, la_ifg_id_t ifg_id);
    ~ifg_handler_base() override;
    void pre_initialize() override;

    la_status configure_port(la_uint_t mac_lane_base_id,
                             size_t mac_lanes_reserved_count,
                             la_mac_port::port_speed_e speed,
                             size_t mac_lanes_count,
                             la_mac_port::mlp_mode_e mlp_mode,
                             la_mac_port::fc_mode_e fc_mode) override;

    // The opposite to configure_port
    la_status clear_port(la_uint_t mac_lane_base_id,
                         size_t mac_lanes_reserved_count,
                         la_mac_port::port_speed_e speed,
                         size_t mac_lanes_count) override;

    la_status reset_tx_fifo_memory_allocation();
    la_status allocate_fifo_memory(size_t mac_lane_base, la_mac_port::port_speed_e speed) override;
    la_status reset_fifo_memory_allocation(size_t mac_lane_base, size_t mac_lanes_reserved_count) override;
    la_status allocate_tx_fifo_memory(size_t mac_lane_base, size_t buffer_units);
    virtual la_status allocate_tx_fifo_memory_main_ports(size_t mac_lane_base, size_t buffer_units) = 0;
    la_status reset_fifo_memory_allocation();
    la_status set_fc_mode(la_uint_t mac_lane_base_id,
                          size_t mac_lanes_reserved_count,
                          la_mac_port::port_speed_e speed,
                          la_mac_port::fc_mode_e fc_mode) override;
    la_status reset_port_tc_custom_protocol_configuration(la_uint_t mac_lane_base_id, la_uint_t idx) override;
    la_status set_port_tc_layer(la_uint_t mac_lane_base_id,
                                la_uint_t tpid,
                                la_mac_port::tc_protocol_e protocol,
                                la_layer_e layer) override;
    la_status get_port_tc_layer(la_uint_t mac_lane_base_id,
                                la_uint_t tpid,
                                la_mac_port::tc_protocol_e protocol,
                                la_layer_e& out_layer) const override;
    la_status set_port_tc_for_custom_protocol(la_uint_t mac_lane_base_id,
                                              la_tpid_t tpid,
                                              la_uint_t idx,
                                              la_over_subscription_tc_t ostc,
                                              la_initial_tc_t itc) override;
    la_status get_port_tc_for_custom_protocol(la_uint_t mac_lane_base_id,
                                              la_tpid_t tpid,
                                              la_uint_t idx,
                                              la_over_subscription_tc_t& out_ostc,
                                              la_initial_tc_t& out_itc) const override;
    la_status get_port_tc_for_fixed_protocol(la_uint_t mac_lane_base_id,
                                             la_mac_port::tc_protocol_e protocol,
                                             la_uint8_t priority,
                                             la_over_subscription_tc_t& out_ostc,
                                             la_initial_tc_t& out_itc) const override;

    la_status reset_oob_packet_counters();

    /// @brief Get the mux selector for a given L3 protocol.
    ///
    /// The mux output is the key to the TCAM to calculate the port TC.
    ///
    /// @param[in]      protocol                L3 protocol.
    /// @param[out]     out_mux_selector        Selector to choose the protocol as input to the TC TCAM.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval         LA_STATUS_EUNKNOWN      An unknown error occurred.
    la_status get_port_tc_fixed_protocol_selector(la_mac_port::tc_protocol_e protocol, la_uint8_t& out_mux_selector) const;

    /// @brief Get the index of fixed L3 protocol.
    ///
    /// Each L3 protocol {IPV4, IPV6, MPLS} have index which is part of the key to the LUT calculation the port TC.
    ///
    /// @param[in]      protocol                L3 protocol.
    /// @param[out]     out_protocol_idx        Protocol index.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval         LA_STATUS_EUNKNOWN      An unknown error occurred.
    la_status get_port_tc_fixed_protocol_idx(la_mac_port::tc_protocol_e protocol, la_uint8_t& out_protocol_idx) const;
    la_uint_t combine_ostc_and_itc(la_over_subscription_tc_t ostc, la_initial_tc_t itc) const;
    void split_value_to_ostc_and_itc(la_uint_t value, la_over_subscription_tc_t& out_ostc, la_initial_tc_t& out_itc) const;
    la_status check_synce_attached(la_device::synce_clock_sel_e prim_sec_clock, bool& out_synce_attached) const override;
    la_status clear_tc_tcam_mem(size_t mem_idx) override;
    size_t get_serdes_count() const override;
    size_t get_num_total_existing_serdes() const override;
    serdes_pool_type_e get_serdes_pool_type() const override;
    size_t get_pif_count() const override;

    la_status reset_oob_inj_credits(size_t mac_lane_base_id, int val) override;
    la_status set_block_ingress_data(size_t mac_lane_base, size_t mac_lanes_reserved_count, bool enabled) override;

    const la_device_impl_wptr get_device() const
    {
        return m_device;
    }

protected:
    enum {
        OSTC_BITS = 2,
        ITC_BITS = 3,
        TC_NUM_TPIDS = 3,
        TC_TPID_IDX_NO_MATCH = 3,
        OSTC_PART_LSB = 0, // OSTC is the LSB bits of this register field
        OSTC_PART_MSB = OSTC_PART_LSB + OSTC_BITS - 1,
        ITC_PART_LSB = OSTC_PART_MSB + 1, // ITC is the MSB bits of this register field
        ITC_PART_MSB = ITC_PART_LSB + ITC_BITS - 1,
        MAX_OSTC = (1 << OSTC_BITS) - 1,
        MAX_ITC = (1 << ITC_BITS) - 1,

        PORT_TC_PCPDEI_SELECTOR = 0,
        PORT_TC_MPLS_TC_SELECTOR = 1,
        PORT_TC_DSCP_SELECTOR = 2,
        PORT_TC_IPV6_TC_SELECTOR = 3,
        PORT_TC_CUSTOM_WITH_OFFSET_SELECTOR = 4,
        NUM_OF_PORT_TC_FIXED_PROTOCOLS = 3,
        TC_PROTOCOL_IDX_NO_MATCH = 7,

        FIFO_BUFFER_MAX_SPEED = 50,
        CSMS_LINES = 64,

        TOT_TM_NPU_PORT_COUNT = 64,
        EXT_TM_NPU_PORT_COUNT = 16,
        TM_NPU_HOST = 16,
        TM_NPU_PKT_DMA = 17,
        TM_NPU_SCH_RCY = 18,
        EXT_TO_INTERNAL_PORT_COUNT = 32,
        INTERNAL_NPU_HOST = 32,
        INTERNAL_PKT_DMA = 33,
        INTERNAL_SCH_RCY = 34,

        FLOW_CONTROL_BITS = 512,
        NUM_PORT_TC_TCAM_ENTRIES = 16,
        ALMOST_EMPTY_THRESHOLD = 9600,

        // SyncE recovered clock detach dummy value
        SYNCE_DETACH_OUTPUT_IFG = 3,
        SYNCE_DETACH_OUTPUT_SERDES = 0x1F,
        SYNCE_DETACH_OUTPUT_DIV = 32,
    };

    // Periodic timer setting per flow control mode
    struct fc_mode_periodic_config_data {
        uint64_t port_periodic_timer;
        uint64_t port_watch_dog_timer;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(fc_mode_periodic_config_data);

    fc_mode_periodic_config_data s_fc_mode_periodic_config[(size_t)la_mac_port::fc_mode_e::CFFC + 1] = {// None
                                                                                                        {0, 0xFFFF},
                                                                                                        // Pause
                                                                                                        {0, 0xFFFF},
                                                                                                        // PFC
                                                                                                        {0, 0xFFFF},
                                                                                                        // CFFC
                                                                                                        {10, 0xFFFF}};

    // Containing device
    la_device_impl_wptr m_device;

    // Containing device revision
    la_device_revision_e m_device_revision;

    // Slice ID
    la_slice_id_t m_slice_id;

    // IFG ID
    la_ifg_id_t m_ifg_id;

    // Slice mode
    la_slice_mode_e m_slice_mode;

    struct ifg_handler_common {
        size_t m_serdes_count;
        size_t m_pif_count;
        size_t m_mac_lanes_reserved_count;
        size_t m_tc_ext_default_tc_width;
        size_t m_num_port_tc_tcam_memories;
        size_t m_total_main_mac_lanes_reserved_count;
        size_t m_tx_fifo_lines_main_serdes;
        serdes_pool_type_e m_pool_type;

        size_t m_tx_fifo_lines_main_pif;
        std::vector<size_t> m_tc_tcam_key_width;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(ifg_handler_common);
    ifg_handler_common m_ifg_handler_common;

    // The weight for each speed for reading by NPU
    // For 10G is 3 (which is the minimum), and then proportionally.
    std::map<la_mac_port::port_speed_e, uint64_t> read_schedule_weight = {{la_mac_port::port_speed_e::E_10G, 3},
                                                                          {la_mac_port::port_speed_e::E_25G, 8},
                                                                          {la_mac_port::port_speed_e::E_40G, 12},
                                                                          {la_mac_port::port_speed_e::E_50G, 15},
                                                                          {la_mac_port::port_speed_e::E_100G, 30},
                                                                          {la_mac_port::port_speed_e::E_200G, 60},
                                                                          {la_mac_port::port_speed_e::E_400G, 120},
                                                                          {la_mac_port::port_speed_e::E_800G, 240}};

    uint64_t flow_control_code[(size_t)la_mac_port::fc_mode_e::CFFC + 1] = {0, 1, 2, 3};
    uint64_t flow_control_priority_map[(size_t)la_mac_port::fc_mode_e::CFFC + 1] = {0, 1, 0xFF, 0xFF};
    std::vector<uint32_t> synce_ifg_demap;
    std::vector<uint32_t> synce_ifg_map;

    float flow_control_default_xon = 1.0 / 3;
    float flow_control_default_xoff = 2.0 / 3;

    struct tcam_entry {
        tcam_entry() = default; // For serialization purposes only
        tcam_entry(la_uint_t entry_key, la_uint_t entry_mask, la_uint_t entry_val)
            : key(entry_key), mask(entry_mask), val(entry_val)
        {
        }

        la_uint_t key;
        la_uint_t mask;
        la_uint_t val;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(tcam_entry);

    struct range_entry {
        range_entry() = default; // For serialization purposes only
        range_entry(la_uint_t low_edge, la_uint_t high_edge, la_uint_t entry_val) : low(low_edge), high(high_edge), val(entry_val)
        {
        }

        la_uint_t low;
        la_uint_t high;
        la_uint_t val;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(range_entry);

    struct range_entry_less {
        bool operator()(const range_entry& a, const range_entry& b) const
        {
            return a.low < b.low;
        }
    };

    using range_entries_set = std::set<range_entry, range_entry_less>;

    // TC TCAM sections
    std::vector<std::unique_ptr<memory_tcam> > m_port_tc_tcam;

    // SyncE recovered clock attached
    std::array<bool, SYNCE_REF_CLOCK_PER_GROUP> m_synce_attached;

    // PIF->Periodic timer mapping for PFC
    map_alloc<la_uint_t, la_uint_t> m_pfc_pif_periodic_timer_map;

    // PIF->periodic_int_en mapping for PFC
    map_alloc<la_uint_t, bool> m_pfc_pif_en_periodic_send_map;

    virtual la_status reset_rx_fifo_memory_allocation() = 0;
    virtual la_status configure_recycle_fifo() = 0;
    virtual la_status allocate_rx_fifo_memory(size_t mac_lane_base, size_t buffer_units) = 0;
    virtual la_status allocate_tx_fifo_memory_extra_ports(size_t mac_lane_base, size_t buffer_units) = 0;
    virtual la_status configure_tx_fifo_lines_value(la_mac_port::port_speed_e speed);
    virtual la_status configure_rx_cgm(size_t mac_lane_base, size_t mac_lanes_reserved_count, la_mac_port::port_speed_e speed) = 0;
    virtual la_status set_fc_mode_periodic(la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count, bool enable) = 0;
    virtual la_status set_fc_mode_fabric_extraction(la_uint_t mac_lane_base_id, bool enable);
    virtual la_status set_fc_mode_port(la_uint_t mac_lane_base_id,
                                       size_t mac_lanes_reserved_count,
                                       la_mac_port::port_speed_e speed,
                                       la_mac_port::fc_mode_e fc_mode)
        = 0;
    virtual la_status configure_oob_inject_packet_counters() = 0;
    virtual la_status configure_oob_extract_packet_counters() = 0;
    virtual la_status get_port_tc_tcam_key_opcode(la_uint_t mac_lane_base_id,
                                                  la_mac_port::tc_protocol_e protocol,
                                                  la_uint32_t& out_opcode,
                                                  la_uint32_t& out_length) const = 0;

    la_status init_pfc_port_values();

    /// @brief Try to merge new range to a set of ranges.
    ///
    /// @param[in,out]  range_entries_set       set of ranges.
    /// @param[in]      min_edge                Lower edge of the new range.
    /// @param[in]      max_edge                Higher edge of the new range.
    /// @param[in]      value                   Value of the new range.
    void merge_entry(range_entries_set& merged_entries, la_uint_t min_edge, la_uint_t max_edge, la_uint_t value);

    /// @brief Extract the port's bit out of a TC TCAM table entry.
    ///
    /// @param[in]      entry_key               TC TCAM table entry key.
    /// @param[in]      protocol                Protocol.
    ///
    /// @retval         0/1                     Port's bit in the entry key
    size_t get_tc_tcam_entry_port(la_uint_t entry_key, la_mac_port::tc_protocol_e protocol);

    /// @brief Extract the index of port's bit out of a TC TCAM table entry.
    ///
    /// @param[in]      entry_key               TC TCAM table entry key.
    ///
    /// @retval                                 Index of port's bit in the entry key
    la_uint_t get_tc_tcam_entry_port_bit_index(la_uint_t entry_key);

    /// @brief Extract the protocol type out of a TC TCAM table entry.
    ///
    /// @param[in]      entry_key               TC TCAM table entry key.
    ///
    /// @retval                                 Protocol type.
    la_mac_port::tc_protocol_e get_tc_tcam_entry_protocol(la_uint_t entry_key);

    // For serialization purposes only
    ifg_handler_base() = default;
};
} // namespace silicon_one

#endif // __IFG_HANDLER_BASE_H__
