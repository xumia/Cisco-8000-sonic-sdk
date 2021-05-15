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

#ifndef __DEVICE_PARAMS_H__
#define __DEVICE_PARAMS_H__

#include "sai_constants.h"
#include "json_struct_writer.h"

namespace silicon_one
{
namespace sai
{

// PI and PD device parameter storage
struct device_params {
    la_slice_id_t slices_per_dev = 0;        // Number of Slices in Device
    la_ifg_id_t ifgs_per_slice = 0;          // Number of IFG in Slice
    std::vector<la_uint32_t> serdes_per_ifg; // Number of Serdes in IFG
    uint32_t host_serdes_id = 0;             // SerDes lane for host ports (PCI and NPUH)
    uint32_t recycle_serdes_id = 0;          // SerDes lane for recycle ports

    // PFC config thresholds
    la_uint_t pfc_head_room_max = 0;
    la_uint_t pfc_default_pause_thr = 0; // range 800-1100
    la_uint_t pfc_default_head_room = 0; // range 900-1400
    la_uint_t pfc_default_ecn_thr = 0;

    la_uint_t pfc_trap_priority = 0;

    silicon_one::la_traffic_class_t tc_lossless_profile = 0;
    silicon_one::la_traffic_class_t tc_lossy_profile = 0;

    la_uint_t pfc_voq_precharge_ncb = 0;  // VOQ pre charge credit balance
    la_uint_t pfc_scaled_thr_percent = 0; // percentage of scaled pause threshold

    // SQ group
    la_uint_t pfc_sqg_thr_max = 0;
    la_uint_t pfc_lossless_sqg_num = 0;
    la_uint_t pfc_lossy_sqg_num = 0;

    // TX output queue thresholds
    la_uint_t pfc_oq_fc_bytes_thr_max = 0;
    la_uint_t pfc_oq_fc_buffers_thr_max = 0;
    la_uint_t pfc_oq_fc_pds_thr_max = 0;
    la_uint_t pfc_oq_drop_bytes_thr_max = 0;
    la_uint_t pfc_oq_drop_buffers_thr_max = 0;
    la_uint_t pfc_oq_drop_pds_thr_max = 0;

    la_uint_t pfc_oq_fc_bytes_thr = 0;
    la_uint_t pfc_oq_fc_buffers_thr = 0;
    la_uint_t pfc_oq_drop_buffers_thr_lo = 0;
    la_uint_t pfc_oq_drop_buffers_thr_hi = 0;

    // RX CGM thresholds
    la_uint_t pfc_rx_pdr_sms_thr0 = 0; // rx pdr threshold0
    la_uint_t pfc_rx_pdr_sms_thr1 = 0; // rx pdr threshold1

    la_uint_t pfc_counter_a_thr0 = 0;
    la_uint_t pfc_counter_a_thr1 = 0;
    la_uint_t pfc_counter_a_thr2 = 0;

    // XON/XOFF timer
    la_uint_t pfc_periodic_timer = 0; // (periodic_timer * 512) / port_speed_in_gig
    la_uint_t pfc_quanta_bits = 0;
    la_uint_t pfc_quanta_max = 0;

    // PFC meter profile
    uint32_t pfc_slice_ifg_id = 0;
    uint64_t pfc_default_cir = 0;
    uint64_t pfc_default_eir = 0;
    uint64_t pfc_default_cbs = 0;
    uint64_t pfc_default_ebs = 0;

    device_params() = default;
    la_status initialize(hw_device_type_e dev_type);

    // Registers fields of this struct with the provided writer by
    // invoking json_struct_writer::register_loc. The
    // json_struct_writer::write method can then be invoked to write
    // any fields registered here.
    void register_fields(json_struct_writer& writer);
    void log_param_values(void);
};
}
}

#endif
