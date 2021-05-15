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

#include "device_params.h"

namespace silicon_one
{
namespace sai
{

la_status
device_params::initialize(hw_device_type_e dev_type)
{
    // Common values
    slices_per_dev = 6;
    ifgs_per_slice = 2;

    // PFC parameters

    // common parameters
    pfc_trap_priority = 0;
    tc_lossless_profile = 0xfe;
    tc_lossy_profile = 0xff;
    pfc_lossless_sqg_num = 0;
    pfc_lossy_sqg_num = 1;
    pfc_slice_ifg_id = 1; // all injects are to ifg 1

    pfc_default_ecn_thr = 0;
    pfc_default_cir = 170000000; // from enable_pfc()
    pfc_default_eir = 170000000;
    pfc_default_cbs = 102400;
    pfc_default_ebs = 1024;

    switch (dev_type) {
    case hw_device_type_e::PACIFIC:
        serdes_per_ifg = std::vector<la_uint32_t>(6 * 2, 18);
        host_serdes_id = 18; // See: sdk/driver/pacific/src/hld/hld_types.h
        recycle_serdes_id = 19;

        pfc_default_pause_thr = 1200;
        pfc_default_head_room = 800;
        pfc_sqg_thr_max = 0x1ffff;
        pfc_rx_pdr_sms_thr0 = 58000;
        pfc_rx_pdr_sms_thr1 = 64000;
        pfc_counter_a_thr0 = 16000;
        pfc_counter_a_thr1 = 40000;
        pfc_counter_a_thr2 = 58000;

        pfc_periodic_timer = 0x3fff;
        pfc_quanta_bits = 512;
        pfc_quanta_max = 0xffff; // sdk always sets to max 0xffff
        pfc_voq_precharge_ncb = 10;
        pfc_scaled_thr_percent = 60;
        pfc_head_room_max = 0x1ffff; // 17 bits width

        pfc_oq_fc_bytes_thr_max = 0x3ffff; // 17 bits width
        pfc_oq_fc_pds_thr_max = 0x7fff;
        pfc_oq_drop_bytes_thr_max = 0x3ffff;
        pfc_oq_drop_buffers_thr_max = 0x1ffff;
        pfc_oq_fc_bytes_thr = (130 * 1024) / 256;
        pfc_oq_fc_buffers_thr = 400;
        pfc_oq_fc_buffers_thr_max = 0x1ffff; // 17 bits width
        pfc_oq_drop_pds_thr_max = 0x7fff;    // 15 bits width
        pfc_oq_drop_buffers_thr_lo = 1000;   // lossy le 100G
        pfc_oq_drop_buffers_thr_hi = 2000;   // lossy gt 100G

        break;

    case hw_device_type_e::GIBRALTAR:
        serdes_per_ifg = std::vector<la_uint32_t>{24, 24, 24, 16, 16, 24, 24, 16, 16, 24, 24, 24};
        host_serdes_id = 24; // See: sdk/driver/gibraltar/src/hld/hld_types.h
        recycle_serdes_id = 25;

        pfc_default_pause_thr = 1200;
        pfc_default_head_room = 800;
        pfc_sqg_thr_max = 0x7ffff;
        pfc_rx_pdr_sms_thr0 = 160000;
        pfc_rx_pdr_sms_thr1 = 170000;
        pfc_counter_a_thr0 = 75000;
        pfc_counter_a_thr1 = 100000;
        pfc_counter_a_thr2 = 160000;

        pfc_periodic_timer = 0x3fff;
        pfc_quanta_bits = 512;
        pfc_quanta_max = 0xffff; // sdk always sets to max 0xffff
        pfc_voq_precharge_ncb = 10;
        pfc_scaled_thr_percent = 60;
        pfc_head_room_max = 0x7ffff; // 19 bits width

        pfc_oq_fc_bytes_thr_max = 0x7ffff; // 19 bits width
        pfc_oq_fc_pds_thr_max = 0xffff;
        pfc_oq_drop_bytes_thr_max = 0x7ffff;
        pfc_oq_drop_buffers_thr_max = 0x7ffff;
        pfc_oq_fc_bytes_thr = (130 * 1024) / 256;
        pfc_oq_fc_buffers_thr = 400;
        pfc_oq_fc_buffers_thr_max = 0x7ffff; // 19 bits width
        pfc_oq_drop_pds_thr_max = 0xffff;    // 16 bits width
        pfc_oq_drop_buffers_thr_lo = 1000;   // lossy le 100G
        pfc_oq_drop_buffers_thr_hi = 4000;   // lossy gt 100G

        break;

    default:
        return LA_STATUS_EINVAL;
    }
    log_param_values();
    return LA_STATUS_SUCCESS;
}

#define LOG_INT(xyz) sai_log_info(SAI_API_SWITCH, "%s = %d", #xyz, xyz)
#define LOG_LONGINT(xyz) sai_log_info(SAI_API_SWITCH, "%s = %llu", #xyz, xyz)

// log all param values
void
device_params::log_param_values()
{
    sai_log_info(SAI_API_SWITCH, "PFC related device parameters:");
    LOG_INT(pfc_head_room_max);
    LOG_INT(pfc_default_pause_thr);
    LOG_INT(pfc_default_head_room);
    LOG_INT(pfc_default_ecn_thr);
    LOG_INT(pfc_trap_priority);
    LOG_INT(tc_lossless_profile);
    LOG_INT(tc_lossy_profile);
    LOG_INT(pfc_voq_precharge_ncb);
    LOG_INT(pfc_scaled_thr_percent);
    LOG_INT(pfc_sqg_thr_max);
    LOG_INT(pfc_lossless_sqg_num);
    LOG_INT(pfc_lossy_sqg_num);
    LOG_INT(pfc_oq_fc_bytes_thr_max);
    LOG_INT(pfc_oq_fc_buffers_thr_max);
    LOG_INT(pfc_oq_fc_pds_thr_max);
    LOG_INT(pfc_oq_drop_bytes_thr_max);
    LOG_INT(pfc_oq_drop_buffers_thr_max);
    LOG_INT(pfc_oq_drop_pds_thr_max);

    LOG_INT(pfc_oq_fc_bytes_thr);
    LOG_INT(pfc_oq_fc_buffers_thr);
    LOG_INT(pfc_oq_drop_buffers_thr_lo);
    LOG_INT(pfc_oq_drop_buffers_thr_hi);
    LOG_INT(pfc_rx_pdr_sms_thr0);
    LOG_INT(pfc_rx_pdr_sms_thr1);
    LOG_INT(pfc_counter_a_thr0);
    LOG_INT(pfc_counter_a_thr1);
    LOG_INT(pfc_counter_a_thr2);
    LOG_INT(pfc_periodic_timer);
    LOG_INT(pfc_quanta_bits);
    LOG_INT(pfc_quanta_max);
    LOG_INT(pfc_slice_ifg_id);

    LOG_LONGINT(pfc_default_cir);
    LOG_LONGINT(pfc_default_eir);
    LOG_LONGINT(pfc_default_cbs);
    LOG_LONGINT(pfc_default_ebs);
}

// Registers the given field with the j_writer keyed by the string
// version of that name
#define REGISTER_FIELD(writer, name) writer.register_loc(&name, #name)

void
device_params::register_fields(json_struct_writer& j_writer)
{
    // To enable JSON configurability of any integral field in this
    // structure, add a line here for the given field name.
    REGISTER_FIELD(j_writer, pfc_head_room_max);
    REGISTER_FIELD(j_writer, pfc_default_pause_thr);
    REGISTER_FIELD(j_writer, pfc_default_head_room);
    REGISTER_FIELD(j_writer, pfc_default_ecn_thr);
    // REGISTER_FIELD(j_writer, pfc_trap_priority);
    // REGISTER_FIELD(j_writer, tc_lossless_profile);
    // REGISTER_FIELD(j_writer, tc_lossy_profile);
    REGISTER_FIELD(j_writer, pfc_voq_precharge_ncb);
    REGISTER_FIELD(j_writer, pfc_scaled_thr_percent);
    REGISTER_FIELD(j_writer, pfc_sqg_thr_max);
    // REGISTER_FIELD(j_writer, pfc_lossless_sqg_num);
    // REGISTER_FIELD(j_writer, pfc_lossy_sqg_num);
    REGISTER_FIELD(j_writer, pfc_oq_fc_bytes_thr_max);
    REGISTER_FIELD(j_writer, pfc_oq_fc_buffers_thr_max);
    REGISTER_FIELD(j_writer, pfc_oq_fc_pds_thr_max);
    REGISTER_FIELD(j_writer, pfc_oq_drop_bytes_thr_max);
    REGISTER_FIELD(j_writer, pfc_oq_drop_buffers_thr_max);
    REGISTER_FIELD(j_writer, pfc_oq_drop_pds_thr_max);
    REGISTER_FIELD(j_writer, pfc_oq_fc_bytes_thr);
    REGISTER_FIELD(j_writer, pfc_oq_fc_buffers_thr);
    REGISTER_FIELD(j_writer, pfc_oq_drop_buffers_thr_lo);
    REGISTER_FIELD(j_writer, pfc_oq_drop_buffers_thr_hi);
    REGISTER_FIELD(j_writer, pfc_rx_pdr_sms_thr0);
    REGISTER_FIELD(j_writer, pfc_rx_pdr_sms_thr1);
    REGISTER_FIELD(j_writer, pfc_counter_a_thr0);
    REGISTER_FIELD(j_writer, pfc_counter_a_thr1);
    REGISTER_FIELD(j_writer, pfc_counter_a_thr2);
    REGISTER_FIELD(j_writer, pfc_periodic_timer);
    REGISTER_FIELD(j_writer, pfc_quanta_bits);
    REGISTER_FIELD(j_writer, pfc_quanta_max);
    REGISTER_FIELD(j_writer, pfc_slice_ifg_id);
    REGISTER_FIELD(j_writer, pfc_default_cir);
    REGISTER_FIELD(j_writer, pfc_default_eir);
    REGISTER_FIELD(j_writer, pfc_default_cbs);
    REGISTER_FIELD(j_writer, pfc_default_ebs);
}
}
}
