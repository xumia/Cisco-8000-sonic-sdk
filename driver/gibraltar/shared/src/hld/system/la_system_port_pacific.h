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

#ifndef __LA_SYSTEM_PORT_PACIFIC_H__
#define __LA_SYSTEM_PORT_PACIFIC_H__

#include "hld_types_fwd.h"
#include "la_system_port_base.h"
#include "la_system_port_pacgb.h"
#include "nplapi/npl_constants.h"
#include "system/la_device_impl.h"
#include "system/la_mac_port_base.h"
#include "system/la_npu_host_port_base.h"
#include "system/la_pci_port_base.h"
#include "system/la_recycle_port_base.h"
#include "system/la_remote_port_impl.h"
#include "tm/la_unicast_tc_profile_impl.h"
#include "tm/la_voq_set_impl.h"

#include "hld_utils.h"
#include "npu/resolution_utils.h"
#include "tm/la_system_port_scheduler_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

class la_system_port_pacific : public la_system_port_pacgb
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_system_port_pacific() = default;
    //////////////////////////////
public:
    explicit la_system_port_pacific(const la_device_impl_wptr& device);
    ~la_system_port_pacific() override;

    la_status destroy() override;

    la_status set_inject_up_entry(npl_initial_pd_nw_rx_data_t initial_pd_nw_rx_data) override;
    la_status erase_inject_up_entry() override;
    la_status set_recycled_inject_up_entry() override;

    la_status set_mtu(la_mtu_t mtu) override;

    la_status set_pfc(bool enable);

    la_status populate_common_dsp_attributes(npl_dsp_attr_common_t& common_attributes) override;
    la_status get_output_queue_size(la_oq_id_t oq_offset, size_t& out_size) const override;
    la_status get_output_queue_fcn_enabled(la_oq_id_t oq_offset, bool& out_fcn_enabled) const override;

    la_status read_egress_congestion_watermark(la_traffic_class_t tc,
                                               bool clear_on_read,
                                               egress_max_congestion_watermark& out_cong_wm) override;
    la_status read_egress_delay_watermark(la_traffic_class_t tc,
                                          bool clear_on_read,
                                          egress_max_delay_watermark& out_delay_wm) override;

    // SGACL APIs.
    la_status update_npp_sgt_attributes(la_sgt_t security_group_tag) override;
    la_status update_dsp_sgt_attributes(bool security_group_policy_enforcement) override;

private:
    la_status update_mtu_macro_trigger_threshold(la_mtu_t old_mtu, la_mtu_t mtu) override;
    la_status calculate_network_txpp(npl_dsp_l2_attributes_table_t::key_type& key, la_uint_t pif_offset) override;
    la_status calculate_network_txpp(npl_dsp_l3_attributes_table_t::key_type& key, la_uint_t pif_offset) override;
    la_uint8_t fill_in_dsp_attr_key(la_uint_t pif_offset);
    la_status set_tc_profile_core_ect(const la_tc_profile_wcptr& tc_profile) override;
    la_status teardown_tm_tables_ect() override;
};

} // namespace silicon_one

#endif // __LA_SYSTEM_PORT_PACIFIC_H__
