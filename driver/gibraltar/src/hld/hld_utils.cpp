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

#include "npu/la_gue_port_impl.h"

#include "common/logger.h"
#include "npu/la_acl_delegate.h"
#include "npu/la_acl_impl.h"
#include "npu/la_gre_port_impl.h"
#include "npu/la_ip_over_ip_tunnel_port_impl.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_lpts_impl.h"
#include "npu/la_next_hop_gibraltar.h"
#include "npu/la_svi_port_base.h"
#include "npu/la_vrf_impl.h"
#include "npu/la_vxlan_next_hop_base.h"
#include "system/la_device_impl.h"
#include "system/la_l2_mirror_command_base.h"

#include "hld_utils.h"
#include "npu/la_acl_impl.h"
#include <sstream>
namespace silicon_one
{

slice_ifg_vec_t
get_ifgs(const la_object_wcptr& obj)
{
    return get_ifgs_base(obj);
}

void
populate_rcy_data_mirror_command(const la_mirror_command_wcptr& mirror_cmd, bool is_recycle_ac, npl_tx_to_rx_rcy_data_t& rcy_data)
{
    if (is_recycle_ac) {
        rcy_data.unscheduled_recycle_data = NPL_TX2RX_SCHED_RCY_DATA_RCY_PORT_TO_INJECT_UP & 0x3f;
        rcy_data.unscheduled_recycle_code.unscheduled_recycle_code_lsb
            = bit_utils::get_bit(NPL_TX2RX_SCHED_RCY_DATA_RCY_PORT_TO_INJECT_UP, 6);
        rcy_data.unscheduled_recycle_code.recycle_pkt = bit_utils::get_bit(NPL_TX2RX_SCHED_RCY_DATA_RCY_PORT_TO_INJECT_UP, 7);
        return;
    }

    if (mirror_cmd == nullptr) {
        rcy_data.unscheduled_recycle_data = 0x0;
        rcy_data.unscheduled_recycle_code.unscheduled_recycle_code_lsb = 0x0;
        rcy_data.unscheduled_recycle_code.recycle_pkt = 0x0;
    } else {
        rcy_data.unscheduled_recycle_data = mirror_cmd->get_gid() & 0x3f;
        rcy_data.unscheduled_recycle_code.unscheduled_recycle_code_lsb = 0x1;
        rcy_data.unscheduled_recycle_code.recycle_pkt = 0x1;
    }
}

la_status
populate_rcy_data(const la_device_impl_wcptr& device,
                  const la_mirror_command_wcptr& mirror_cmd,
                  bool is_recycle_ac,
                  npl_tx_to_rx_rcy_data_t& rcy_data)
{
    populate_rcy_data_mirror_command(mirror_cmd, is_recycle_ac, rcy_data);

    if (is_recycle_ac) {
        return LA_STATUS_SUCCESS;
    }

    // If TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST is true, packets should be recycled and transmitted through the PCI port.
    bool test_mode_punt_to_egress;
    la_status status
        = device->get_bool_property(la_device_property_e::TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST, test_mode_punt_to_egress);
    return_on_error(status);

    if (test_mode_punt_to_egress) {
        // TODO: change to (attrib.tx_to_rx_rcy_data = NPL_TX2RX_RCY_DATA_INJECT_DOWN_TO_DMA_PORT) after NPL team add support to
        // this union.
        rcy_data.unscheduled_recycle_data = NPL_TX2RX_RCY_DATA_INJECT_DOWN_TO_DMA_PORT & 0x3f;
        rcy_data.unscheduled_recycle_code.unscheduled_recycle_code_lsb
            = bit_utils::get_bit(NPL_TX2RX_RCY_DATA_INJECT_DOWN_TO_DMA_PORT, 6);
        rcy_data.unscheduled_recycle_code.recycle_pkt = bit_utils::get_bit(NPL_TX2RX_RCY_DATA_INJECT_DOWN_TO_DMA_PORT, 7);
    }

    return LA_STATUS_SUCCESS;
}

npl_npu_encap_header_l3_dlp_t
get_l3_dlp_encap(la_l3_port_gid_t gid)
{
    npl_npu_encap_header_l3_dlp_t encap_header = {};
    encap_header.l3_dlp_id.l3_dlp_lsbs = get_l3_lp_lsb(gid);
    encap_header.properties.l3_dlp_id_ext.l3_dlp_msbs = get_l3_lp_msb(gid);
    return encap_header;
}

npl_l3_dlp_id_t
get_l3_dlp_id(la_l3_port_gid_t gid)
{
    npl_l3_dlp_id_t npl_l3_dlp = {};
    npl_l3_dlp.lsbs.l3_dlp_lsbs = get_l3_lp_lsb(gid);
    npl_l3_dlp.msbs.l3_dlp_msbs = get_l3_lp_msb(gid);
    return npl_l3_dlp;
}

uint32_t
get_l3_dlp_value_from_gid(la_l3_port_gid_t gid)
{
    return ((get_l3_lp_lsb(gid) << la_device_impl::L3_PORT_GID_PROPERTIES_WIDTH)
            | (get_l3_lp_msb(gid) << la_device_impl::L3_PORT_GID_EXTENSION_OFFSET_ON_PROPERTIES));
}
} // namespace silicon_one
